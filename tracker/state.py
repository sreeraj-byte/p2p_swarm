"""Thread-safe in-memory state store for P2P Swarm tracker and monitor.

Implements Section 12, 12.2, 12.3, 12.4, and 12.5:
- In-memory state protected by a single lock around all mutations.
- Exact JSON schema generation for GET /api/state.
- Piece-map grid with downsampling rules (per_cell = ceil(total / 400);
  all missing: -1, partly missing: -3, one sender: color_index, mixed: -2).
- Per-file piece counts and exact sender byte contribution tracking across piece boundaries.
- Moving average transfer speed over a 3-second window and ETA calculation.
- Circular ring buffer of MAX_EVENTS (newest first).
- Signed POST /api/report processing with HMAC-SHA256, timestamp skew, replay,
  and body size checks.
"""

from collections import deque
import hashlib
import hmac
import json
import math
import threading
import time
from typing import Any, Deque, Dict, List, Optional, Set, Tuple

import config
from common.discovery import DeviceTable, DeviceEntry


class TrackerState:
    """Thread-safe state repository for swarm progress, peers, telemetry, and events."""

    def __init__(
        self,
        server_name: str = "Tracker",
        server_ip: str = "127.0.0.1",
        web_port: int = config.DEFAULT_WEB_PORT,
        report_key: Optional[bytes] = None,
        device_table: Optional[DeviceTable] = None,
    ) -> None:
        self._lock = threading.Lock()

        # Tracker identity
        self.server_name = server_name
        self.server_ip = server_ip
        self.web_port = web_port
        self.report_key = report_key
        self.device_table = device_table

        # Swarm metadata
        self.swarm_name: str = ""
        self.swarm_id_short: str = ""
        self.piece_size: int = config.DEFAULT_PIECE_SIZE
        self.total_pieces: int = 0
        self.total_bytes: int = 0
        self.files_total: int = 0

        # Transfer progress
        self.transfer_state: str = "idle"  # idle, discovering, downloading, complete, failed
        self.started_at: Optional[float] = None
        self.pieces_done: int = 0
        self.bytes_done: int = 0
        self.bad_pieces: int = 0
        self.files_done: int = 0

        # Speed calculation (sliding window of (timestamp, bytes) over 3.0s)
        self._speed_window: Deque[Tuple[float, int]] = deque()
        self._sender_speed_windows: Dict[str, Deque[Tuple[float, int]]] = {}

        # Senders tracking
        # device_id -> sender dict
        self._senders: Dict[str, Dict[str, Any]] = {}
        self._device_to_color: Dict[str, int] = {}
        self._next_color_index: int = 0

        # Replay protection: device_id -> last_seq (int)
        self._sender_last_seq: Dict[str, int] = {}
        self._sender_last_report: Dict[str, float] = {}

        # Piece ownership: piece_index -> color_index
        self._piece_owners: Dict[int, int] = {}
        # piece_index -> sender device_id
        self._piece_sender_ids: Dict[int, str] = {}

        # Files tracking: list of file dicts
        # {path, length, start_offset, end_offset, pieces_total, pieces_done, complete, by_sender: {dev_id: bytes}}
        self._files: List[Dict[str, Any]] = []

        # Event log ring buffer (MAX_EVENTS)
        self._events: Deque[Dict[str, Any]] = deque(maxlen=config.MAX_EVENTS)

        # Telemetry counters
        self.invalid_reports_count: int = 0

    # ------------------------------------------------------------------
    # Swarm & Transfer Lifecycle Reducers
    # ------------------------------------------------------------------

    def set_swarm(self, metadata: Dict[str, Any], swarm_id: str) -> None:
        """Initialize swarm structure and per-file piece boundaries from canonical metadata."""
        with self._lock:
            root_name = metadata.get("root")
            if not root_name and metadata.get("files"):
                root_name = metadata["files"][0]["path"]
            self.swarm_name = root_name or "shared"
            self.swarm_id_short = swarm_id[:16]
            self.piece_size = int(metadata.get("piece_size", config.DEFAULT_PIECE_SIZE))
            self.total_bytes = int(metadata.get("total_size", 0))
            total_p = metadata.get("total_pieces")
            if total_p is None:
                total_p = len(metadata.get("piece_hashes", []))
            self.total_pieces = int(total_p)
            raw_files = metadata.get("files", [])
            self.files_total = len(raw_files)

            # Build file boundary records
            self._files.clear()
            curr_offset = 0
            for f in raw_files:
                f_len = int(f.get("length", 0))
                f_path = str(f.get("path", ""))
                f_start = curr_offset
                f_end = curr_offset + f_len
                curr_offset = f_end

                # Calculate intersecting piece indices
                if f_len == 0:
                    intersecting_pieces: Set[int] = set()
                else:
                    first_p = f_start // self.piece_size
                    last_p = (f_end - 1) // self.piece_size
                    intersecting_pieces = set(range(first_p, last_p + 1))

                self._files.append(
                    {
                        "path": f_path,
                        "length": f_len,
                        "start_offset": f_start,
                        "end_offset": f_end,
                        "piece_indices": intersecting_pieces,
                        "pieces_done_set": set(),
                        "pieces_done": 0,
                        "pieces_total": len(intersecting_pieces),
                        "complete": (f_len == 0),
                        "by_sender": {},
                    }
                )

    def set_transfer_state(self, state: str) -> None:
        """Update transfer operational state."""
        with self._lock:
            self.transfer_state = state
            if state == "downloading" and self.started_at is None:
                self.started_at = time.time()
                self._record_event_locked("TRANSFER_STARTED", f"Transfer started for swarm {self.swarm_name}", "info")
            elif state == "complete":
                self._record_event_locked("TRANSFER_COMPLETE", "Transfer completed successfully", "info")
            elif state == "failed":
                self._record_event_locked("TRANSFER_FAILED", "Transfer failed", "error")

    def record_event(self, event_type: str, msg: str, level: str = "info", t: Optional[float] = None) -> None:
        """Thread-safe event recording."""
        with self._lock:
            self._record_event_locked(event_type, msg, level, t)

    def _record_event_locked(
        self,
        event_type: str,
        msg: str,
        level: str = "info",
        t: Optional[float] = None,
    ) -> None:
        event = {
            "t": t if t is not None else time.time(),
            "level": level,
            "type": event_type,
            "msg": msg,
        }
        self._events.append(event)

    # ------------------------------------------------------------------
    # Peer & Progress Reducers
    # ------------------------------------------------------------------

    def on_sender_verified(
        self,
        device_id: str,
        name: str,
        ip: str,
        tcp_port: int,
    ) -> None:
        """Record verified sender peer."""
        with self._lock:
            if device_id not in self._device_to_color:
                self._device_to_color[device_id] = self._next_color_index
                self._next_color_index += 1

            color_idx = self._device_to_color[device_id]
            if device_id not in self._senders:
                self._senders[device_id] = {
                    "device_id": device_id,
                    "name": name,
                    "ip": ip,
                    "tcp_port": tcp_port,
                    "pieces": 0,
                    "bytes": 0,
                    "failures": 0,
                    "status": "active",
                    "color_index": color_idx,
                }
            else:
                s = self._senders[device_id]
                s["name"] = name
                s["ip"] = ip
                s["tcp_port"] = tcp_port
                s["status"] = "active"

            if device_id not in self._sender_speed_windows:
                self._sender_speed_windows[device_id] = deque()

            self._record_event_locked("SENDER_VERIFIED", f"Sender {name} ({ip}:{tcp_port}) verified", "info")

    def on_piece_downloaded(
        self,
        piece_index: int,
        device_id: str,
        sender_name: str,
        piece_bytes: int,
    ) -> None:
        """Record piece delivery and calculate per-file byte contributions."""
        now = time.time()
        with self._lock:
            # Assign color index if unseen
            if device_id not in self._device_to_color:
                self._device_to_color[device_id] = self._next_color_index
                self._next_color_index += 1
            color_idx = self._device_to_color[device_id]

            # Register piece completion
            self._piece_owners[piece_index] = color_idx
            self._piece_sender_ids[piece_index] = device_id
            self.pieces_done += 1
            self.bytes_done += piece_bytes

            # Update overall and sender speed windows
            self._speed_window.append((now, piece_bytes))
            if device_id not in self._sender_speed_windows:
                self._sender_speed_windows[device_id] = deque()
            self._sender_speed_windows[device_id].append((now, piece_bytes))

            # Update sender record
            if device_id not in self._senders:
                self._senders[device_id] = {
                    "device_id": device_id,
                    "name": sender_name,
                    "pieces": 1,
                    "bytes": piece_bytes,
                    "failures": 0,
                    "status": "active",
                    "color_index": color_idx,
                }
            else:
                self._senders[device_id]["pieces"] += 1
                self._senders[device_id]["bytes"] += piece_bytes
                self._senders[device_id]["status"] = "active"

            # Update per-file piece counts and exact sender byte overlap
            p_start = piece_index * self.piece_size
            p_end = p_start + piece_bytes

            for f in self._files:
                f_start = f["start_offset"]
                f_end = f["end_offset"]
                overlap = max(0, min(p_end, f_end) - max(p_start, f_start))
                if overlap > 0:
                    f["by_sender"][device_id] = f["by_sender"].get(device_id, 0) + overlap

                if piece_index in f["piece_indices"] and piece_index not in f["pieces_done_set"]:
                    f["pieces_done_set"].add(piece_index)
                    f["pieces_done"] = len(f["pieces_done_set"])
                    if f["pieces_done"] == f["pieces_total"]:
                        if not f["complete"]:
                            f["complete"] = True
                            self.files_done += 1
                            self._record_event_locked("FILE_COMPLETE", f"File complete: {f['path']}", "info")

    def on_piece_hash_failed(
        self,
        piece_index: int,
        device_id: str,
        sender_name: str,
    ) -> None:
        """Record piece verification failure against sender."""
        with self._lock:
            self.bad_pieces += 1
            if device_id in self._senders:
                self._senders[device_id]["failures"] += 1
            self._record_event_locked(
                "PIECE_FAILED",
                f"Piece {piece_index} hash failure from sender {sender_name}",
                "warning",
            )

    def on_sender_banned(self, device_id: str, sender_name: str) -> None:
        """Mark sender as banned."""
        with self._lock:
            if device_id in self._senders:
                self._senders[device_id]["status"] = "banned"
            if self.device_table:
                self.device_table.mark_banned(device_id)
            self._record_event_locked("SENDER_BANNED", f"Sender {sender_name} banned due to repeated failures", "error")

    def on_sender_failed(self, device_id: str, sender_name: Optional[str] = None) -> None:
        """Record sender failure or disconnection."""
        with self._lock:
            if device_id in self._senders:
                self._senders[device_id]["failures"] += 1
                self._senders[device_id]["status"] = "failed"
            label = sender_name or device_id
            self._record_event_locked("SENDER_FAILED", f"Sender {label} connection failed", "warning")

    def on_auth_rejected(self, source_ip: str) -> None:
        """Record authentication failure from IP."""
        with self._lock:
            self._record_event_locked(
                "AUTH_REJECTED",
                f"Authentication rejected from {source_ip}: invalid join code proof",
                "warning",
            )

    # ------------------------------------------------------------------
    # Signed Telemetry Ingestion (Section 12.2)
    # ------------------------------------------------------------------

    def process_report(
        self,
        raw_body: bytes,
        signature_header: Optional[str],
        now: Optional[float] = None,
    ) -> Tuple[bool, int, str]:
        """Validate and ingest a signed sender telemetry report.

        Enforces:
        - Maximum body size of 64 KiB
        - HMAC-SHA256 signature verification with report_key
        - JSON structure and mandatory fields
        - Clock skew within REPORT_CLOCK_SKEW
        - Strictly increasing sequence number per device (replay protection)

        Returns:
            Tuple of (success: bool, http_status_code: int, message: str)
        """
        current_time = now if now is not None else time.time()

        # 1. Body size check (64 KiB)
        if len(raw_body) > config.MAX_REPORT_BYTES:
            with self._lock:
                self.invalid_reports_count += 1
            return False, 400, f"Payload size {len(raw_body)} exceeds max 64 KiB"

        # 2. Signature verification
        if not signature_header:
            with self._lock:
                self.invalid_reports_count += 1
            return False, 401, "Missing X-Signature header"

        if not self.report_key:
            with self._lock:
                self.invalid_reports_count += 1
            return False, 500, "Tracker has no report_key configured for verification"

        expected_sig = hmac.new(self.report_key, raw_body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_sig.lower(), signature_header.strip().lower()):
            with self._lock:
                self.invalid_reports_count += 1
            return False, 401, "Invalid report HMAC signature"

        # 3. JSON parsing
        try:
            data = json.loads(raw_body.decode("utf-8"))
        except Exception:
            with self._lock:
                self.invalid_reports_count += 1
            return False, 400, "Malformed JSON payload"

        if not isinstance(data, dict):
            with self._lock:
                self.invalid_reports_count += 1
            return False, 400, "JSON payload must be an object"

        device_id = data.get("device_id")
        seq = data.get("seq")
        ts = data.get("ts")
        pieces_sent = data.get("pieces_sent")
        bytes_sent = data.get("bytes_sent")
        active_conns = data.get("active_connections")

        if (
            not isinstance(device_id, str)
            or not isinstance(seq, int)
            or not isinstance(ts, (int, float))
            or not isinstance(pieces_sent, int)
            or not isinstance(bytes_sent, int)
            or not isinstance(active_conns, int)
        ):
            with self._lock:
                self.invalid_reports_count += 1
            return False, 400, "Missing or invalid report field types"

        # 4. Timestamp clock skew check
        if abs(current_time - float(ts)) > config.REPORT_CLOCK_SKEW:
            with self._lock:
                self.invalid_reports_count += 1
            return False, 400, f"Timestamp skew {abs(current_time - float(ts)):.1f}s exceeds {config.REPORT_CLOCK_SKEW}s limit"

        # 5. Strictly increasing sequence number per device (replay protection)
        with self._lock:
            last_seq = self._sender_last_seq.get(device_id, -1)
            if seq <= last_seq:
                self.invalid_reports_count += 1
                return False, 400, f"Replayed or stale sequence {seq} <= last {last_seq}"

            # Valid report: update tracker state
            self._sender_last_seq[device_id] = seq
            self._sender_last_report[device_id] = current_time

            # Update sender record if exists
            if device_id in self._senders:
                s = self._senders[device_id]
                s["active_connections"] = active_conns
                # Note: pieces and bytes delivered to receiver are directly verified in-process,
                # but we preserve reported sender-side totals for metrics if desired.
                s["sender_reported_pieces"] = pieces_sent
                s["sender_reported_bytes"] = bytes_sent

            # Ingest any reported sender events
            events = data.get("events")
            if isinstance(events, list):
                for ev in events:
                    if isinstance(ev, dict) and "type" in ev and "msg" in ev:
                        self._record_event_locked(
                            str(ev["type"]),
                            f"[{device_id[:6]}] {ev['msg']}",
                            level=str(ev.get("level", "info")),
                            t=float(ev.get("t", current_time)),
                        )

        return True, 200, "Report accepted"

    # ------------------------------------------------------------------
    # Speed & ETA Calculation
    # ------------------------------------------------------------------

    def _compute_speed_locked(self, window: Deque[Tuple[float, int]], current_time: float) -> int:
        """Compute moving average speed in bytes per second over a 3.0s window."""
        window_duration = 3.0
        cutoff = current_time - window_duration
        while window and window[0][0] < cutoff:
            window.popleft()

        if not window:
            return 0

        total_window_bytes = sum(w[1] for w in window)
        # If all samples are at nearly the exact same timestamp, use total time or at least 0.5s span
        dt = current_time - window[0][0]
        if dt < 0.2:
            dt = 0.2
        return int(total_window_bytes / dt)

    # ------------------------------------------------------------------
    # Piece Map Downsampling (Section 12.5)
    # ------------------------------------------------------------------

    def _compute_piece_map_locked(self) -> Dict[str, Any]:
        """Generate piece map with downsampling rules.

        Rules:
        - per_cell = ceil(total_pieces / PIECE_MAP_MAX_CELLS)
        - If all pieces in cell are missing: -1
        - If partly missing: -3
        - If all completed by a single sender: sender's color_index
        - If completed by multiple senders: -2
        """
        if self.total_pieces <= 0:
            return {"cells": 0, "per_cell": 1, "data": []}

        per_cell = math.ceil(self.total_pieces / config.PIECE_MAP_MAX_CELLS)
        num_cells = math.ceil(self.total_pieces / per_cell)
        cell_data: List[int] = []

        for c in range(num_cells):
            start_p = c * per_cell
            end_p = min((c + 1) * per_cell, self.total_pieces)
            cell_size = end_p - start_p

            missing_count = sum(1 for p in range(start_p, end_p) if p not in self._piece_owners)

            if missing_count == cell_size:
                # All pieces in this cell are missing
                cell_data.append(-1)
            elif 0 < missing_count < cell_size:
                # Partly missing
                cell_data.append(-3)
            else:
                # All pieces completed in this cell
                senders_in_cell = {self._piece_owners[p] for p in range(start_p, end_p)}
                if len(senders_in_cell) == 1:
                    cell_data.append(senders_in_cell.pop())
                else:
                    cell_data.append(-2)  # Mixed senders

        return {
            "cells": num_cells,
            "per_cell": per_cell,
            "data": cell_data,
        }

    # ------------------------------------------------------------------
    # State Snapshot Serialization (GET /api/state)
    # ------------------------------------------------------------------

    def get_state_dict(self, now: Optional[float] = None) -> Dict[str, Any]:
        """Generate JSON state snapshot matching Section 12.5 specification."""
        current_time = now if now is not None else time.time()

        with self._lock:
            # Overall speed & ETA
            speed_bps = self._compute_speed_locked(self._speed_window, current_time)
            remaining_bytes = max(0, self.total_bytes - self.bytes_done)
            eta_s = int(remaining_bytes / speed_bps) if speed_bps > 0 and remaining_bytes > 0 else 0
            if self.transfer_state == "complete":
                eta_s = 0

            # Devices list
            devices_list: List[Dict[str, Any]] = []
            if self.device_table:
                for dev in self.device_table.get_devices():
                    last_seen_age = round(max(0.0, current_time - dev.last_seen), 1)
                    devices_list.append(
                        {
                            "device_id": dev.device_id,
                            "id": dev.device_id,
                            "name": dev.name,
                            "ip": dev.ip,
                            "tcp_port": dev.tcp_port,
                            "port": dev.tcp_port,
                            "role": dev.role,
                            "status": dev.status,
                            "trust": dev.trust,
                            "last_seen_age": last_seen_age,
                            "swarm_short": dev.swarm_id_short,
                            "files": dev.files,
                            "total_bytes": dev.total_bytes,
                        }
                    )

            # Ensure any verified senders not yet in devices_list are represented
            for s_id, s in self._senders.items():
                if not any(d.get("device_id") == s_id or d.get("id") == s_id for d in devices_list):
                    last_seen_age = round(max(0.0, current_time - self._sender_last_report.get(s_id, current_time)), 1)
                    devices_list.append(
                        {
                            "device_id": s_id,
                            "id": s_id,
                            "name": s["name"],
                            "ip": s.get("ip", "127.0.0.1"),
                            "tcp_port": s.get("tcp_port", 0),
                            "port": s.get("tcp_port", 0),
                            "role": "sender",
                            "status": "online" if s["status"] == "active" else s["status"],
                            "trust": "verified",
                            "last_seen_age": last_seen_age,
                            "swarm_short": self.swarm_id_short,
                            "files": self.files_total,
                            "total_bytes": self.total_bytes,
                        }
                    )

            # Senders list with per-sender speed
            senders_list: List[Dict[str, Any]] = []
            for s_id, s in self._senders.items():
                w = self._sender_speed_windows.get(s_id, deque())
                s_speed = self._compute_speed_locked(w, current_time)
                senders_list.append(
                    {
                        "device_id": s["device_id"],
                        "name": s["name"],
                        "pieces": s["pieces"],
                        "bytes": s["bytes"],
                        "speed_bps": s_speed,
                        "failures": s["failures"],
                        "status": s["status"],
                        "color_index": s["color_index"],
                    }
                )

            # Piece map
            piece_map_data = self._compute_piece_map_locked()

            # Files list (clean representation without internal sets)
            files_list: List[Dict[str, Any]] = []
            for f in self._files:
                files_list.append(
                    {
                        "path": f["path"],
                        "length": f["length"],
                        "pieces_done": f["pieces_done"],
                        "pieces_total": f["pieces_total"],
                        "complete": f["complete"],
                        "by_sender": dict(f["by_sender"]),
                    }
                )

            # Events list (newest first per Section 12.3 / 13)
            events_list = list(reversed(self._events))

            return {
                "server_time": current_time,
                "tracker": {
                    "name": self.server_name,
                    "ip": self.server_ip,
                    "web_port": self.web_port,
                    "tls": True,
                    "auth": True,
                },
                "devices": devices_list,
                "swarm": {
                    "name": self.swarm_name,
                    "swarm_id_short": self.swarm_id_short,
                    "piece_size": self.piece_size,
                    "total_pieces": self.total_pieces,
                    "total_bytes": self.total_bytes,
                    "files_total": self.files_total,
                },
                "transfer": {
                    "state": self.transfer_state,
                    "started_at": self.started_at,
                    "pieces_done": self.pieces_done,
                    "bytes_done": self.bytes_done,
                    "speed_bps": speed_bps,
                    "eta_s": eta_s,
                    "files_done": self.files_done,
                    "bad_pieces": self.bad_pieces,
                },
                "senders": senders_list,
                "piece_map": piece_map_data,
                "files": files_list,
                "events": events_list,
            }
