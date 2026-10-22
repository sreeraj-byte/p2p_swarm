"""Sender reporting client for telemetry submission to tracker.

Implements Sections 12, 12.2, and 14.4:
- Background reporting worker thread batched every REPORT_INTERVAL (0.5s).
- Reports only when state (pieces_sent, bytes_sent, active_conns, or events) has changed.
- HMAC-SHA256 signature generated with report_key and passed in X-Signature header.
- Strictly increasing sequence number (seq) per device.
- Never raises exceptions that interrupt sender operations or file transfer.
- Learns tracker endpoint from --tracker HOST:PORT or dynamic UDP BEACON.
"""

import hashlib
import hmac
import json
import logging
import threading
import time
from typing import Any, Dict, List, Optional
import urllib.request
import urllib.error

import config

logger = logging.getLogger(__name__)


class ReportClient:
    """Client for generating and transmitting signed telemetry reports to the tracker."""

    def __init__(
        self,
        device_id: str,
        report_key: bytes,
        tracker_address: Optional[str] = None,
        interval: float = config.REPORT_INTERVAL,
    ) -> None:
        self.device_id = device_id
        self.report_key = report_key
        self.tracker_address = tracker_address
        self.interval = interval

        self._lock = threading.Lock()
        self._seq = 0
        self._pieces_sent = 0
        self._bytes_sent = 0
        self._active_connections = 0
        self._pending_events: List[Dict[str, Any]] = []

        # Last reported snapshot to avoid redundant requests when nothing changed
        self._last_reported_pieces = -1
        self._last_reported_bytes = -1
        self._last_reported_conns = -1

        self._is_running = False
        self._thread: Optional[threading.Thread] = None

    def set_tracker(self, host: str, port: int) -> None:
        """Set or update destination tracker address."""
        with self._lock:
            self.tracker_address = f"{host}:{port}"
            logger.debug("ReportClient tracker set to %s", self.tracker_address)

    def update_stats(self, pieces_sent: int, bytes_sent: int, active_conns: int) -> None:
        """Update sender performance counters."""
        with self._lock:
            self._pieces_sent = pieces_sent
            self._bytes_sent = bytes_sent
            self._active_connections = active_conns

    def record_event(self, event_type: str, msg: str, level: str = "info") -> None:
        """Buffer a sender-side event to be submitted with next report."""
        with self._lock:
            self._pending_events.append(
                {
                    "type": event_type,
                    "msg": msg,
                    "level": level,
                    "t": time.time(),
                }
            )

    def start(self) -> None:
        """Start periodic reporting background thread."""
        if self._is_running:
            return
        self._is_running = True
        self._thread = threading.Thread(target=self._report_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop reporting background thread."""
        self._is_running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)
            self._thread = None

    def send_report_now(self) -> bool:
        """Attempt immediate report transmission. Never raises exceptions."""
        with self._lock:
            target = self.tracker_address
            if not target:
                return False

            self._seq += 1
            seq = self._seq
            now = time.time()
            pieces = self._pieces_sent
            b_sent = self._bytes_sent
            conns = self._active_connections
            events = list(self._pending_events)

        payload = {
            "device_id": self.device_id,
            "seq": seq,
            "ts": now,
            "pieces_sent": pieces,
            "bytes_sent": b_sent,
            "active_connections": conns,
            "events": events,
        }

        try:
            raw_body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            signature = hmac.new(self.report_key, raw_body, hashlib.sha256).hexdigest()

            url = f"http://{target}/api/report"
            req = urllib.request.Request(
                url,
                data=raw_body,
                headers={
                    "Content-Type": "application/json",
                    "X-Signature": signature,
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                if resp.status == 200:
                    with self._lock:
                        self._last_reported_pieces = pieces
                        self._last_reported_bytes = b_sent
                        self._last_reported_conns = conns
                        # Remove sent events
                        self._pending_events = self._pending_events[len(events):]
                    return True
        except Exception as err:
            logger.debug("Failed sending report to %s: %s", target, err)

        return False

    def _report_loop(self) -> None:
        """Background loop executing report cadence."""
        while self._is_running:
            time.sleep(self.interval)
            if not self._is_running:
                break

            # Check if something changed
            with self._lock:
                target = self.tracker_address
                if not target:
                    continue

                has_changed = (
                    self._pieces_sent != self._last_reported_pieces
                    or self._bytes_sent != self._last_reported_bytes
                    or self._active_connections != self._last_reported_conns
                    or len(self._pending_events) > 0
                )

            if has_changed:
                self.send_report_now()
