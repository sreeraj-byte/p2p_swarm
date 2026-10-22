"""P2P Swarm Receiver (Multi-sender Downloader CLI).

Implements Section 9, Section 14.1 (TLS 1.2+ certificate pinning), and Section 7.3/7.4 (Mutual Join-Code Authentication):
- Connects to senders over TLS, strictly pinning the sender's certificate (verify_mode=CERT_REQUIRED, check_hostname=False).
- Executes mutual join-code challenge-response authentication via Scrypt-derived keys and constant-time HMAC-SHA256 verification.
- Rejects unauthenticated peers and peers with mismatched swarm IDs (SWARM_MISMATCH).
- Pull-based parallel retrieval from multiple authenticated senders via a shared work queue.
- Dynamic worker spawning and dynamic peer joins.
- Hash verification, failure retries (attempts[i]), strikes, and session banning.
- Section 15 terminal output with per-sender A/B piece split statistics.
"""

import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import logging
import queue
import secrets
import socket
import ssl
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from common.auth import (
    AuthError,
    compute_client_proof,
    derive_auth_key,
    derive_report_key,
    get_join_code,
    verify_server_proof,
)
from common.metadata import (
    MetadataValidationError,
    compute_swarm_id,
    compute_swarm_id_short,
    validate_metadata,
)
from common.pieces import PieceWriter
from common.protocol import (
    ConnectionClosedError,
    ProtocolError,
    make_bye,
    make_get_metadata,
    make_hello,
    make_request,
    recv_message,
    send_message,
)
from common.discovery import DeviceEntry, DeviceTable, DiscoveryListener, format_dashboard_urls
from common.logutil import get_logger
from common.tlsutil import create_client_ssl_context, format_tls_error
from tracker.state import TrackerState
from tracker.server import TrackerServer
import config

# Mute werkzeug HTTP request logs so lines like POST /api/report ... 200 do not interleave with progress bars
logging.getLogger("werkzeug").setLevel(logging.WARNING)
logger = get_logger("receiver")


class SenderStatsDict(dict):
    """Dictionary mapping sender device_id to statistics dict, supporting endpoint fallback."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._endpoint_to_id: Dict[str, str] = {}

    def register_endpoint(self, endpoint: str, device_id: str) -> None:
        self._endpoint_to_id[endpoint] = device_id

    def copy(self) -> "SenderStatsDict":
        c = SenderStatsDict(self)
        c._endpoint_to_id = dict(self._endpoint_to_id)
        return c

    def __getitem__(self, key: str) -> Any:
        if super().__contains__(key):
            return super().__getitem__(key)
        if key in self._endpoint_to_id:
            dev_id = self._endpoint_to_id[key]
            if super().__contains__(dev_id):
                return super().__getitem__(dev_id)
        for dev_id, val in self.items():
            if isinstance(val, dict):
                if val.get("endpoint") == key or val.get("name") == key:
                    return val
                ep = str(val.get("endpoint", ""))
                if key in ep or (val.get("tcp_port") and str(val.get("tcp_port")) in key):
                    return val
        raise KeyError(key)

    def __contains__(self, key: object) -> bool:
        if super().__contains__(key):
            return True
        if isinstance(key, str) and key in self._endpoint_to_id:
            dev_id = self._endpoint_to_id[key]
            if super().__contains__(dev_id):
                return True
        for dev_id, val in self.items():
            if isinstance(val, dict):
                if val.get("endpoint") == key or val.get("name") == key:
                    return True
                if isinstance(key, str) and (key in str(val.get("endpoint", "")) or (val.get("tcp_port") and str(val.get("tcp_port")) in key)):
                    return True
        return False

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default


class BannedSendersList(list):
    """List of banned device_ids with endpoint fallback for compatibility."""

    def __init__(self, device_ids: Any = (), endpoint_map: Optional[Dict[str, str]] = None) -> None:
        super().__init__(device_ids)
        self._endpoint_map: Dict[str, str] = dict(endpoint_map) if endpoint_map else {}

    def __contains__(self, item: object) -> bool:
        if super().__contains__(item):
            return True
        if isinstance(item, str) and item in self._endpoint_map:
            return super().__contains__(self._endpoint_map[item])
        return False


def render_progress_bar(
    pieces_done: int,
    total_pieces: int,
    bytes_done: int,
    total_bytes: int,
    elapsed: float,
    width: int = 20,
) -> str:
    """Format in-place terminal progress bar according to Section 15."""
    if total_pieces == 0:
        return "[====================] 100%  0/0 pieces"

    fraction = min(1.0, pieces_done / total_pieces)
    filled = int(fraction * width)
    bar = "#" * filled + "-" * (width - filled)
    percent = int(fraction * 100)

    speed_bps = bytes_done / max(0.001, elapsed)
    speed_mb = speed_bps / (1024 * 1024)

    remaining_bytes = max(0, total_bytes - bytes_done)
    if speed_bps > 0 and remaining_bytes > 0:
        eta_sec = int(remaining_bytes / speed_bps)
        mins, secs = divmod(eta_sec, 60)
        eta_str = f"ETA {mins:02d}:{secs:02d}"
    else:
        eta_str = "ETA 00:00"

    return f"[{bar}] {percent:3d}%  {pieces_done}/{total_pieces} pieces  {speed_mb:4.1f} MB/s  {eta_str}"


class SwarmReceiver:
    """Multi-threaded parallel receiver with certificate pinning and mutual join-code authentication."""

    def __init__(
        self,
        senders: Optional[List[str]] = None,
        out_dir: Path = Path("downloads"),
        cert_path: Union[str, Path] = "certs/cert.pem",
        join_code: Optional[str] = None,
        overwrite: bool = False,
        name: str = "Receiver-C",
        verbose: bool = True,
        backoff_base: float = 1.0,
        request_timeout: Optional[float] = None,
        device_id: Optional[str] = None,
        handshake_timeout: Optional[float] = None,
        enable_discovery: Optional[bool] = None,
        discovery_port: int = config.DISCOVERY_PORT,
        min_senders: int = config.DEFAULT_MIN_SENDERS,
        discover_timeout: float = config.DEFAULT_DISCOVER_TIMEOUT,
        target_swarm: Optional[str] = None,
        device_table: Optional[DeviceTable] = None,
        enable_tracker: bool = False,
        web_port: int = config.DEFAULT_WEB_PORT,
        web_host: str = "0.0.0.0",
        web_pin: Optional[str] = None,
        tracker_state: Optional[TrackerState] = None,
        keep_tracker_alive: bool = False,
        exit_when_done: bool = True,
    ) -> None:
        self.initial_senders = list(senders) if senders else []
        self.out_dir = Path(out_dir).resolve()
        self.cert_path = Path(cert_path).resolve()
        self.overwrite = overwrite
        self.name = name
        self.verbose = verbose
        self.backoff_base = backoff_base
        self.request_timeout = request_timeout if request_timeout is not None else config.REQUEST_TIMEOUT
        self.handshake_timeout = handshake_timeout if handshake_timeout is not None else config.HANDSHAKE_TIMEOUT
        self.device_id = device_id or secrets.token_hex(16)
        if enable_discovery is None:
            self.enable_discovery = (len(self.initial_senders) == 0)
        else:
            self.enable_discovery = enable_discovery
        self.discovery_port = discovery_port
        self.min_senders = min_senders
        self.discover_timeout = discover_timeout
        self.target_swarm = target_swarm
        self.device_table = device_table if device_table is not None else DeviceTable()
        self._listener: Optional[DiscoveryListener] = None

        self.enable_tracker = enable_tracker
        self.web_port = web_port
        self.web_host = web_host
        self.web_pin = web_pin
        self.keep_tracker_alive = keep_tracker_alive
        self.exit_when_done = exit_when_done
        self._dashboard_stop_event = threading.Event()

        # Read join code and derive auth and report keys (Section 7.4)
        self.join_code = join_code or get_join_code()
        self.auth_key = derive_auth_key(self.join_code)
        self.report_key = derive_report_key(self.auth_key)

        # In-process tracker state and HTTP monitor server (Sections 12 and 12.5)
        if tracker_state is not None:
            self.tracker_state: Optional[TrackerState] = tracker_state
        elif self.enable_tracker:
            self.tracker_state = TrackerState(
                server_name=self.name,
                server_ip=self.web_host,
                web_port=self.web_port,
                report_key=self.report_key,
                device_table=self.device_table,
            )
        else:
            self.tracker_state = None

        self.tracker_server: Optional[TrackerServer] = None
        if self.enable_tracker and self.tracker_state is not None:
            self.tracker_server = TrackerServer(
                state=self.tracker_state,
                host=self.web_host,
                port=self.web_port,
                web_pin=self.web_pin,
                discovery_port=self.discovery_port,
                device_id=self.device_id,
                enable_beacon=True,
            )

        # Client TLS context pinning the sender's certificate (Section 14.1)
        self.ssl_context = create_client_ssl_context(self.cert_path)

        self.metadata: Optional[Dict[str, Any]] = None
        self.swarm_id: Optional[str] = None
        self.swarm_id_short: Optional[str] = None
        self.writer: Optional[PieceWriter] = None

        # Thread synchronization and work queue
        self._work_queue: queue.Queue[int] = queue.Queue()
        self._done_pieces: Set[int] = set()
        self._piece_attempts: Dict[int, int] = defaultdict(int)
        self._piece_sources: Dict[int, str] = {}
        self._sender_strikes: Dict[str, int] = defaultdict(int)
        self._banned_senders: Set[str] = set()
        self._failed_senders: Set[str] = set()
        self._sender_stats: SenderStatsDict = SenderStatsDict()
        self._connected_device_ids: Set[str] = set()
        self._endpoint_to_device_id: Dict[str, str] = {}
        self._active_device_ids: Set[str] = set()
        self._active_workers: Set[str] = set()
        self._worker_threads: List[threading.Thread] = []
        self._workers_active_max: int = 0
        self._connect_semaphore = threading.Semaphore(config.MAX_CONCURRENT_CONNECT_ATTEMPTS)
        self._sender_failure_times: Dict[str, float] = {}
        self.failure_backoff = 5.0

        self._state_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._fatal_error: Optional[str] = None
        self._start_time: Optional[float] = None
        self._total_bytes_done = 0
        self._bad_pieces_total = 0

    def stop_dashboard(self) -> None:
        """Signal the post-download dashboard keep-alive loop to terminate."""
        self._dashboard_stop_event.set()

    def _on_sender_discovered(self, entry: DeviceEntry) -> None:
        """Callback from DiscoveryListener when a sender is announced (Section 9.2)."""
        if not self.swarm_id_short:
            return
        if entry.swarm_id_short == self.swarm_id_short:
            sender_addr = f"{entry.ip}:{entry.tcp_port}"
            self._endpoint_to_device_id[sender_addr] = entry.device_id
            self._sender_stats.register_endpoint(sender_addr, entry.device_id)
            with self._state_lock:
                if (
                    entry.device_id in self._connected_device_ids
                    or entry.device_id in self._active_device_ids
                    or entry.device_id in self._banned_senders
                ):
                    return
                last_fail = self._sender_failure_times.get(sender_addr, 0.0)
                if time.time() - last_fail < self.failure_backoff:
                    return
                self._active_device_ids.add(entry.device_id)

            added = self.add_sender(sender_addr)
            if not added:
                with self._state_lock:
                    self._active_device_ids.discard(entry.device_id)
            elif self.verbose:
                print(f"\n[DISCOVERY] Dynamically joined newly discovered sender: {entry.name} ({sender_addr})")

    def _discover_initial_senders(self) -> List[str]:
        """Auto-discovery of candidate senders per Section 9.1 steps 3 and 4."""
        # If manual senders were provided and meet min_senders, skip waiting unless zero
        if self.initial_senders and len(self.initial_senders) >= self.min_senders:
            return []

        start_time = time.time()
        chosen_swarm: Optional[str] = None
        candidates: List[str] = []

        if self.verbose:
            print(f"Discovering senders on LAN (UDP port {self.discovery_port})...")

        while time.time() - start_time < self.discover_timeout:
            swarm_groups = self.device_table.get_senders_by_swarm(only_online=True)

            if self.target_swarm:
                matching = {}
                for s_id, devs in swarm_groups.items():
                    if (
                        self.target_swarm in s_id
                        or any(self.target_swarm == d.swarm_name for d in devs)
                        or any(self.target_swarm == d.swarm_id_short for d in devs)
                    ):
                        matching[s_id] = devs
                swarm_groups = matching

            if len(swarm_groups) > 1 and not self.target_swarm:
                swarm_list = [f"{s_id} ({len(devs)} senders)" for s_id, devs in swarm_groups.items()]
                raise RuntimeError(
                    f"Multiple distinct swarms discovered: {', '.join(swarm_list)}. "
                    "Specify which swarm to join with --swarm NAME_OR_ID."
                )

            if len(swarm_groups) == 1:
                s_id, devs = next(iter(swarm_groups.items()))
                chosen_swarm = s_id
                candidates = [f"{d.ip}:{d.tcp_port}" for d in devs]
                with self._state_lock:
                    for d in devs:
                        self._active_device_ids.add(d.device_id)
                if (len(candidates) + len(self.initial_senders)) >= self.min_senders:
                    break

            time.sleep(0.2)

        if len(swarm_groups) > 1 and not self.target_swarm:
            swarm_list = [f"{s_id} ({len(devs)} senders)" for s_id, devs in swarm_groups.items()]
            raise RuntimeError(
                f"Multiple distinct swarms discovered: {', '.join(swarm_list)}. "
                "Specify which swarm to join with --swarm NAME_OR_ID."
            )

        if not candidates and not self.initial_senders:
            raise ConnectionError(
                f"No senders discovered within {self.discover_timeout:.1f}s timeout. "
                "Use --senders host:port to specify manually."
            )

        if self.verbose and candidates:
            dev_names = [f"{d.name} ({d.ip})" for d in self.device_table.get_devices(role="sender", only_online=True)]
            print(f"Discovered senders: {', '.join(dev_names)}  swarm={chosen_swarm or '-'}")

        return candidates

    def download(self) -> Dict[str, Any]:
        """Execute the multi-sender download workflow."""
        if self.tracker_server:
            try:
                self.tracker_server.start(blocking=False)
                if self.verbose:
                    print(f"P2P Swarm Receiver | {self.name} | dashboard: {format_dashboard_urls(self.tracker_server.host, self.tracker_server.port)}")
            except (Exception, SystemExit) as err:
                logger.debug("Failed starting tracker server: %s", err)
        elif self.verbose:
            print(f"P2P Swarm Receiver | {self.name} | TLS on")

        # Step 0: Start UDP discovery listener and resolve candidate seeders
        if self.enable_discovery:
            self._listener = DiscoveryListener(
                own_device_id=self.device_id,
                device_table=self.device_table,
                port=self.discovery_port,
                on_sender_discovered=self._on_sender_discovered,
            )
            self._listener.start()

            discovered = self._discover_initial_senders()
            for s in discovered:
                if s not in self.initial_senders:
                    self.initial_senders.append(s)

        if not self.initial_senders:
            raise ConnectionError(
                "No senders available. Provide --senders host:port or enable automatic discovery."
            )

        if self.verbose:
            print(f"Initial seeders: {', '.join(self.initial_senders)}")

        try:
            # Step 1: Establish metadata and swarm ID from the first reachable seeder
            self._fetch_initial_metadata()
            assert self.metadata is not None and self.swarm_id is not None

            if self.tracker_state:
                try:
                    self.tracker_state.set_swarm(self.metadata, self.swarm_id)
                    self.tracker_state.set_transfer_state("downloading")
                except Exception as err:
                    logger.debug("Tracker set_swarm error: %s", err)

            total_pieces = len(self.metadata["piece_hashes"])
            total_bytes = self.metadata["total_size"]
            num_files = len(self.metadata["files"])

            if self.verbose:
                root_desc = f"{self.metadata['root']}/" if self.metadata['root'] else self.metadata['files'][0]['path']
                print(f"Swarm ID: {self.swarm_id_short} | Content: {root_desc} ({num_files} files, {total_bytes / (1024 * 1024):.1f} MB, {total_pieces} pieces)")

            # Step 2: Initialize PieceWriter and populate missing piece queue
            self.writer = PieceWriter(self.out_dir, self.metadata, overwrite=self.overwrite)

            for i in range(total_pieces):
                self._work_queue.put(i)

            self._start_time = time.time()

            # Step 3: Spawn a worker thread for each candidate sender
            for sender_str in list(self.initial_senders):
                self._start_worker(sender_str)

            # Step 4: Monitor transfer completion in main thread
            while not self._stop_event.is_set():
                with self._state_lock:
                    if self._fatal_error:
                        raise RuntimeError(f"Download aborted: {self._fatal_error}")
                    if len(self._done_pieces) >= total_pieces:
                        break
                    if not self._active_workers:
                        raise ConnectionError("All senders went offline or were banned before download finished.")
                time.sleep(0.1)
        finally:
            self._stop_event.set()
            if self._listener:
                self._listener.stop()
                self._listener = None
            for t in list(self._worker_threads):
                t.join(timeout=2.0)
            if self.writer:
                self.writer.close()
            download_succeeded = bool(self.writer and self.writer.is_complete())
            if self.tracker_server and not self.keep_tracker_alive:
                if self.exit_when_done or not download_succeeded:
                    try:
                        self.tracker_server.stop()
                    except Exception:
                        pass

        elapsed = max(0.001, time.time() - (self._start_time or time.time()))

        if self.tracker_state:
            try:
                if self.writer and self.writer.is_complete():
                    self.tracker_state.set_transfer_state("complete")
            except Exception:
                pass

        if self.verbose:
            print("\n")
            self._print_final_summary(elapsed, total_pieces, num_files)

        if self.enable_tracker and self.tracker_server and not self.exit_when_done and download_succeeded:
            print("Transfer complete. Dashboard still running; press Ctrl+C to quit")
            try:
                while not self._dashboard_stop_event.is_set():
                    time.sleep(0.2)
            except KeyboardInterrupt:
                pass
            finally:
                if not self.keep_tracker_alive:
                    try:
                        self.tracker_server.stop()
                    except Exception:
                        pass

        return {
            "status": "complete" if (self.writer and self.writer.is_complete()) else "incomplete",
            "swarm_id": self.swarm_id,
            "pieces_done": len(self._done_pieces),
            "bytes_done": self._total_bytes_done,
            "total_bytes": total_bytes,
            "elapsed_s": elapsed,
            "bad_pieces": self._bad_pieces_total,
            "sender_stats": self._sender_stats.copy(),
            "banned_senders": BannedSendersList(self._banned_senders, self._endpoint_to_device_id),
            "failed_senders": list(self._failed_senders),
            "completed": self.writer.is_complete(),
            "workers": self._workers_active_max or len(self._connected_device_ids),
            "connected_device_ids": list(self._connected_device_ids),
        }

    def add_sender(self, sender_str: str) -> bool:
        """Dynamically join a newly discovered sender mid-transfer (Section 9.2)."""
        with self._state_lock:
            if sender_str in self._active_workers or sender_str in self._banned_senders:
                return False
            # Check if this sender recently failed and is currently in backoff
            last_fail = self._sender_failure_times.get(sender_str, 0.0)
            if time.time() - last_fail < self.failure_backoff:
                return False
            if self._stop_event.is_set():
                return False
            self._failed_senders.discard(sender_str)

        t = self._start_worker(sender_str)
        return t is not None

    def _start_worker(self, sender_str: str) -> Optional[threading.Thread]:
        """Parse sender address and start a worker thread."""
        if ":" in sender_str:
            host, port_str = sender_str.split(":", 1)
            port = int(port_str)
        else:
            host = sender_str
            port = config.DEFAULT_TCP_PORT

        sender_label = f"{host}:{port}"
        with self._state_lock:
            if sender_label in self._active_workers:
                return None
            self._active_workers.add(sender_label)

        t = threading.Thread(
            target=self._sender_worker,
            args=(sender_label, host, port),
            daemon=True,
        )
        self._worker_threads.append(t)
        t.start()
        return t

    def _connect_and_handshake(self, host: str, port: int, sender_label: str) -> Tuple[ssl.SSLSocket, str, str, str]:
        """Establish TLS connection and execute mutual challenge-response authentication.

        Steps:
        1. Open TCP and wrap with pinned TLS context (Section 14.1).
        2. Receive CHALLENGE(nonce, device_id, name).
        3. Check device_id ban status.
        4. Send HELLO(proof = HMAC(auth_key, nonce || client_device_id)).
        5. Receive WELCOME(proof_server, swarm_id).
        6. Verify proof_server in constant time (Section 7.3 Step 5).

        Returns:
            Tuple of (authenticated_tls_socket, sender_swarm_id, sender_device_id, sender_name).
        """
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(self.handshake_timeout)
        try:
            raw_sock.connect((host, port))
        except ConnectionRefusedError:
            raw_sock.close()
            raise ConnectionError(f"connection refused: sender is not running or port is closed (peer {sender_label})") from None
        except (TimeoutError, socket.timeout):
            raw_sock.close()
            raise ConnectionError(f"connection timed out connecting to {sender_label}") from None
        except OSError as err:
            raw_sock.close()
            raise ConnectionError(f"Failed to connect to {sender_label}: {format_tls_error(err)}") from None

        # 1. TLS Handshake pinning certificate
        try:
            tls_sock = self.ssl_context.wrap_socket(raw_sock, server_hostname=None)
        except (ssl.SSLError, OSError) as err:
            raw_sock.close()
            raise ConnectionError(f"{format_tls_error(err)} (peer {sender_label})") from None

        try:
            # 2. Receive CHALLENGE
            challenge_hdr, _ = recv_message(tls_sock, max_payload_len=0)
            if challenge_hdr.get("type") != "CHALLENGE" or challenge_hdr.get("v") != config.PROTOCOL_VERSION:
                tls_sock.close()
                raise ProtocolError(f"Expected CHALLENGE message from {sender_label}, got {challenge_hdr}")

            sender_device_id = str(challenge_hdr.get("device_id") or sender_label)
            sender_name = str(challenge_hdr.get("name") or sender_device_id)

            if sender_device_id in self._banned_senders:
                tls_sock.close()
                raise AuthError(f"Sender {sender_device_id} ({sender_label}) is banned!")

            nonce_hex = challenge_hdr.get("nonce", "")
            nonce_bytes = bytes.fromhex(nonce_hex)

            # 3. Send HELLO with client proof
            client_proof = compute_client_proof(self.auth_key, nonce_bytes, self.device_id)
            hello_msg = make_hello(
                device_id=self.device_id,
                name=self.name,
                role="receiver",
                proof=client_proof,
            )
            send_message(tls_sock, hello_msg)

            # 4. Receive WELCOME (or ERROR)
            resp_hdr, _ = recv_message(tls_sock, max_payload_len=0)
            msg_type = resp_hdr.get("type")
            if msg_type == "ERROR":
                tls_sock.close()
                err_code = resp_hdr.get("code")
                err_msg = resp_hdr.get("message")
                if err_code == "AUTH_FAILED":
                    raise AuthError(f"Authentication rejected by {sender_label}: {err_msg}")
                if err_code == "RATE_LIMITED":
                    raise AuthError(f"Rate limited by {sender_label}: {err_msg}")
                raise ProtocolError(f"Handshake error from {sender_label}: {err_code} - {err_msg}")

            if msg_type != "WELCOME":
                tls_sock.close()
                raise ProtocolError(f"Expected WELCOME message from {sender_label}, got {resp_hdr}")

            server_proof = resp_hdr.get("proof", "")
            sender_swarm_id = resp_hdr.get("swarm_id", "")

            # 5. Verify server mutual proof in constant time
            if not verify_server_proof(self.auth_key, nonce_bytes, self.device_id, server_proof):
                tls_sock.close()
                raise AuthError(f"Sender {sender_label} failed mutual server proof!")

            # Handshake complete: switch to socket timeout
            tls_sock.settimeout(config.SOCKET_TIMEOUT)
            return tls_sock, sender_swarm_id, sender_device_id, sender_name
        except (TimeoutError, socket.timeout):
            tls_sock.close()
            raise ConnectionError(f"handshake timed out during authentication with {sender_label}") from None

    def _fetch_initial_metadata(self) -> None:
        """Connect to initial senders in sequence until valid metadata is obtained."""
        last_error = None
        for sender_str in self.initial_senders:
            if ":" in sender_str:
                host, port_str = sender_str.split(":", 1)
                port = int(port_str)
            else:
                host = sender_str
                port = config.DEFAULT_TCP_PORT

            try:
                with self._connect_semaphore:
                    tls_sock, _, sender_device_id, sender_name = self._connect_and_handshake(host, port, sender_str)
                self._endpoint_to_device_id[sender_str] = sender_device_id
                self._endpoint_to_device_id[f"{host}:{port}"] = sender_device_id
                self._sender_stats.register_endpoint(sender_str, sender_device_id)
                self._sender_stats.register_endpoint(f"{host}:{port}", sender_device_id)

                send_message(tls_sock, make_get_metadata())
                meta_hdr, canon_bytes = recv_message(tls_sock, max_payload_len=config.MAX_METADATA_BYTES)
                tls_sock.close()

                if meta_hdr.get("type") != "METADATA":
                    continue

                meta = json.loads(canon_bytes.decode("utf-8"))
                validate_metadata(meta, out_dir=self.out_dir)

                self.metadata = meta
                self.swarm_id = compute_swarm_id(meta)
                self.swarm_id_short = compute_swarm_id_short(self.swarm_id)
                return
            except Exception as err:
                last_error = err
                continue

        raise ConnectionError(f"Could not retrieve valid metadata from any sender: {last_error}")

    def _sender_worker(self, sender_label: str, host: str, port: int) -> None:
        """Worker thread dedicated to pulling pieces from one verified sender over TLS."""
        sock: Optional[ssl.SSLSocket] = None
        sender_device_id: Optional[str] = None
        sender_name: Optional[str] = None
        is_connected_owner = False
        try:
            # Reconnect loop
            for reconnect_attempt in range(config.CONNECT_RETRIES):
                if self._stop_event.is_set():
                    return
                try:
                    with self._connect_semaphore:
                        sock, sender_swarm_id, sender_device_id, sender_name = self._connect_and_handshake(host, port, sender_label)

                    self._endpoint_to_device_id[sender_label] = sender_device_id
                    self._endpoint_to_device_id[f"{host}:{port}"] = sender_device_id
                    self._sender_stats.register_endpoint(sender_label, sender_device_id)
                    self._sender_stats.register_endpoint(f"{host}:{port}", sender_device_id)

                    # Deduplication check: if device_id is already connected, close duplicate connection
                    with self._state_lock:
                        if sender_device_id in self._connected_device_ids:
                            logger.info(
                                "Closing duplicate connection for sender %s (%s)",
                                sender_device_id,
                                sender_label,
                            )
                            if self.verbose:
                                print(
                                    f"\n[DUPLICATE] Sender {sender_name} (device_id={sender_device_id}, endpoint={sender_label}) is already connected. Closing duplicate connection."
                                )
                            sock.close()
                            sock = None
                            cur_t = threading.current_thread()
                            if cur_t in self._worker_threads:
                                self._worker_threads.remove(cur_t)
                            return

                        self._connected_device_ids.add(sender_device_id)
                        self._active_device_ids.add(sender_device_id)
                        is_connected_owner = True
                        self._workers_active_max = max(self._workers_active_max, len(self._connected_device_ids))

                        if sender_device_id not in self._sender_stats:
                            self._sender_stats[sender_device_id] = {
                                "pieces": 0,
                                "bytes": 0,
                                "device_id": sender_device_id,
                                "name": sender_name,
                                "endpoint": sender_label,
                                "tcp_port": port,
                            }

                    # Verify Swarm ID matches (Section 7.3 Step 7)
                    if sender_swarm_id != self.swarm_id:
                        expected_id = self.swarm_id[:16] if self.swarm_id else "None"
                        sender_id_short = sender_swarm_id[:16] if sender_swarm_id else "None"
                        print(f"\n[WARNING] SWARM_MISMATCH: Sender {sender_name} ({sender_label}) offered swarm {sender_id_short} != expected {expected_id}. Disconnecting.")
                        sock.close()
                        sock = None
                        with self._state_lock:
                            self._failed_senders.add(sender_device_id)
                            self._failed_senders.add(sender_label)
                        if self.tracker_state:
                            try:
                                self.tracker_state.on_sender_failed(sender_device_id, sender_name)
                            except Exception:
                                pass
                        return

                    # Authentication succeeded: Show "Verified" (Section 15)
                    self.device_table.mark_verified(sender_device_id)
                    self.device_table.mark_verified(sender_label)
                    self.device_table.mark_verified(f"{host}:{port}")
                    if self.tracker_state:
                        try:
                            self.tracker_state.on_sender_verified(
                                device_id=sender_device_id,
                                name=sender_name,
                                ip=host,
                                tcp_port=port,
                            )
                        except Exception:
                            pass
                    if self.verbose:
                        print(f"Verified {sender_name} ({sender_label})  OK")
                    break

                except (OSError, ProtocolError, AuthError) as err:
                    if sock:
                        try:
                            sock.close()
                        except OSError:
                            pass
                        sock = None
                    if isinstance(err, AuthError):
                        # Auth failure is non-retryable
                        with self._state_lock:
                            if sender_device_id:
                                self._failed_senders.add(sender_device_id)
                            self._failed_senders.add(sender_label)
                        if self.tracker_state:
                            try:
                                if sender_device_id:
                                    self.tracker_state.on_sender_failed(sender_device_id, sender_name)
                                self.tracker_state.on_auth_rejected(host)
                            except Exception:
                                pass
                        if self.verbose:
                            print(f"\n[!] Authentication failure with {sender_label}: {err}")
                        return

                    if reconnect_attempt < config.CONNECT_RETRIES - 1:
                        backoff = self.backoff_base * (2 ** reconnect_attempt)
                        time.sleep(backoff)
                    else:
                        with self._state_lock:
                            if sender_device_id:
                                self._failed_senders.add(sender_device_id)
                            self._failed_senders.add(sender_label)
                            self._sender_failure_times[sender_label] = time.time()
                            self._sender_failure_times[f"{host}:{port}"] = time.time()
                        if self.tracker_state:
                            try:
                                if sender_device_id:
                                    self.tracker_state.on_sender_failed(sender_device_id, sender_name)
                            except Exception:
                                pass
                        if self.verbose:
                            print(f"\n[!] Failed to connect to {sender_label} after {config.CONNECT_RETRIES} attempts.")
                        return

            if not sock or not sender_device_id:
                return

            total_pieces = len(self.metadata["piece_hashes"])

            # Work Queue Loop (Section 9.3)
            while not self._stop_event.is_set():
                with self._state_lock:
                    if len(self._done_pieces) >= total_pieces:
                        break
                    if sender_device_id in self._banned_senders or sender_label in self._banned_senders:
                        break

                # 1-second timeout: queue momentarily empty does NOT exit worker! (Section 9.3)
                try:
                    piece_idx = self._work_queue.get(timeout=1.0)
                except queue.Empty:
                    continue

                # Check if completed by another worker while waiting in queue
                with self._state_lock:
                    if piece_idx in self._done_pieces:
                        self._work_queue.task_done()
                        continue
                    if self._piece_attempts[piece_idx] >= config.MAX_PIECE_ATTEMPTS:
                        self._fatal_error = f"Piece {piece_idx} exceeded MAX_PIECE_ATTEMPTS ({config.MAX_PIECE_ATTEMPTS})"
                        self._stop_event.set()
                        self._work_queue.task_done()
                        break

                # Request piece from this sender with per-request timeout
                try:
                    sock.settimeout(self.request_timeout)
                    send_message(sock, make_request(piece_idx))
                    hdr, payload = recv_message(sock, max_payload_len=config.MAX_PIECE_PAYLOAD)
                    if hdr.get("type") != "PIECE" or hdr.get("index") != piece_idx:
                        raise ProtocolError(f"Unexpected response: {hdr}")
                except (OSError, ProtocolError) as err:
                    # Timeout or connection failure
                    with self._state_lock:
                        self._work_queue.put(piece_idx)
                        self._work_queue.task_done()
                        self._failed_senders.add(sender_device_id)
                        self._failed_senders.add(sender_label)
                        self._piece_attempts[piece_idx] += 1
                        if self._piece_attempts[piece_idx] >= config.MAX_PIECE_ATTEMPTS:
                            self._fatal_error = f"Piece {piece_idx} exceeded MAX_PIECE_ATTEMPTS ({config.MAX_PIECE_ATTEMPTS})"
                            self._stop_event.set()
                    if self.tracker_state:
                        try:
                            self.tracker_state.on_sender_failed(sender_device_id, sender_name)
                        except Exception:
                            pass
                    if self.verbose:
                        print(f"\n[!] Connection error or request timeout with {sender_label} on piece {piece_idx}: {err}")
                    break

                # Check length and SHA-256 against metadata
                expected_hash = self.metadata["piece_hashes"][piece_idx]
                actual_hash = hashlib.sha256(payload).hexdigest()

                if actual_hash == expected_hash:
                    # Match: write to disk and register completion
                    try:
                        completed_files = self.writer.write_piece(piece_idx, payload)
                    except Exception as err:
                        with self._state_lock:
                            self._work_queue.put(piece_idx)
                            self._work_queue.task_done()
                        print(f"\n[!] Disk write failed on piece {piece_idx}: {err}")
                        break

                    with self._state_lock:
                        self._done_pieces.add(piece_idx)
                        self._piece_sources[piece_idx] = sender_device_id
                        self._sender_stats[sender_device_id]["pieces"] += 1
                        self._sender_stats[sender_device_id]["bytes"] += len(payload)
                        self._total_bytes_done += len(payload)
                        done_count = len(self._done_pieces)

                    self._work_queue.task_done()

                    if self.tracker_state:
                        try:
                            self.tracker_state.on_piece_downloaded(
                                piece_index=piece_idx,
                                device_id=sender_device_id,
                                sender_name=sender_name,
                                piece_bytes=len(payload),
                            )
                            for comp_f in completed_files:
                                self.tracker_state.on_file_complete(comp_f)
                        except Exception:
                            pass

                    if self.verbose:
                        for comp_f in completed_files:
                            print(f"\nFile complete: {comp_f}")

                        bar_str = render_progress_bar(
                            pieces_done=done_count,
                            total_pieces=total_pieces,
                            bytes_done=self._total_bytes_done,
                            total_bytes=self.metadata["total_size"],
                            elapsed=max(0.001, time.time() - (self._start_time or time.time())),
                        )
                        sys.stdout.write(f"\r{bar_str}")
                        sys.stdout.flush()

                else:
                    # Hash Mismatch: discard bytes, put index back, increment strike count
                    with self._state_lock:
                        self._work_queue.put(piece_idx)
                        self._work_queue.task_done()
                        self._bad_pieces_total += 1
                        self._sender_strikes[sender_device_id] += 1
                        self._piece_attempts[piece_idx] += 1
                        strikes = self._sender_strikes[sender_device_id]
                        is_banned = (strikes >= config.HASH_STRIKES_TO_BAN)
                        if is_banned:
                            self._banned_senders.add(sender_device_id)
                            self._failed_senders.add(sender_device_id)
                            self._failed_senders.add(sender_label)
                            self.device_table.mark_banned(sender_device_id)
                            self.device_table.mark_banned(sender_label)
                        if self._piece_attempts[piece_idx] >= config.MAX_PIECE_ATTEMPTS:
                            self._fatal_error = f"Piece {piece_idx} exceeded MAX_PIECE_ATTEMPTS ({config.MAX_PIECE_ATTEMPTS})"
                            self._stop_event.set()

                    if self.tracker_state:
                        try:
                            self.tracker_state.on_piece_hash_failed(
                                piece_index=piece_idx,
                                device_id=sender_device_id,
                                sender_name=sender_name,
                            )
                            if is_banned:
                                self.tracker_state.on_sender_banned(
                                    device_id=sender_device_id,
                                    sender_name=sender_name,
                                )
                        except Exception:
                            pass

                    print(f"\n[WARNING] Corrupted piece {piece_idx} from {sender_name} ({sender_label})! (strike {strikes}/{config.HASH_STRIKES_TO_BAN})")

                    if is_banned:
                        print(f"\n[SENDER_BANNED] Sender {sender_name} ({sender_device_id}) reached {config.HASH_STRIKES_TO_BAN} hash strikes. Banned for session!")
                        try:
                            send_message(sock, make_bye())
                        except OSError:
                            pass
                        break

            # Signal BYE if leaving gracefully
            if sock and not self._stop_event.is_set():
                try:
                    send_message(sock, make_bye())
                except OSError:
                    pass

        finally:
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass
            with self._state_lock:
                self._active_workers.discard(sender_label)
                if is_connected_owner and sender_device_id:
                    self._connected_device_ids.discard(sender_device_id)
                self._sender_failure_times[sender_label] = time.time()
                self._sender_failure_times[f"{host}:{port}"] = time.time()
                cur_t = threading.current_thread()
                if cur_t in self._worker_threads:
                    self._worker_threads.remove(cur_t)

    def _print_final_summary(self, elapsed: float, total_pieces: int, num_files: int) -> None:
        """Print Section 15 transfer summary with per-sender A/B piece distribution."""
        sender_splits = []
        for dev_id, stats in sorted(self._sender_stats.items()):
            cnt = stats["pieces"]
            pct = (cnt / total_pieces * 100) if total_pieces > 0 else 0
            label = stats.get("name") or dev_id
            sender_splits.append(f"{label}: {cnt} ({pct:.0f}%)")

        split_str = " | ".join(sender_splits) if sender_splits else "no senders"
        files_done = self.writer.completed_files_count() if self.writer else num_files

        print(
            f"Summary: {len(self._done_pieces)} pieces in {elapsed:.1f} s | "
            f"{split_str} | bad pieces: {self._bad_pieces_total} | files: {files_done}/{num_files}"
        )


def download_from_senders(
    senders: Optional[List[str]] = None,
    out_dir: Path = Path("downloads"),
    cert_path: Union[str, Path] = "certs/cert.pem",
    join_code: Optional[str] = None,
    overwrite: bool = False,
    name: str = "Receiver-C",
    verbose: bool = True,
    backoff_base: float = 1.0,
    request_timeout: Optional[float] = None,
    handshake_timeout: Optional[float] = None,
    enable_discovery: Optional[bool] = None,
    discovery_port: int = config.DISCOVERY_PORT,
    min_senders: int = config.DEFAULT_MIN_SENDERS,
    discover_timeout: float = config.DEFAULT_DISCOVER_TIMEOUT,
    target_swarm: Optional[str] = None,
    device_table: Optional[DeviceTable] = None,
    exit_when_done: bool = True,
) -> Dict[str, Any]:
    """Helper function to download from multiple senders concurrently."""
    if enable_discovery is None:
        # Default to False if manual senders were provided (fast unit test fallback),
        # True if no senders were provided (auto-discovery workflow).
        enable_discovery = (senders is None or len(senders) == 0)

    rx = SwarmReceiver(
        senders=senders,
        out_dir=out_dir,
        cert_path=cert_path,
        join_code=join_code,
        overwrite=overwrite,
        name=name,
        verbose=verbose,
        backoff_base=backoff_base,
        request_timeout=request_timeout,
        handshake_timeout=handshake_timeout,
        enable_discovery=enable_discovery,
        discovery_port=discovery_port,
        min_senders=min_senders,
        discover_timeout=discover_timeout,
        target_swarm=target_swarm,
        device_table=device_table,
        exit_when_done=exit_when_done,
    )
    return rx.download()


def main() -> None:
    parser = argparse.ArgumentParser(description="P2P Swarm Receiver (Multi-sender TLS Downloader)")
    parser.add_argument("--out", type=str, required=True, help="Destination directory for downloaded data")
    parser.add_argument(
        "--senders",
        type=str,
        nargs="*",
        default=None,
        help="List of sender addresses in HOST:PORT format (e.g. 127.0.0.1:6881 127.0.0.1:6882). If omitted, senders are auto-discovered via UDP.",
    )
    parser.add_argument(
        "--min-senders",
        type=int,
        default=config.DEFAULT_MIN_SENDERS,
        help=f"Minimum number of candidate senders required before starting download (default: {config.DEFAULT_MIN_SENDERS})",
    )
    parser.add_argument(
        "--discover-timeout",
        type=float,
        default=config.DEFAULT_DISCOVER_TIMEOUT,
        help=f"Seconds to wait for auto-discovery before erroring (default: {config.DEFAULT_DISCOVER_TIMEOUT}s)",
    )
    parser.add_argument(
        "--swarm",
        type=str,
        default=None,
        help="Swarm name or 8-char short hex ID to filter/join when multiple swarms are present",
    )
    parser.add_argument(
        "--no-discovery",
        action="store_true",
        help="Disable automatic UDP discovery (requires --senders)",
    )
    parser.add_argument(
        "--discovery-port",
        type=int,
        default=config.DISCOVERY_PORT,
        help=f"UDP discovery port (default: {config.DISCOVERY_PORT})",
    )
    parser.add_argument("--cert", type=str, default="certs/cert.pem", help="Path to pinned sender TLS certificate")
    parser.add_argument("--code", type=str, default=None, help="Shared swarm join code (prefer P2P_JOIN_CODE env var)")
    parser.add_argument("--name", type=str, default="Receiver-C", help="Receiver display name")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite existing files in destination directory")
    parser.add_argument(
        "--request-timeout",
        type=float,
        default=config.REQUEST_TIMEOUT,
        help=f"Per-request response timeout in seconds (default: {config.REQUEST_TIMEOUT})",
    )
    parser.add_argument(
        "--handshake-timeout",
        type=float,
        default=config.HANDSHAKE_TIMEOUT,
        help=f"Handshake and authentication timeout in seconds (default: {config.HANDSHAKE_TIMEOUT})",
    )
    parser.add_argument(
        "--web-port",
        type=int,
        default=config.DEFAULT_WEB_PORT,
        help=f"HTTP port for monitor dashboard and telemetry (default: {config.DEFAULT_WEB_PORT})",
    )
    parser.add_argument(
        "--web-host",
        type=str,
        default="0.0.0.0",
        help="HTTP host to bind the monitor dashboard to (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--web-pin",
        type=str,
        default=None,
        help="Optional PIN required to access the dashboard and /api/state",
    )
    parser.add_argument(
        "--no-tracker",
        action="store_true",
        help="Disable the embedded HTTP tracker and dashboard",
    )
    parser.add_argument(
        "--exit-when-done",
        action="store_true",
        help="Exit immediately after transfer finishes instead of keeping the dashboard alive until Ctrl+C",
    )

    args = parser.parse_args()

    if args.no_discovery and not args.senders:
        parser.error("Cannot disable discovery (--no-discovery) without providing manual --senders.")

    join_code = get_join_code(args.code)

    receiver = SwarmReceiver(
        senders=args.senders,
        out_dir=Path(args.out),
        cert_path=Path(args.cert),
        join_code=join_code,
        overwrite=args.overwrite,
        name=args.name,
        verbose=True,
        request_timeout=args.request_timeout,
        handshake_timeout=args.handshake_timeout,
        enable_discovery=not args.no_discovery,
        discovery_port=args.discovery_port,
        min_senders=args.min_senders,
        discover_timeout=args.discover_timeout,
        target_swarm=args.swarm,
        enable_tracker=not args.no_tracker,
        web_port=args.web_port,
        web_host=args.web_host,
        web_pin=args.web_pin,
        exit_when_done=args.exit_when_done,
    )

    try:
        receiver.download()
    except KeyboardInterrupt:
        print("\nDownload interrupted by user (Ctrl+C). Partial files kept as .part.")
        sys.exit(130)
    except Exception as err:
        print(f"\nDownload failed: {err}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
