"""P2P Swarm Sender (Seeder daemon).

Implements Section 8, Section 14.1 (TLS 1.2+), and Section 7.3/7.4 (Mutual Join-Code Authentication):
- Serves file or folder data over TLS with certificate pinning.
- Mutual authentication: challenge-response handshake using Scrypt-derived keys and constant-time HMAC.
- Per-IP rate limiting protecting against brute-force authentication attempts.
- Bandwidth throttling (--throttle-kbps) for classroom demonstrations.
- Section 15 terminal output tracking transfers and peer verification.
"""

import argparse
import os
from pathlib import Path
import secrets
import socket
import ssl
import sys
import threading
import time
from typing import Any, Dict, Optional, Union

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from common.auth import (
    AuthRateLimiter,
    compute_server_proof,
    default_rate_limiter,
    derive_auth_key,
    derive_report_key,
    get_join_code,
    verify_client_proof,
)
from common.metadata import build_metadata, compute_swarm_id_short
from common.pieces import PieceReader
from common.protocol import (
    ConnectionClosedError,
    ProtocolError,
    make_challenge,
    make_error,
    make_metadata_header,
    make_piece_header,
    make_welcome,
    recv_message,
    send_message,
)
from common.discovery import (
    DeviceEntry,
    DeviceTable,
    DiscoveryBroadcaster,
    DiscoveryListener,
    make_heartbeat,
)
from common.reporting import ReportClient
from common.tlsutil import create_server_ssl_context, format_tls_error
import config


class SenderServer:
    """TLS Seeder server managing authenticated peer streaming and request fulfillment."""

    def __init__(
        self,
        source_path: Path,
        port: int = config.DEFAULT_TCP_PORT,
        bind_host: str = "0.0.0.0",
        name: str = "Sender-A",
        cert_path: Union[str, Path] = "certs/cert.pem",
        key_path: Union[str, Path] = "certs/key.pem",
        join_code: Optional[str] = None,
        rate_limiter: Optional[AuthRateLimiter] = None,
        piece_size: int = config.DEFAULT_PIECE_SIZE,
        throttle_kbps: Optional[int] = None,
        device_id: Optional[str] = None,
        handshake_timeout: float = config.HANDSHAKE_TIMEOUT,
        enable_discovery: bool = True,
        discovery_port: int = config.DISCOVERY_PORT,
        heartbeat_interval: float = config.HEARTBEAT_INTERVAL,
        tracker: Optional[str] = None,
    ) -> None:
        self.source_path = Path(source_path).resolve()
        self.port = port
        self.bind_host = bind_host
        self.name = name
        self.cert_path = Path(cert_path).resolve()
        self.key_path = Path(key_path).resolve()
        self.piece_size = piece_size
        self.throttle_kbps = throttle_kbps
        self._throttle_lock = threading.Lock()
        self._next_allowed_send_time: float = 0.0
        self.device_id = device_id or secrets.token_hex(16)
        self.rate_limiter = rate_limiter or default_rate_limiter
        self.handshake_timeout = handshake_timeout
        self.enable_discovery = enable_discovery
        self.discovery_port = discovery_port
        self.heartbeat_interval = heartbeat_interval
        self.tracker = tracker

        # Read join code and derive cryptographic keys (Section 7.4)
        self.join_code = join_code or get_join_code()
        self.auth_key = derive_auth_key(self.join_code)
        self.report_key = derive_report_key(self.auth_key)

        # Reporter client for sending telemetry to tracker (Section 12.2)
        self.reporter = ReportClient(
            device_id=self.device_id,
            report_key=self.report_key,
            tracker_address=self.tracker,
        )

        # Build canonical metadata and initialize piece reader
        self.metadata, self.canonical_bytes, self.swarm_id = build_metadata(
            self.source_path, piece_size=self.piece_size
        )
        self.swarm_id_short = compute_swarm_id_short(self.swarm_id)
        self.reader = PieceReader(self.source_path, self.metadata)

        # Configure server TLS context (Section 14.1)
        self.ssl_context = create_server_ssl_context(self.cert_path, self.key_path)

        self._server_sock: Optional[socket.socket] = None
        self._broadcaster: Optional[DiscoveryBroadcaster] = None
        self._disc_listener: Optional[DiscoveryListener] = None
        self._is_running = False
        self._pieces_sent = 0
        self._bytes_sent = 0
        self._start_time: Optional[float] = None
        self._lock = threading.Lock()
        self._conn_lock = threading.Lock()
        self._active_conn_count = 0

    def start(self, blocking: bool = True) -> None:
        """Start TLS server listener socket."""
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.bind_host, self.port))
        self._server_sock.listen(config.MAX_CONNECTIONS_PER_SENDER)
        self._is_running = True
        self._start_time = time.time()

        # Update port if dynamic port 0 was passed
        self.port = self._server_sock.getsockname()[1]

        # Start telemetry reporting client
        if self.tracker:
            print(f"Tracker: found at {self.tracker}")
        self.reporter.start()

        # Start automatic UDP discovery heartbeats and beacon listener unless disabled (Section 11)
        if self.enable_discovery:
            def make_hb() -> bytes:
                root_name = self.metadata.get("root")
                if not root_name and self.metadata.get("files"):
                    root_name = self.metadata["files"][0]["path"]
                return make_heartbeat(
                    device_id=self.device_id,
                    name=self.name,
                    role="sender",
                    tcp_port=self.port,
                    swarm_name=root_name or "shared",
                    swarm_id_short=self.swarm_id_short,
                    files=len(self.metadata["files"]),
                    total_bytes=self.metadata["total_size"],
                )

            self._broadcaster = DiscoveryBroadcaster(
                payload_factory=make_hb,
                port=self.discovery_port,
                interval=self.heartbeat_interval,
            )
            self._broadcaster.start()

            # Listen for tracker UDP BEACONs to learn tracker dynamically
            def on_tracker_discovered(entry: DeviceEntry) -> None:
                tracker_addr = f"{entry.ip}:{entry.web_port}"
                if not self.reporter.tracker_address:
                    self.reporter.set_tracker(entry.ip, entry.web_port)
                    print(f"Tracker: found at {tracker_addr}")

            self._disc_listener = DiscoveryListener(
                own_device_id=self.device_id,
                device_table=DeviceTable(),
                port=self.discovery_port,
                on_tracker_discovered=on_tracker_discovered,
            )
            self._disc_listener.start()

        self._print_startup_banner()

        if blocking:
            self._serve_loop()
        else:
            t = threading.Thread(target=self._serve_loop, daemon=True)
            t.start()

    def stop(self) -> None:
        """Shut down sender server."""
        self._is_running = False
        self.reporter.stop()
        if self._broadcaster:
            self._broadcaster.stop()
            self._broadcaster = None
        if self._disc_listener:
            self._disc_listener.stop()
            self._disc_listener = None
        if self._server_sock:
            try:
                self._server_sock.close()
            except OSError:
                pass
        self.reader.close()

    def _print_startup_banner(self) -> None:
        """Print Section 15 terminal header."""
        total_mb = self.metadata["total_size"] / (1024 * 1024)
        num_files = len(self.metadata["files"])
        num_pieces = len(self.metadata["piece_hashes"])
        piece_kib = self.metadata["piece_size"] // 1024

        print(f"P2P Swarm Sender | name={self.name} | {self.bind_host}:{self.port} | TLS on")
        root_desc = f"{self.metadata['root']}/" if self.metadata['root'] else self.metadata['files'][0]['path']
        print(
            f"Sharing: {root_desc} ({num_files} files, {total_mb:.1f} MB, {num_pieces} pieces of {piece_kib} KiB)  "
            f"swarm={self.swarm_id_short}"
        )
        print("Ready for receiver connections...\n")

    def _serve_loop(self) -> None:
        """Accept connections and dispatch to worker threads."""
        while self._is_running:
            try:
                client_sock, client_addr = self._server_sock.accept()
                client_sock.settimeout(self.handshake_timeout)
                client_ip, client_port = client_addr

                # Check max concurrent connections (Section 5, Section 8)
                with self._conn_lock:
                    if self._active_conn_count >= config.MAX_CONNECTIONS_PER_SENDER:
                        try:
                            send_message(
                                client_sock,
                                make_error("BUSY", f"Maximum connections ({config.MAX_CONNECTIONS_PER_SENDER}) reached"),
                            )
                        except OSError:
                            pass
                        client_sock.close()
                        continue
                    self._active_conn_count += 1

                # Check per-IP rate limit before TLS handshake (Section 14.2)
                is_blocked, remaining = self.rate_limiter.is_blocked(client_ip)
                if is_blocked:
                    print(f"[RATE_LIMITED] Rejecting connection from blocked IP {client_ip} ({remaining:.1f}s remaining)")
                    try:
                        send_message(
                            client_sock,
                            make_error("RATE_LIMITED", f"Too many authentication failures. Blocked for {int(remaining)}s."),
                        )
                    except OSError:
                        pass
                    with self._conn_lock:
                        self._active_conn_count -= 1
                    client_sock.close()
                    continue

                t = threading.Thread(
                    target=self._handle_client,
                    args=(client_sock, client_addr),
                    daemon=True,
                )
                t.start()
            except OSError:
                break

    def _handle_client(self, raw_sock: socket.socket, client_addr: tuple) -> None:
        """Execute TLS handshake and mutual join-code challenge-response with connecting peer."""
        client_ip, client_port = client_addr
        tls_sock: Optional[ssl.SSLSocket] = None

        try:
            # 1. Complete TLS handshake within handshake_timeout
            try:
                tls_sock = self.ssl_context.wrap_socket(raw_sock, server_side=True)
            except (TimeoutError, socket.timeout):
                print(f"Handshake timed out from {client_ip}:{client_port}")
                return
            except (ssl.SSLError, OSError) as err:
                print(f"TLS handshake failed from {client_ip}:{client_port}: {format_tls_error(err)}")
                return

            # 2. Step 2: Send CHALLENGE with fresh random nonce (Section 7.3)
            nonce_bytes = secrets.token_bytes(32)
            nonce_hex = nonce_bytes.hex()
            challenge_msg = make_challenge(
                device_id=self.device_id,
                name=self.name,
                nonce=nonce_hex,
            )
            send_message(tls_sock, challenge_msg)

            # 3. Step 3: Receive HELLO with client proof (Section 7.3)
            try:
                hello_hdr, _ = recv_message(tls_sock, max_payload_len=0)
            except (TimeoutError, socket.timeout):
                print(f"Handshake timed out waiting for HELLO from {client_ip}:{client_port}")
                return

            if hello_hdr.get("type") != "HELLO" or hello_hdr.get("v") != config.PROTOCOL_VERSION:
                try:
                    send_message(tls_sock, make_error("BAD_REQUEST", "Expected HELLO message with valid protocol version"))
                except OSError:
                    pass
                return

            client_device_id = hello_hdr.get("device_id", "")
            client_name = hello_hdr.get("name", "Unknown-Receiver")
            client_proof = hello_hdr.get("proof", "")

            # 4. Step 4: Verify client proof in constant time (Section 7.3)
            if not verify_client_proof(self.auth_key, nonce_bytes, client_device_id, client_proof):
                newly_blocked = self.rate_limiter.record_failure(client_ip)
                print(f"[AUTH_FAILED] Invalid join-code proof from {client_ip}:{client_port} ({client_name})")
                if newly_blocked:
                    print(f"[RATE_LIMITED] IP {client_ip} exceeded {config.AUTH_MAX_FAILURES} failures. Blocked for {config.AUTH_BLOCK_SECONDS}s!")
                try:
                    send_message(tls_sock, make_error("AUTH_FAILED", "Invalid join-code authentication proof"))
                except OSError:
                    pass
                return

            # 5. Step 5: Send WELCOME with mutual server proof (Section 7.3)
            self.rate_limiter.record_success(client_ip)
            server_proof = compute_server_proof(self.auth_key, nonce_bytes, client_device_id)
            welcome_msg = make_welcome(proof=server_proof, swarm_id=self.swarm_id)
            send_message(tls_sock, welcome_msg)

            print(f"Receiver {client_name} ({client_ip}:{client_port}) connected (verified)")
            with self._conn_lock:
                self._active_conn_count += 1
            self.reporter.update_stats(self._pieces_sent, self._bytes_sent, self._active_conn_count)
            self.reporter.record_event("RECEIVER_CONNECTED", f"Receiver {client_name} connected")

            # Authentication succeeded: switch to general socket timeout for data transfer
            tls_sock.settimeout(config.SOCKET_TIMEOUT)

            # 6. Service loop: METADATA, REQUEST, BYE
            while self._is_running:
                try:
                    header, _ = recv_message(tls_sock)
                except (ConnectionClosedError, ProtocolError):
                    break

                msg_type = header.get("type")

                if msg_type == "GET_METADATA":
                    resp_hdr = make_metadata_header(self.swarm_id)
                    send_message(tls_sock, resp_hdr, payload=self.canonical_bytes)

                elif msg_type == "REQUEST":
                    idx = header.get("index")
                    num_pieces = len(self.metadata["piece_hashes"])
                    if not isinstance(idx, int) or idx < 0 or idx >= num_pieces:
                        err_msg = make_error("BAD_INDEX", f"Requested piece index {idx} out of range [0, {num_pieces})")
                        send_message(tls_sock, err_msg)
                        continue

                    # Read piece data across files
                    try:
                        piece_bytes = self.reader.read_piece(idx)
                    except Exception as err:
                        err_msg = make_error("INTERNAL", f"Failed reading piece {idx}: {err}")
                        send_message(tls_sock, err_msg)
                        continue

                    # Optional demo throttle applied per sender across all peer connections
                    if self.throttle_kbps and self.throttle_kbps > 0:
                        chunk_seconds = len(piece_bytes) / (self.throttle_kbps * 1024.0)
                        with self._throttle_lock:
                            now = time.time()
                            if self._next_allowed_send_time < now:
                                self._next_allowed_send_time = now
                            send_at = self._next_allowed_send_time
                            self._next_allowed_send_time += chunk_seconds
                        sleep_dur = send_at - time.time()
                        if sleep_dur > 0:
                            time.sleep(sleep_dur)

                    # Send piece message
                    piece_hdr = make_piece_header(index=idx, length=len(piece_bytes))
                    send_message(tls_sock, piece_hdr, payload=piece_bytes)

                    # Update statistics
                    with self._lock:
                        self._pieces_sent += 1
                        self._bytes_sent += len(piece_bytes)
                        elapsed = max(0.001, time.time() - (self._start_time or time.time()))
                        speed_mb = (self._bytes_sent / (1024 * 1024)) / elapsed

                    self.reporter.update_stats(self._pieces_sent, self._bytes_sent, self._active_conn_count)
                    print(f"Sent piece {idx + 1:4d}/{num_pieces} -> {client_name} [{self._pieces_sent} pieces] [{speed_mb:.1f} MB/s]")

                elif msg_type == "BYE":
                    print(f"Receiver {client_name} ({client_ip}:{client_port}) finished and sent BYE.")
                    self.reporter.record_event("RECEIVER_BYE", f"Receiver {client_name} disconnected")
                    break
                else:
                    err_msg = make_error("BAD_REQUEST", f"Unexpected message type: {msg_type}")
                    send_message(tls_sock, err_msg)

        finally:
            with self._conn_lock:
                self._active_conn_count = max(0, self._active_conn_count - 1)
            self.reporter.update_stats(self._pieces_sent, self._bytes_sent, self._active_conn_count)
            if tls_sock:
                try:
                    tls_sock.close()
                except OSError:
                    pass
            else:
                try:
                    raw_sock.close()
                except OSError:
                    pass
            print(f"Connection with {client_ip}:{client_port} closed.")


def main() -> None:
    parser = argparse.ArgumentParser(description="P2P Swarm Sender (TLS Seeder daemon)")
    parser.add_argument("--path", type=str, required=True, help="Path to file or folder to share")
    parser.add_argument("--port", type=int, default=config.DEFAULT_TCP_PORT, help=f"Listening port (default: {config.DEFAULT_TCP_PORT})")
    parser.add_argument("--name", type=str, default="Sender-A", help="Sender display name")
    parser.add_argument("--cert", type=str, default="certs/cert.pem", help="Path to TLS certificate (default: certs/cert.pem)")
    parser.add_argument("--key", type=str, default="certs/key.pem", help="Path to TLS private key (default: certs/key.pem)")
    parser.add_argument("--code", type=str, default=None, help="Shared swarm join code (prefer P2P_JOIN_CODE env var)")
    parser.add_argument("--piece-size", type=int, default=config.DEFAULT_PIECE_SIZE, help="Piece size in bytes")
    parser.add_argument(
        "--throttle-kbps",
        type=int,
        default=None,
        help="Throttle upload speed limit in KiB/s across all peer connections (per-sender aggregate limit; e.g. 500 for ~500 KiB/s)",
    )
    parser.add_argument("--bind", type=str, default="0.0.0.0", help="Address to bind to (default: 0.0.0.0)")
    parser.add_argument(
        "--tracker",
        type=str,
        default=None,
        help="Tracker address as HOST:PORT (default: auto-discover via UDP BEACON)",
    )
    parser.add_argument("--no-discovery", action="store_true", help="Disable automatic UDP discovery announcements")
    parser.add_argument(
        "--discovery-port",
        type=int,
        default=config.DISCOVERY_PORT,
        help=f"UDP discovery port (default: {config.DISCOVERY_PORT})",
    )

    args = parser.parse_args()

    join_code = get_join_code(args.code)

    server = SenderServer(
        source_path=Path(args.path),
        port=args.port,
        bind_host=args.bind,
        name=args.name,
        cert_path=Path(args.cert),
        key_path=Path(args.key),
        join_code=join_code,
        piece_size=args.piece_size,
        throttle_kbps=args.throttle_kbps,
        enable_discovery=not args.no_discovery,
        discovery_port=args.discovery_port,
        tracker=args.tracker,
    )

    try:
        server.start(blocking=True)
    except KeyboardInterrupt:
        print("\nShutting down sender gracefully...")
        server.stop()


if __name__ == "__main__":
    main()
