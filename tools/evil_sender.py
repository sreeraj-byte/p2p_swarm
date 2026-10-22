"""Evil Sender: Test-only fixture that deliberately corrupts pieces.

WARNING: This is a test fixture designed to verify that the receiver properly
detects SHA-256 hash mismatches, increments strikes, retries missing pieces,
and bans malicious peers after HASH_STRIKES_TO_BAN strikes.

Uses the same TLS certificate pinning and mutual join-code challenge-response as real senders.
"""

import argparse
from pathlib import Path
import secrets
import socket
import ssl
import sys
import threading
import time
from typing import Optional, Union

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from common.auth import (
    compute_server_proof,
    derive_auth_key,
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
from common.tlsutil import create_server_ssl_context
import config

EVIL_BANNER = """
*******************************************************************************
*                    TEST TOOL ONLY: EVIL SENDER                              *
*  WARNING: Deliberately corrupts pieces to test receiver hash verification,  *
*  strikes, retries, and banning logic. NEVER use for regular file sharing!    *
*******************************************************************************
"""


class EvilSenderServer:
    """Test-only sender that corrupts every Nth piece payload over TLS."""

    def __init__(
        self,
        source_path: Path,
        port: int = 6883,
        bind_host: str = "127.0.0.1",
        name: str = "Evil-Sender",
        cert_path: Union[str, Path] = "certs/cert.pem",
        key_path: Union[str, Path] = "certs/key.pem",
        join_code: Optional[str] = None,
        corrupt_every: int = 1,
        piece_size: int = config.DEFAULT_PIECE_SIZE,
        throttle_kbps: Optional[int] = None,
        device_id: Optional[str] = None,
    ) -> None:
        self.source_path = Path(source_path).resolve()
        self.port = port
        self.bind_host = bind_host
        self.name = name
        self.cert_path = Path(cert_path).resolve()
        self.key_path = Path(key_path).resolve()
        self.corrupt_every = corrupt_every
        self.piece_size = piece_size
        self.throttle_kbps = throttle_kbps
        self.device_id = device_id or secrets.token_hex(16)

        self.join_code = join_code or get_join_code()
        self.auth_key = derive_auth_key(self.join_code)

        self.metadata, self.canonical_bytes, self.swarm_id = build_metadata(
            self.source_path, piece_size=self.piece_size
        )
        self.swarm_id_short = compute_swarm_id_short(self.swarm_id)
        self.reader = PieceReader(self.source_path, self.metadata)

        self.ssl_context = create_server_ssl_context(self.cert_path, self.key_path)

        self._server_sock: Optional[socket.socket] = None
        self._is_running = False
        self._request_count = 0
        self._pieces_corrupted = 0
        self._lock = threading.Lock()

    def start(self, blocking: bool = True) -> None:
        """Start evil sender server socket."""
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.bind_host, self.port))
        self._server_sock.listen(5)
        self._is_running = True

        self.port = self._server_sock.getsockname()[1]
        print(EVIL_BANNER)
        print(f"Evil Sender [{self.name}] listening on {self.bind_host}:{self.port} | TLS on")
        print(f"Corrupting every {self.corrupt_every} request(s).\n")

        if blocking:
            self._serve_loop()
        else:
            t = threading.Thread(target=self._serve_loop, daemon=True)
            t.start()

    def stop(self) -> None:
        """Shut down evil sender server."""
        self._is_running = False
        if self._server_sock:
            try:
                self._server_sock.close()
            except OSError:
                pass
        self.reader.close()

    def _serve_loop(self) -> None:
        while self._is_running:
            try:
                client_sock, client_addr = self._server_sock.accept()
                client_sock.settimeout(config.HANDSHAKE_TIMEOUT)
                t = threading.Thread(
                    target=self._handle_client,
                    args=(client_sock, client_addr),
                    daemon=True,
                )
                t.start()
            except OSError:
                break

    def _handle_client(self, raw_sock: socket.socket, client_addr: tuple) -> None:
        client_ip, client_port = client_addr
        tls_sock: Optional[ssl.SSLSocket] = None
        try:
            try:
                tls_sock = self.ssl_context.wrap_socket(raw_sock, server_side=True)
            except (ssl.SSLError, OSError):
                return

            # 1. Challenge-response handshake
            nonce_bytes = secrets.token_bytes(32)
            send_message(tls_sock, make_challenge(self.device_id, self.name, nonce_bytes.hex()))

            hello_hdr, _ = recv_message(tls_sock, max_payload_len=0)
            if hello_hdr.get("type") != "HELLO":
                return

            client_device_id = hello_hdr.get("device_id", "")
            client_proof = hello_hdr.get("proof", "")
            if not verify_client_proof(self.auth_key, nonce_bytes, client_device_id, client_proof):
                send_message(tls_sock, make_error("AUTH_FAILED", "Authentication failed"))
                return

            server_proof = compute_server_proof(self.auth_key, nonce_bytes, client_device_id)
            send_message(tls_sock, make_welcome(proof=server_proof, swarm_id=self.swarm_id))

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
                        send_message(tls_sock, make_error("BAD_INDEX", "Invalid piece index"))
                        continue

                    piece_bytes = self.reader.read_piece(idx)

                    with self._lock:
                        self._request_count += 1
                        should_corrupt = (self._request_count % self.corrupt_every == 0)

                    if should_corrupt:
                        # Corrupt payload by bit-flipping
                        corrupted = bytearray(piece_bytes)
                        if len(corrupted) > 0:
                            corrupted[0] ^= 0xFF
                        piece_bytes = bytes(corrupted)
                        with self._lock:
                            self._pieces_corrupted += 1
                        print(f"Evil Sender: CORRUPTING piece {idx} sent to {client_ip}:{client_port}!")
                    else:
                        print(f"Evil Sender: Serving genuine piece {idx} to {client_ip}:{client_port}")

                    if self.throttle_kbps and self.throttle_kbps > 0:
                        time.sleep(len(piece_bytes) / (self.throttle_kbps * 1024))

                    piece_hdr = make_piece_header(index=idx, length=len(piece_bytes))
                    send_message(tls_sock, piece_hdr, payload=piece_bytes)

                elif msg_type == "BYE":
                    break
        finally:
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


def main() -> None:
    parser = argparse.ArgumentParser(description="Evil Sender (Test-only fixture)")
    parser.add_argument("--path", type=str, required=True, help="Path to shared test data")
    parser.add_argument("--port", type=int, default=6883, help="Port to listen on (default: 6883)")
    parser.add_argument("--cert", type=str, default="certs/cert.pem", help="Path to TLS certificate")
    parser.add_argument("--key", type=str, default="certs/key.pem", help="Path to TLS private key")
    parser.add_argument("--code", type=str, default=None, help="Shared swarm join code")
    parser.add_argument("--corrupt-every", type=int, default=1, help="Corrupt every Nth piece (default: 1)")
    parser.add_argument("--name", type=str, default="Evil-Sender", help="Evil sender name")
    parser.add_argument("--bind", type=str, default="127.0.0.1", help="Address to bind (default: 127.0.0.1)")
    parser.add_argument(
        "--throttle-kbps",
        type=int,
        default=None,
        help="Throttle upload speed limit in KiB/s (kilobytes per second, 1024 bytes/s; e.g. 500 for ~500 KB/s)",
    )

    args = parser.parse_args()

    join_code = get_join_code(args.code)

    server = EvilSenderServer(
        source_path=Path(args.path),
        port=args.port,
        bind_host=args.bind,
        name=args.name,
        cert_path=Path(args.cert),
        key_path=Path(args.key),
        join_code=join_code,
        corrupt_every=args.corrupt_every,
        throttle_kbps=args.throttle_kbps,
    )
    try:
        server.start(blocking=True)
    except KeyboardInterrupt:
        print("\nStopping evil sender...")
        server.stop()


if __name__ == "__main__":
    main()
