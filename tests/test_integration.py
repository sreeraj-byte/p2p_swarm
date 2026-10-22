"""End-to-end localhost integration tests for P2P Swarm Phase 4 (TLS + Mutual Join Code Auth).

Integration Tests Covered:
1. Integration Test 1 (Section 18):
   2 senders + receiver with sample folder over TLS: output tree byte-identical, both senders contributed pieces.
2. Integration Test 3 (Section 18):
   Kill one sender mid-transfer: remaining sender completes the transfer byte-identically over TLS.
3. Integration Test 4 (Section 18):
   Evil sender + good sender: evil sender strikes recorded and banned after HASH_STRIKES_TO_BAN,
   good sender completes the transfer byte-identically over TLS.
4. Swarm Mismatch Test (Section 7.3 step 7):
   Two senders with different data: second sender rejected with SWARM_MISMATCH over TLS.
5. Dynamic Sender Join (Section 9.2):
   New sender added mid-transfer is successfully authenticated and incorporated into the work queue pool.
6. Frozen Sender Request Timeout (Section 14):
   Sender accepts REQUEST and never replies; receiver per-request timeout triggers, chunk returns to queue,
   sender marked failed, and other sender completes transfer.
7. All Senders Failed:
   When all senders go offline, receiver fails with a clear error and non-zero exit code.
8. MAX_PIECE_ATTEMPTS Exceeded:
   When piece retries exceed cap (6), transfer aborts with clear error.
9. Clean Ctrl+C Shutdown:
   Receiver leaves .part files intact and exits cleanly.
10. Integration Test 5 (Section 18):
    Wrong join code rejected; correct code accepted.
11. Integration Test 6 (Section 18):
    Cert mismatch: receiver pins a different certificate than the sender presents; connection is refused by TLS.
12. Per-IP Rate Limiting Block:
    IP exceeding AUTH_MAX_FAILURES is blocked; limiter is resettable between tests.
"""

import hashlib
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys
import threading
import time
from typing import Tuple
import pytest

from common.auth import (
    AuthError,
    compute_client_proof,
    compute_server_proof,
    default_rate_limiter,
    derive_auth_key,
    verify_client_proof,
)
from common.metadata import build_metadata
from common.protocol import (
    ConnectionClosedError,
    ProtocolError,
    make_bye,
    make_challenge,
    make_hello,
    make_metadata_header,
    make_request,
    make_welcome,
    recv_message,
    send_message,
)
from common.tlsutil import create_client_ssl_context, create_server_ssl_context
from receiver import SwarmReceiver, download_from_senders
from sender import SenderServer
from tools.evil_sender import EvilSenderServer
from tools.gen_certs import generate_self_signed_cert
from tools.make_test_data import create_test_dataset
import config

TEST_JOIN_CODE = "p2p-swarm-viva-test-passkey-2026"


@pytest.fixture(autouse=True)
def reset_rate_limiter() -> None:
    """Ensure the singleton rate limiter is cleanly reset before and after every test."""
    default_rate_limiter.reset()
    yield
    default_rate_limiter.reset()


def _hash_file(file_path: Path) -> str:
    """Compute SHA-256 hex digest of a file on disk."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as fp:
        while chunk := fp.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def _compare_directories(src_dir: Path, dst_dir: Path) -> None:
    """Recursively verify all files in dst_dir match src_dir byte-for-byte."""
    src_files = sorted([p.relative_to(src_dir).as_posix() for p in src_dir.glob("**/*") if p.is_file()])
    dst_files = sorted([p.relative_to(dst_dir).as_posix() for p in dst_dir.glob("**/*") if p.is_file()])

    assert src_files == dst_files, f"File tree mismatch:\nSource: {src_files}\nDest: {dst_files}"

    for rel in src_files:
        src_sha = _hash_file(src_dir / rel)
        dst_sha = _hash_file(dst_dir / rel)
        assert src_sha == dst_sha, f"Hash mismatch on '{rel}': {src_sha} != {dst_sha}"


def _make_certs(tmp_path: Path, subname: str = "certs") -> Tuple[Path, Path]:
    """Helper to generate fresh certificates in a temporary folder."""
    return generate_self_signed_cert(tmp_path / subname)


def test_integration_1_two_senders_parallel_download(tmp_path: Path) -> None:
    """Integration Test 1: 2 senders + receiver downloading sample folder in parallel over TLS.

    Verifies:
    - Output tree is byte-identical (SHA-256 of every file).
    - Both senders contributed pieces (A/B piece split).
    """
    cert_path, key_path = _make_certs(tmp_path)
    sample_dir = tmp_path / "sample_folder"
    create_test_dataset(sample_dir, piece_size=config.MIN_PIECE_SIZE)

    # Start Sender A and Sender B on dynamic ports
    sender_a = SenderServer(
        source_path=sample_dir,
        port=0,
        bind_host="127.0.0.1",
        name="Sender-A",
        cert_path=cert_path,
        key_path=key_path,
        join_code=TEST_JOIN_CODE,
        piece_size=config.MIN_PIECE_SIZE,
    )
    sender_b = SenderServer(
        source_path=sample_dir,
        port=0,
        bind_host="127.0.0.1",
        name="Sender-B",
        cert_path=cert_path,
        key_path=key_path,
        join_code=TEST_JOIN_CODE,
        piece_size=config.MIN_PIECE_SIZE,
    )
    sender_a.start(blocking=False)
    sender_b.start(blocking=False)
    time.sleep(0.1)

    dest_dir = tmp_path / "dest_integration_1"
    dest_dir.mkdir()

    try:
        sender_addrs = [f"127.0.0.1:{sender_a.port}", f"127.0.0.1:{sender_b.port}"]
        res = download_from_senders(
            senders=sender_addrs,
            out_dir=dest_dir,
            cert_path=cert_path,
            join_code=TEST_JOIN_CODE,
            verbose=False,
        )

        assert res["completed"] is True
        assert res["bad_pieces"] == 0

        # Verify A/B piece split: BOTH senders must have contributed pieces
        stats = res["sender_stats"]
        pieces_a = stats[f"127.0.0.1:{sender_a.port}"]["pieces"]
        pieces_b = stats[f"127.0.0.1:{sender_b.port}"]["pieces"]

        print(f"\nA/B Split: Sender A = {pieces_a} pieces, Sender B = {pieces_b} pieces (Total: {res['pieces_done']})")
        assert pieces_a > 0, "Sender A did not contribute any pieces!"
        assert pieces_b > 0, "Sender B did not contribute any pieces!"
        assert pieces_a + pieces_b == res["pieces_done"]

        # Verify complete output tree matches sample_dir
        _compare_directories(sample_dir, dest_dir / sample_dir.name)

    finally:
        sender_a.stop()
        sender_b.stop()


def test_integration_3_kill_sender_mid_transfer(tmp_path: Path) -> None:
    """Integration Test 3: Kill one sender mid-transfer; transfer still completes over TLS."""
    cert_path, key_path = _make_certs(tmp_path)
    sample_dir = tmp_path / "sample_folder_kill"
    sample_dir.mkdir()
    # Create ~240 KiB payload (~15 pieces of 16 KiB)
    (sample_dir / "file1.bin").write_bytes(b"A" * 120_000)
    (sample_dir / "file2.bin").write_bytes(b"B" * 120_000)

    # Throttle so pieces take time to transfer
    sender_a = SenderServer(
        source_path=sample_dir,
        port=0,
        bind_host="127.0.0.1",
        name="Sender-A",
        cert_path=cert_path,
        key_path=key_path,
        join_code=TEST_JOIN_CODE,
        piece_size=config.MIN_PIECE_SIZE,
        throttle_kbps=300,
    )
    sender_b = SenderServer(
        source_path=sample_dir,
        port=0,
        bind_host="127.0.0.1",
        name="Sender-B",
        cert_path=cert_path,
        key_path=key_path,
        join_code=TEST_JOIN_CODE,
        piece_size=config.MIN_PIECE_SIZE,
        throttle_kbps=300,
    )
    sender_a.start(blocking=False)
    sender_b.start(blocking=False)
    time.sleep(0.1)

    dest_dir = tmp_path / "dest_integration_3"
    dest_dir.mkdir()

    download_result = {}
    download_error = []

    def run_receiver():
        try:
            rx = SwarmReceiver(
                senders=[f"127.0.0.1:{sender_a.port}", f"127.0.0.1:{sender_b.port}"],
                out_dir=dest_dir,
                cert_path=cert_path,
                join_code=TEST_JOIN_CODE,
                verbose=False,
                backoff_base=0.05,
            )
            download_result.update(rx.download())
        except Exception as err:
            download_error.append(err)

    rx_thread = threading.Thread(target=run_receiver)
    rx_thread.start()

    time.sleep(0.15)
    print("\nKilling Sender A mid-transfer...")
    sender_a.stop()

    rx_thread.join(timeout=10.0)

    try:
        assert not download_error, f"Receiver failed after sender was killed: {download_error}"
        assert download_result.get("completed") is True

        _compare_directories(sample_dir, dest_dir / sample_dir.name)
        print("Integration Test 3 passed: Remaining sender finished all missing pieces.")

    finally:
        sender_a.stop()
        sender_b.stop()


def test_integration_4_evil_sender_strikes_and_banning(tmp_path: Path) -> None:
    """Integration Test 4: Evil sender + good sender over TLS."""
    cert_path, key_path = _make_certs(tmp_path)
    sample_dir = tmp_path / "sample_folder_evil"
    create_test_dataset(sample_dir, piece_size=config.MIN_PIECE_SIZE)

    good_sender = SenderServer(
        source_path=sample_dir,
        port=0,
        bind_host="127.0.0.1",
        name="Good-Sender",
        cert_path=cert_path,
        key_path=key_path,
        join_code=TEST_JOIN_CODE,
        piece_size=config.MIN_PIECE_SIZE,
    )
    evil_sender = EvilSenderServer(
        source_path=sample_dir,
        port=0,
        bind_host="127.0.0.1",
        name="Evil-Sender",
        cert_path=cert_path,
        key_path=key_path,
        join_code=TEST_JOIN_CODE,
        corrupt_every=1,
        piece_size=config.MIN_PIECE_SIZE,
    )
    good_sender.start(blocking=False)
    evil_sender.start(blocking=False)
    time.sleep(0.1)

    dest_dir = tmp_path / "dest_integration_4"
    dest_dir.mkdir()

    try:
        res = download_from_senders(
            senders=[f"127.0.0.1:{evil_sender.port}", f"127.0.0.1:{good_sender.port}"],
            out_dir=dest_dir,
            cert_path=cert_path,
            join_code=TEST_JOIN_CODE,
            verbose=False,
            backoff_base=0.1,
        )

        assert res["completed"] is True
        evil_label = f"127.0.0.1:{evil_sender.port}"
        assert evil_label in res["banned_senders"], f"Evil sender {evil_label} was not banned!"
        assert res["bad_pieces"] >= config.HASH_STRIKES_TO_BAN

        good_label = f"127.0.0.1:{good_sender.port}"
        assert res["sender_stats"][good_label]["pieces"] > 0

        _compare_directories(sample_dir, dest_dir / sample_dir.name)
    finally:
        good_sender.stop()
        evil_sender.stop()


def test_integration_swarm_mismatch_rejection(tmp_path: Path) -> None:
    """Test SWARM_MISMATCH: A sender offering different data is rejected over TLS."""
    cert_path, key_path = _make_certs(tmp_path)
    dir_a = tmp_path / "data_a"
    dir_a.mkdir()
    (dir_a / "file1.txt").write_bytes(b"DatasetA" * 1000)

    dir_b = tmp_path / "data_b"
    dir_b.mkdir()
    (dir_b / "file1.txt").write_bytes(b"DifferentDatasetB" * 1000)

    sender_a = SenderServer(
        source_path=dir_a,
        port=0,
        bind_host="127.0.0.1",
        name="Sender-A",
        cert_path=cert_path,
        key_path=key_path,
        join_code=TEST_JOIN_CODE,
        piece_size=config.MIN_PIECE_SIZE,
    )
    sender_b = SenderServer(
        source_path=dir_b,
        port=0,
        bind_host="127.0.0.1",
        name="Sender-B",
        cert_path=cert_path,
        key_path=key_path,
        join_code=TEST_JOIN_CODE,
        piece_size=config.MIN_PIECE_SIZE,
    )
    sender_a.start(blocking=False)
    sender_b.start(blocking=False)
    time.sleep(0.1)

    dest_dir = tmp_path / "dest_mismatch"
    dest_dir.mkdir()

    try:
        res = download_from_senders(
            senders=[f"127.0.0.1:{sender_a.port}", f"127.0.0.1:{sender_b.port}"],
            out_dir=dest_dir,
            cert_path=cert_path,
            join_code=TEST_JOIN_CODE,
            verbose=False,
        )

        assert res["completed"] is True
        b_label = f"127.0.0.1:{sender_b.port}"
        assert res["sender_stats"][b_label]["pieces"] == 0

        _compare_directories(dir_a, dest_dir / dir_a.name)
    finally:
        sender_a.stop()
        sender_b.stop()


def test_integration_dynamic_sender_join(tmp_path: Path) -> None:
    """Section 9.2: Dynamically add a new sender mid-transfer over TLS."""
    cert_path, key_path = _make_certs(tmp_path)
    sample_dir = tmp_path / "sample_folder_dyn"
    create_test_dataset(sample_dir, piece_size=config.MIN_PIECE_SIZE)

    sender_a = SenderServer(
        source_path=sample_dir,
        port=0,
        bind_host="127.0.0.1",
        name="Sender-A",
        cert_path=cert_path,
        key_path=key_path,
        join_code=TEST_JOIN_CODE,
        piece_size=config.MIN_PIECE_SIZE,
        throttle_kbps=400,
    )
    sender_b = SenderServer(
        source_path=sample_dir,
        port=0,
        bind_host="127.0.0.1",
        name="Sender-B",
        cert_path=cert_path,
        key_path=key_path,
        join_code=TEST_JOIN_CODE,
        piece_size=config.MIN_PIECE_SIZE,
        throttle_kbps=400,
    )
    sender_a.start(blocking=False)
    sender_b.start(blocking=False)
    time.sleep(0.1)

    dest_dir = tmp_path / "dest_dynamic"
    dest_dir.mkdir()

    rx = SwarmReceiver(
        senders=[f"127.0.0.1:{sender_a.port}"],
        out_dir=dest_dir,
        cert_path=cert_path,
        join_code=TEST_JOIN_CODE,
        verbose=False,
        backoff_base=0.1,
    )

    download_result = {}

    def run_rx():
        download_result.update(rx.download())

    t = threading.Thread(target=run_rx)
    t.start()

    time.sleep(0.15)
    joined = rx.add_sender(f"127.0.0.1:{sender_b.port}")
    assert joined is True

    t.join(timeout=10.0)

    try:
        assert download_result.get("completed") is True
        stats = download_result["sender_stats"]
        assert stats[f"127.0.0.1:{sender_a.port}"]["pieces"] > 0
        assert stats[f"127.0.0.1:{sender_b.port}"]["pieces"] > 0

        _compare_directories(sample_dir, dest_dir / sample_dir.name)
    finally:
        sender_a.stop()
        sender_b.stop()


class FrozenSenderServer:
    """Sender fixture that responds to metadata handshake normally over TLS, but freezes on REQUEST."""

    def __init__(
        self,
        source_path: Path,
        cert_path: Path,
        key_path: Path,
        join_code: str = TEST_JOIN_CODE,
        port: int = 0,
        bind_host: str = "127.0.0.1",
        piece_size: int = config.MIN_PIECE_SIZE,
    ):
        self.source_path = source_path
        self.port = port
        self.bind_host = bind_host
        self.cert_path = cert_path
        self.key_path = key_path
        self.join_code = join_code
        self.auth_key = derive_auth_key(join_code)
        self.metadata, self.canonical_bytes, self.swarm_id = build_metadata(source_path, piece_size=piece_size)
        self.ssl_context = create_server_ssl_context(cert_path, key_path)
        self._server_sock = None
        self._is_running = False

    def start(self):
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.bind_host, self.port))
        self._server_sock.listen(5)
        self.port = self._server_sock.getsockname()[1]
        self._is_running = True
        t = threading.Thread(target=self._serve, daemon=True)
        t.start()

    def stop(self):
        self._is_running = False
        if self._server_sock:
            try:
                self._server_sock.close()
            except OSError:
                pass

    def _serve(self):
        while self._is_running:
            try:
                raw_sock, _ = self._server_sock.accept()
                t = threading.Thread(target=self._handle_client, args=(raw_sock,), daemon=True)
                t.start()
            except OSError:
                break

    def _handle_client(self, raw_sock: socket.socket):
        tls_sock = None
        try:
            tls_sock = self.ssl_context.wrap_socket(raw_sock, server_side=True)

            nonce_bytes = secrets.token_bytes(32)
            send_message(tls_sock, make_challenge("frozen-id", "Frozen-Sender", nonce_bytes.hex()))

            hello_hdr, _ = recv_message(tls_sock, max_payload_len=0)
            if hello_hdr.get("type") != "HELLO":
                return

            client_device_id = hello_hdr.get("device_id", "")
            client_proof = hello_hdr.get("proof", "")
            if not verify_client_proof(self.auth_key, nonce_bytes, client_device_id, client_proof):
                return

            server_proof = compute_server_proof(self.auth_key, nonce_bytes, client_device_id)
            send_message(tls_sock, make_welcome(proof=server_proof, swarm_id=self.swarm_id))

            while self._is_running:
                try:
                    hdr, _ = recv_message(tls_sock)
                except (ConnectionClosedError, ProtocolError, OSError):
                    break
                if hdr.get("type") == "GET_METADATA":
                    send_message(tls_sock, make_metadata_header(self.swarm_id), payload=self.canonical_bytes)
                elif hdr.get("type") == "REQUEST":
                    while self._is_running:
                        time.sleep(0.1)
        finally:
            if tls_sock:
                try:
                    tls_sock.close()
                except OSError:
                    pass


def test_integration_frozen_sender_request_timeout(tmp_path: Path) -> None:
    """Verify that a frozen sender triggers per-request timeout over TLS."""
    cert_path, key_path = _make_certs(tmp_path)
    sample_dir = tmp_path / "sample_folder_frozen"
    sample_dir.mkdir()
    (sample_dir / "file1.bin").write_bytes(b"FrozenPayload1" * 3000)
    (sample_dir / "file2.bin").write_bytes(b"FrozenPayload2" * 3000)

    good_sender = SenderServer(
        source_path=sample_dir,
        port=0,
        bind_host="127.0.0.1",
        name="Good-Sender",
        cert_path=cert_path,
        key_path=key_path,
        join_code=TEST_JOIN_CODE,
        piece_size=config.MIN_PIECE_SIZE,
    )
    frozen_sender = FrozenSenderServer(
        source_path=sample_dir,
        cert_path=cert_path,
        key_path=key_path,
        join_code=TEST_JOIN_CODE,
        port=0,
        bind_host="127.0.0.1",
        piece_size=config.MIN_PIECE_SIZE,
    )
    good_sender.start(blocking=False)
    frozen_sender.start()
    time.sleep(0.1)

    dest_dir = tmp_path / "dest_frozen"
    dest_dir.mkdir()

    try:
        frozen_label = f"127.0.0.1:{frozen_sender.port}"
        good_label = f"127.0.0.1:{good_sender.port}"

        res = download_from_senders(
            senders=[frozen_label, good_label],
            out_dir=dest_dir,
            cert_path=cert_path,
            join_code=TEST_JOIN_CODE,
            verbose=False,
            request_timeout=0.4,
            backoff_base=0.05,
        )

        assert res["completed"] is True
        assert frozen_label in res["failed_senders"]
        assert res["sender_stats"][good_label]["pieces"] > 0
        assert res["bad_pieces"] == 0

        _compare_directories(sample_dir, dest_dir / sample_dir.name)
    finally:
        good_sender.stop()
        frozen_sender.stop()


def test_integration_all_senders_failed(tmp_path: Path) -> None:
    """Verify that when all senders fail over TLS, receiver terminates with clear error."""
    cert_path, key_path = _make_certs(tmp_path)
    sample_dir = tmp_path / "sample_folder_all_fail"
    sample_dir.mkdir()
    (sample_dir / "file.bin").write_bytes(b"FailData" * 5000)

    sender = SenderServer(
        source_path=sample_dir,
        port=0,
        bind_host="127.0.0.1",
        cert_path=cert_path,
        key_path=key_path,
        join_code=TEST_JOIN_CODE,
        piece_size=config.MIN_PIECE_SIZE,
        throttle_kbps=100,
    )
    sender.start(blocking=False)
    time.sleep(0.1)

    dest_dir = tmp_path / "dest_all_fail"
    dest_dir.mkdir()

    rx = SwarmReceiver(
        senders=[f"127.0.0.1:{sender.port}"],
        out_dir=dest_dir,
        cert_path=cert_path,
        join_code=TEST_JOIN_CODE,
        verbose=False,
        backoff_base=0.05,
        request_timeout=0.3,
    )

    def kill_sender_shortly():
        time.sleep(0.15)
        sender.stop()

    threading.Thread(target=kill_sender_shortly, daemon=True).start()

    with pytest.raises(ConnectionError, match="All senders went offline or were banned"):
        rx.download()

    # CLI test with non-existent port
    proc = subprocess.run([
        sys.executable, "receiver.py",
        "--out", str(dest_dir),
        "--cert", str(cert_path),
        "--code", TEST_JOIN_CODE,
        "--senders", "127.0.0.1:1",
        "--overwrite",
    ], capture_output=True, text=True)

    assert proc.returncode != 0
    assert "Download failed" in proc.stderr or "Download failed" in proc.stdout


def test_integration_max_piece_attempts_exceeded(tmp_path: Path) -> None:
    """Verify that exceeding MAX_PIECE_ATTEMPTS aborts the download over TLS."""
    cert_path, key_path = _make_certs(tmp_path)
    sample_dir = tmp_path / "sample_folder_max_attempts"
    sample_dir.mkdir()
    (sample_dir / "file.bin").write_bytes(b"MaxAttemptsExceeded" * 2000)

    evil_1 = EvilSenderServer(
        source_path=sample_dir,
        port=0,
        bind_host="127.0.0.1",
        cert_path=cert_path,
        key_path=key_path,
        join_code=TEST_JOIN_CODE,
        corrupt_every=1,
        piece_size=config.MIN_PIECE_SIZE,
    )
    evil_2 = EvilSenderServer(
        source_path=sample_dir,
        port=0,
        bind_host="127.0.0.1",
        cert_path=cert_path,
        key_path=key_path,
        join_code=TEST_JOIN_CODE,
        corrupt_every=1,
        piece_size=config.MIN_PIECE_SIZE,
    )
    evil_1.start(blocking=False)
    evil_2.start(blocking=False)
    time.sleep(0.1)

    dest_dir = tmp_path / "dest_max_attempts"
    dest_dir.mkdir()

    try:
        rx = SwarmReceiver(
            senders=[f"127.0.0.1:{evil_1.port}", f"127.0.0.1:{evil_2.port}"],
            out_dir=dest_dir,
            cert_path=cert_path,
            join_code=TEST_JOIN_CODE,
            verbose=False,
            backoff_base=0.05,
            request_timeout=0.5,
        )

        with pytest.raises((RuntimeError, ConnectionError)) as exc_info:
            rx.download()

        err_msg = str(exc_info.value)
        assert "MAX_PIECE_ATTEMPTS" in err_msg or "All senders went offline or were banned" in err_msg
    finally:
        evil_1.stop()
        evil_2.stop()


def test_integration_clean_ctrl_c_leaves_part_files(tmp_path: Path) -> None:
    """Verify that stopping receiver (simulating Ctrl+C) leaves .part files over TLS."""
    cert_path, key_path = _make_certs(tmp_path)
    sample_dir = tmp_path / "sample_folder_ctrlc"
    sample_dir.mkdir()
    (sample_dir / "large_file.bin").write_bytes(b"C" * (20 * config.MIN_PIECE_SIZE))

    sender = SenderServer(
        source_path=sample_dir,
        port=0,
        bind_host="127.0.0.1",
        cert_path=cert_path,
        key_path=key_path,
        join_code=TEST_JOIN_CODE,
        piece_size=config.MIN_PIECE_SIZE,
        throttle_kbps=100,
    )
    sender.start(blocking=False)
    time.sleep(0.1)

    dest_dir = tmp_path / "dest_ctrlc"
    dest_dir.mkdir()

    proc = subprocess.Popen([
        sys.executable, "receiver.py",
        "--out", str(dest_dir),
        "--cert", str(cert_path),
        "--code", TEST_JOIN_CODE,
        "--senders", f"127.0.0.1:{sender.port}",
        "--overwrite",
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    try:
        part_file = dest_dir / sample_dir.name / "large_file.bin.part"
        for _ in range(60):
            if part_file.exists() and part_file.stat().st_size > 0:
                break
            time.sleep(0.05)

        assert part_file.exists(), "part file was not created yet"

        proc.send_signal(signal.SIGINT)
        proc.communicate(timeout=5.0)

        assert proc.returncode in (130, -signal.SIGINT, 1)
        assert part_file.exists(), ".part file should remain on disk after Ctrl+C"
        final_file = dest_dir / sample_dir.name / "large_file.bin"
        assert not final_file.exists(), "final file should not exist since transfer was interrupted"
    finally:
        sender.stop()
        if proc.poll() is None:
            proc.kill()


def test_integration_5_wrong_join_code_rejected(tmp_path: Path) -> None:
    """Integration Test 5 (Section 18): Wrong join code rejected; correct code accepted."""
    cert_path, key_path = _make_certs(tmp_path)
    sample_dir = tmp_path / "sample_folder_auth"
    sample_dir.mkdir()
    (sample_dir / "notes.txt").write_bytes(b"SecretContentForAuthorizedPeersOnly" * 500)

    correct_code = "viva-2026-correct-password"
    wrong_code = "viva-2026-WRONG-password"

    sender = SenderServer(
        source_path=sample_dir,
        port=0,
        bind_host="127.0.0.1",
        name="Sender-Secure",
        cert_path=cert_path,
        key_path=key_path,
        join_code=correct_code,
        piece_size=config.MIN_PIECE_SIZE,
    )
    sender.start(blocking=False)
    time.sleep(0.1)

    dest_dir = tmp_path / "dest_auth"
    dest_dir.mkdir()

    try:
        sender_addr = f"127.0.0.1:{sender.port}"

        # 1. Receiver connects with WRONG code: MUST be rejected
        with pytest.raises(ConnectionError):
            download_from_senders(
                senders=[sender_addr],
                out_dir=dest_dir,
                cert_path=cert_path,
                join_code=wrong_code,
                verbose=False,
                backoff_base=0.05,
            )

        # 2. Reset rate limiter to clear the failure for localhost
        default_rate_limiter.reset()

        # 3. Receiver connects with CORRECT code: MUST be accepted
        res = download_from_senders(
            senders=[sender_addr],
            out_dir=dest_dir,
            cert_path=cert_path,
            join_code=correct_code,
            verbose=False,
            backoff_base=0.05,
        )

        assert res["completed"] is True
        _compare_directories(sample_dir, dest_dir / sample_dir.name)
        print("Integration Test 5 passed: Wrong join code rejected; correct code accepted.")

    finally:
        sender.stop()


def test_integration_6_cert_mismatch_connection_refused(tmp_path: Path) -> None:
    """Integration Test 6 (Section 18): Cert mismatch -> TLS connection refused."""
    cert_path_a, key_path_a = _make_certs(tmp_path, "certs_a")
    cert_path_b, _ = _make_certs(tmp_path, "certs_b")  # Completely different certificate

    sample_dir = tmp_path / "sample_folder_cert_mismatch"
    sample_dir.mkdir()
    (sample_dir / "data.bin").write_bytes(b"CertMismatchTestData" * 100)

    # Sender presents cert A
    sender = SenderServer(
        source_path=sample_dir,
        port=0,
        bind_host="127.0.0.1",
        cert_path=cert_path_a,
        key_path=key_path_a,
        join_code=TEST_JOIN_CODE,
        piece_size=config.MIN_PIECE_SIZE,
    )
    sender.start(blocking=False)
    time.sleep(0.1)

    dest_dir = tmp_path / "dest_cert_mismatch"
    dest_dir.mkdir()

    try:
        # Receiver pins cert B -> TLS certificate verification fails
        with pytest.raises(ConnectionError, match="TLS"):
            download_from_senders(
                senders=[f"127.0.0.1:{sender.port}"],
                out_dir=dest_dir,
                cert_path=cert_path_b,  # Mismatched pinned certificate
                join_code=TEST_JOIN_CODE,
                verbose=False,
                backoff_base=0.05,
            )

        print("Integration Test 6 passed: Mismatched certificate strictly rejected by TLS.")

    finally:
        sender.stop()


def test_integration_rate_limit_block_and_reset(tmp_path: Path) -> None:
    """Verify rate-limiting blocks repeated bad authentications and reset() clears it."""
    cert_path, key_path = _make_certs(tmp_path)
    sample_dir = tmp_path / "sample_folder_ratelimit"
    sample_dir.mkdir()
    (sample_dir / "file.bin").write_bytes(b"RateLimitData" * 100)

    correct_code = "auth-correct-code"
    wrong_code = "auth-wrong-code"

    sender = SenderServer(
        source_path=sample_dir,
        port=0,
        bind_host="127.0.0.1",
        cert_path=cert_path,
        key_path=key_path,
        join_code=correct_code,
        piece_size=config.MIN_PIECE_SIZE,
    )
    sender.start(blocking=False)
    time.sleep(0.1)

    dest_dir = tmp_path / "dest_ratelimit"
    dest_dir.mkdir()

    try:
        sender_addr = f"127.0.0.1:{sender.port}"

        # Trigger AUTH_MAX_FAILURES (5) auth failures from 127.0.0.1
        for i in range(config.AUTH_MAX_FAILURES):
            try:
                download_from_senders(
                    senders=[sender_addr],
                    out_dir=dest_dir,
                    cert_path=cert_path,
                    join_code=wrong_code,
                    verbose=False,
                    backoff_base=0.01,
                )
            except Exception:
                pass

        # Verify IP 127.0.0.1 is now blocked by the rate limiter
        blocked, remaining = default_rate_limiter.is_blocked("127.0.0.1")
        assert blocked is True
        assert remaining > 0

        # Even with the CORRECT code, the blocked IP is rejected
        with pytest.raises(ConnectionError):
            download_from_senders(
                senders=[sender_addr],
                out_dir=dest_dir,
                cert_path=cert_path,
                join_code=correct_code,
                verbose=False,
                backoff_base=0.01,
            )

        # Reset limiter state (Section 14.2)
        default_rate_limiter.reset()
        blocked_after, _ = default_rate_limiter.is_blocked("127.0.0.1")
        assert blocked_after is False

        # Now correct code connects and downloads successfully!
        res = download_from_senders(
            senders=[sender_addr],
            out_dir=dest_dir,
            cert_path=cert_path,
            join_code=correct_code,
            verbose=False,
            backoff_base=0.05,
        )
        assert res["completed"] is True
        print("Rate limit test passed: IP blocked after max failures and successfully unblocked by reset().")

    finally:
        sender.stop()


def test_per_sender_throttle_enforced_across_concurrent_connections(tmp_path: Path) -> None:
    """Verify that --throttle-kbps is enforced across all concurrent peer connections to a sender."""
    cert_path, key_path = _make_certs(tmp_path)
    piece_size = 16384
    # 4 pieces of 16 KiB = 64 KiB
    data_content = secrets.token_bytes(4 * piece_size)
    data_file = tmp_path / "throttled_data.bin"
    data_file.write_bytes(data_content)

    # Throttle to 64 KiB/s: 64 KiB takes 1.0 second minimum
    throttle_kbps = 64
    join_code = "throttle-test-2026"

    sender = SenderServer(
        source_path=data_file,
        port=0,
        name="ThrottledSender",
        cert_path=cert_path,
        key_path=key_path,
        join_code=join_code,
        piece_size=piece_size,
        throttle_kbps=throttle_kbps,
        enable_discovery=False,
    )
    sender.start(blocking=False)
    time.sleep(0.1)

    try:
        # Open two client connections concurrently requesting 2 pieces each
        ssl_ctx = create_client_ssl_context(cert_path)
        auth_key = derive_auth_key(join_code)

        def client_worker(pieces: list, results: list):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("127.0.0.1", sender.port))
            tls_s = ssl_ctx.wrap_socket(s)
            ch_hdr, _ = recv_message(tls_s, max_payload_len=0)
            nonce = bytes.fromhex(ch_hdr["nonce"])
            client_id = secrets.token_hex(8)
            proof = compute_client_proof(auth_key, nonce, client_id)
            send_message(tls_s, make_hello(client_id, "Worker", "receiver", proof))
            w_hdr, _ = recv_message(tls_s, max_payload_len=0)
            assert w_hdr["type"] == "WELCOME"

            t0 = time.time()
            for p in pieces:
                send_message(tls_s, make_request(p))
                hdr, payload = recv_message(tls_s)
                assert hdr["type"] == "PIECE"
            results.append(time.time() - t0)
            send_message(tls_s, make_bye())
            tls_s.close()

        durations: list = []
        t_overall_start = time.time()
        t1 = threading.Thread(target=client_worker, args=([0, 1], durations))
        t2 = threading.Thread(target=client_worker, args=([2, 3], durations))
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        overall_duration = time.time() - t_overall_start

        # 64 KiB transferred across 4 pieces at 64 KiB/s (each piece = 0.25s delay):
        # If throttle were per-connection, 2 connections with 2 pieces each would complete in ~0.25s.
        # With per-sender aggregate throttle, sends are spaced across both connections (3 * 0.25s = 0.75s),
        # so overall duration is >= 0.70s.
        assert overall_duration >= 0.70, f"Expected aggregate throttle >= 0.70s, got {overall_duration:.2f}s"
    finally:
        sender.stop()

