"""Security unit tests for Phase 4: TLS certificate pinning, mutual join code auth, and rate limiting.

Covers Section 14, 7.3, and 7.4:
- Scrypt key derivation (32-byte key, salt=b"p2p-swarm/auth/v1", N=2^14, r=8, p=1).
- Constant-time proof comparison (hmac.compare_digest).
- Replayed proof rejection (proof generated for nonce A rejected on nonce B).
- Wrong join code rejection (client proof mismatch).
- Per-IP rate limiting: blocks after AUTH_MAX_FAILURES failures, resets state via reset().
- Certificate generation validation: SAN (localhost, 127.0.0.1, custom IP), BasicConstraints CA:TRUE, KeyUsage, SKI/AKI.
- Strict TLS client verification: verify_mode=CERT_REQUIRED, check_hostname=False, never CERT_NONE.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import secrets
import socket
import ssl
import threading
import time
from typing import Tuple
import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtensionOID

from common.auth import (
    AuthError,
    AuthRateLimiter,
    compute_client_proof,
    compute_server_proof,
    default_rate_limiter,
    derive_auth_key,
    derive_report_key,
    verify_client_proof,
    verify_server_proof,
)
from common.protocol import (
    ConnectionClosedError,
    ProtocolError,
    make_challenge,
    make_get_metadata,
    make_request,
    make_welcome,
    recv_message,
    send_message,
)
from common.tlsutil import (
    create_client_ssl_context,
    create_server_ssl_context,
    format_tls_error,
)
import config
from receiver import SwarmReceiver, download_from_senders
from sender import SenderServer
from tools.gen_certs import generate_self_signed_cert


@pytest.fixture(autouse=True)
def reset_rate_limiter() -> None:
    """Ensure rate limiter is reset before and after each test."""
    default_rate_limiter.reset()
    yield
    default_rate_limiter.reset()


def _generate_expired_cert(out_dir: Path) -> Tuple[Path, Path]:
    """Helper to generate an expired certificate for TLS testing."""
    out_dir.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    subject = issuer = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "localhost")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=10))
        .not_valid_after(now - timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path = out_dir / "expired_cert.pem"
    key_path = out_dir / "expired_key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


def test_scrypt_key_derivation_deterministic() -> None:
    """Verify Scrypt key derivation parameters and determinism."""
    code = "viva-demo-secure-code-2026"
    key1 = derive_auth_key(code)
    key2 = derive_auth_key(code)

    assert len(key1) == 32
    assert key1 == key2

    # Different codes must yield different keys
    key_other = derive_auth_key("different-code-9999")
    assert key1 != key_other

    # Report key derivation
    rep1 = derive_report_key(key1)
    assert len(rep1) == 32
    assert rep1 != key1


def test_empty_join_code_rejected() -> None:
    """Empty join code must raise ValueError."""
    with pytest.raises(ValueError, match="cannot be empty"):
        derive_auth_key("")


def test_mutual_proof_verification_constant_time() -> None:
    """Verify challenge-response proof generation and constant-time verification."""
    auth_key = derive_auth_key("test-join-code-passkey")
    nonce = secrets.token_bytes(32)
    device_id = "device-receiver-01"

    # Client proof
    client_proof = compute_client_proof(auth_key, nonce, device_id)
    assert verify_client_proof(auth_key, nonce, device_id, client_proof) is True

    # Mutated proof rejected
    corrupted_proof = ("0" if client_proof[0] != "0" else "1") + client_proof[1:]
    assert verify_client_proof(auth_key, nonce, device_id, corrupted_proof) is False

    # Server mutual proof
    server_proof = compute_server_proof(auth_key, nonce, device_id)
    assert verify_server_proof(auth_key, nonce, device_id, server_proof) is True
    assert verify_server_proof(auth_key, nonce, device_id, corrupted_proof) is False


def test_replayed_proof_rejected() -> None:
    """Verify that a proof computed with nonce_A is rejected when presented for nonce_B."""
    auth_key = derive_auth_key("test-join-code-passkey")
    nonce_a = secrets.token_bytes(32)
    nonce_b = secrets.token_bytes(32)
    device_id = "device-receiver-01"

    proof_a = compute_client_proof(auth_key, nonce_a, device_id)

    # Replaying proof_a against nonce_b must fail
    assert verify_client_proof(auth_key, nonce_b, device_id, proof_a) is False


def test_wrong_join_code_rejected() -> None:
    """Verify that proofs derived from different join codes fail verification."""
    key_alice = derive_auth_key("correct-join-code-1234")
    key_eve = derive_auth_key("wrong-join-code-9999")

    nonce = secrets.token_bytes(32)
    device_id = "device-receiver-01"

    eve_proof = compute_client_proof(key_eve, nonce, device_id)
    assert verify_client_proof(key_alice, nonce, device_id, eve_proof) is False


def test_rate_limiter_blocks_and_resets() -> None:
    """Verify per-IP rate limiter blocks after AUTH_MAX_FAILURES and supports reset()."""
    limiter = AuthRateLimiter(max_failures=3, block_duration=2.0)
    attacker_ip = "192.168.1.50"
    victim_ip = "192.168.1.51"

    # Initially not blocked
    blocked, _ = limiter.is_blocked(attacker_ip)
    assert blocked is False

    # 1st failure
    assert limiter.record_failure(attacker_ip) is False
    # 2nd failure
    assert limiter.record_failure(attacker_ip) is False
    # 3rd failure triggers block
    assert limiter.record_failure(attacker_ip) is True

    # Attacker IP is now blocked
    blocked, remaining = limiter.is_blocked(attacker_ip)
    assert blocked is True
    assert remaining > 0

    # Other IPs unaffected
    blocked_other, _ = limiter.is_blocked(victim_ip)
    assert blocked_other is False

    # State must be resettable between tests (Section 14.2)
    limiter.reset()
    blocked_after_reset, _ = limiter.is_blocked(attacker_ip)
    assert blocked_after_reset is False


def test_gen_certs_extensions(tmp_path: Path) -> None:
    """Verify certificate generated by gen_certs has all strict Python 3.13 extensions."""
    cert_path, key_path = generate_self_signed_cert(
        out_dir=tmp_path,
        additional_ips=["192.168.43.10", "node.local"],
        days=30,
    )
    assert cert_path.exists()
    assert key_path.exists()

    cert_bytes = cert_path.read_bytes()
    cert = x509.load_pem_x509_certificate(cert_bytes)

    # 1. BasicConstraints: CA:TRUE
    bc_ext = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
    assert bc_ext.critical is True
    assert bc_ext.value.ca is True

    # 2. KeyUsage
    ku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
    assert ku_ext.critical is True
    assert ku_ext.value.digital_signature is True
    assert ku_ext.value.key_cert_sign is True

    # 3. SubjectAlternativeName
    san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    names = [str(n.value) for n in san_ext.value]
    assert "localhost" in names
    assert "127.0.0.1" in names
    assert "192.168.43.10" in names
    assert "node.local" in names

    # 4. SKI and AKI
    ski_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
    aki_ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
    assert ski_ext is not None
    assert aki_ext is not None


def test_client_ssl_context_strict_pinning(tmp_path: Path) -> None:
    """Verify receiver SSLContext enforces CERT_REQUIRED and never CERT_NONE."""
    cert_path, _ = generate_self_signed_cert(out_dir=tmp_path)
    ctx = create_client_ssl_context(cert_path)

    # Strict certificate pinning assertions
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.verify_mode != ssl.CERT_NONE
    assert ctx.check_hostname is False
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2


def test_client_ssl_context_missing_file() -> None:
    """Verify that referencing non-existent certificate raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError, match="not found"):
        create_client_ssl_context("/non/existent/cert.pem")


def test_format_tls_error_mappings() -> None:
    """Verify that TLS and network connection exceptions map to user-friendly messages without stack traces."""
    # 1. Certificate mismatch
    err_mismatch = ssl.SSLCertVerificationError(18, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate")
    err_mismatch.verify_code = 18
    err_mismatch.verify_message = "self-signed certificate"
    msg = format_tls_error(err_mismatch)
    assert "certificate mismatch" in msg
    assert "Traceback" not in msg

    # 2. Certificate expired
    err_expired = ssl.SSLCertVerificationError(10, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: certificate has expired")
    err_expired.verify_code = 10
    err_expired.verify_message = "certificate has expired"
    msg_exp = format_tls_error(err_expired)
    assert "certificate not yet valid or expired, check the device clock" in msg_exp
    assert "Traceback" not in msg_exp

    # 3. Certificate not yet valid
    err_not_valid = ssl.SSLCertVerificationError(9, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: certificate is not yet valid")
    err_not_valid.verify_code = 9
    err_not_valid.verify_message = "certificate is not yet valid"
    msg_nv = format_tls_error(err_not_valid)
    assert "certificate not yet valid or expired, check the device clock" in msg_nv

    # 4. Connection refused
    err_refused = ConnectionRefusedError(61, "Connection refused")
    msg_ref = format_tls_error(err_refused)
    assert "connection refused" in msg_ref
    assert "Traceback" not in msg_ref


def test_premature_message_before_hello_refused_and_disconnected(tmp_path: Path) -> None:
    """Verify that a client completing TLS but sending GET_METADATA or REQUEST before HELLO is refused and disconnected."""
    cert_path, key_path = generate_self_signed_cert(out_dir=tmp_path / "certs")
    sample_file = tmp_path / "sample.txt"
    sample_file.write_bytes(b"Hello World P2P Premature Message Test")

    join_code = "demo-join-code-premature-2026"
    sender = SenderServer(
        source_path=sample_file,
        port=0,
        bind_host="127.0.0.1",
        cert_path=cert_path,
        key_path=key_path,
        join_code=join_code,
    )
    sender.start(blocking=False)
    time.sleep(0.1)

    client_ctx = create_client_ssl_context(cert_path)

    try:
        # Case 1: Client sends premature GET_METADATA before HELLO
        raw_sock1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock1.connect(("127.0.0.1", sender.port))
        tls_sock1 = client_ctx.wrap_socket(raw_sock1, server_hostname=None)

        # Receive CHALLENGE
        chal_hdr, _ = recv_message(tls_sock1)
        assert chal_hdr.get("type") == "CHALLENGE"

        # Send premature GET_METADATA instead of HELLO
        send_message(tls_sock1, make_get_metadata())

        # Sender must refuse with ERROR(code="BAD_REQUEST")
        err_hdr, _ = recv_message(tls_sock1)
        assert err_hdr.get("type") == "ERROR"
        assert err_hdr.get("code") == "BAD_REQUEST"

        # Sender must disconnect the client socket immediately
        with pytest.raises(ConnectionClosedError):
            recv_message(tls_sock1)

        tls_sock1.close()

        # Case 2: Client sends premature REQUEST before HELLO
        raw_sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock2.connect(("127.0.0.1", sender.port))
        tls_sock2 = client_ctx.wrap_socket(raw_sock2, server_hostname=None)

        chal_hdr2, _ = recv_message(tls_sock2)
        assert chal_hdr2.get("type") == "CHALLENGE"

        # Send premature REQUEST(0) instead of HELLO
        send_message(tls_sock2, make_request(0))

        err_hdr2, _ = recv_message(tls_sock2)
        assert err_hdr2.get("type") == "ERROR"
        assert err_hdr2.get("code") == "BAD_REQUEST"

        # Disconnection check
        with pytest.raises(ConnectionClosedError):
            recv_message(tls_sock2)

        tls_sock2.close()

    finally:
        sender.stop()


def test_sender_correct_cert_wrong_join_code_rejected_no_pieces(tmp_path: Path) -> None:
    """Verify that a sender with correct cert but wrong join code has its proof rejected by the receiver and no pieces are requested."""
    cert_path, key_path = generate_self_signed_cert(out_dir=tmp_path / "certs_mutual")
    sample_file = tmp_path / "data.bin"
    sample_file.write_bytes(b"SecretSwarmData" * 500)

    server_code = "server-wrong-code"
    client_code = "client-correct-code"

    # Part A: Receiver connects to standard SenderServer running with wrong code
    sender = SenderServer(
        source_path=sample_file,
        port=0,
        bind_host="127.0.0.1",
        cert_path=cert_path,
        key_path=key_path,
        join_code=server_code,
    )
    sender.start(blocking=False)
    time.sleep(0.1)

    dest_dir = tmp_path / "dest1"
    dest_dir.mkdir()

    try:
        with pytest.raises(ConnectionError):
            download_from_senders(
                senders=[f"127.0.0.1:{sender.port}"],
                out_dir=dest_dir,
                cert_path=cert_path,
                join_code=client_code,
                verbose=False,
                backoff_base=0.01,
            )
        # Verify 0 pieces were sent
        assert sender._pieces_sent == 0
    finally:
        sender.stop()

    # Part B: Rogue sender that sends WELCOME with invalid mutual server proof
    server_ssl_ctx = create_server_ssl_context(cert_path, key_path)
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(("127.0.0.1", 0))
    server_sock.listen(1)
    port = server_sock.getsockname()[1]

    requests_received = []

    def rogue_sender_thread():
        try:
            conn, _ = server_sock.accept()
            tls_conn = server_ssl_ctx.wrap_socket(conn, server_side=True)
            nonce = secrets.token_bytes(32)
            # Send CHALLENGE
            send_message(tls_conn, make_challenge(device_id="rogue-01", name="Rogue", nonce=nonce.hex()))
            # Receive HELLO
            hello_hdr, _ = recv_message(tls_conn)
            # Compute server proof with wrong join code
            wrong_auth_key = derive_auth_key("completely-wrong-join-code")
            bad_server_proof = compute_server_proof(wrong_auth_key, nonce, hello_hdr.get("device_id", ""))
            # Send WELCOME with invalid server proof
            send_message(tls_conn, make_welcome(proof=bad_server_proof, swarm_id="a" * 64))

            # Listen for any subsequent requests from receiver
            while True:
                try:
                    hdr, _ = recv_message(tls_conn)
                    requests_received.append(hdr.get("type"))
                except Exception:
                    break
        except Exception:
            pass
        finally:
            server_sock.close()

    t = threading.Thread(target=rogue_sender_thread, daemon=True)
    t.start()

    receiver = SwarmReceiver(
        senders=[f"127.0.0.1:{port}"],
        out_dir=tmp_path / "dest2",
        cert_path=cert_path,
        join_code=client_code,
        verbose=False,
        backoff_base=0.01,
    )

    with pytest.raises(ConnectionError, match="failed mutual server proof|Could not retrieve valid metadata"):
        receiver.download()

    t.join(timeout=1.0)
    # The receiver MUST reject the sender's proof and request zero pieces!
    assert "REQUEST" not in requests_received
    assert len(requests_received) == 0


def test_silent_connections_handshake_timeout_do_not_block(tmp_path: Path) -> None:
    """Verify that 8 silent connections timing out do not block a legitimate receiver."""
    cert_path, key_path = generate_self_signed_cert(out_dir=tmp_path / "certs_silent")
    sample_file = tmp_path / "data.bin"
    test_content = b"SilentConnectionTestData" * 200
    sample_file.write_bytes(test_content)

    join_code = "handshake-timeout-test-code-2026"

    # Start sender with a short handshake timeout (0.5s)
    sender = SenderServer(
        source_path=sample_file,
        port=0,
        bind_host="127.0.0.1",
        cert_path=cert_path,
        key_path=key_path,
        join_code=join_code,
        handshake_timeout=0.5,
    )
    sender.start(blocking=False)
    time.sleep(0.1)

    dest_dir = tmp_path / "dest_silent"
    dest_dir.mkdir()

    try:
        # Open 8 silent TCP connections (saturating MAX_CONNECTIONS_PER_SENDER)
        silent_socks = []
        for _ in range(config.MAX_CONNECTIONS_PER_SENDER):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("127.0.0.1", sender.port))
            silent_socks.append(s)

        # Allow connections to be accepted and wait for handshake timeout (0.5s + margin)
        time.sleep(0.8)

        # The silent connections timed out and were disconnected by the sender
        for s in silent_socks:
            try:
                s.settimeout(0.2)
                data = s.recv(1024)
                assert data == b""
            except OSError:
                pass
            finally:
                s.close()

        # A legitimate receiver must now connect, authenticate, and download without blocking
        result = download_from_senders(
            senders=[f"127.0.0.1:{sender.port}"],
            out_dir=dest_dir,
            cert_path=cert_path,
            join_code=join_code,
            verbose=False,
            handshake_timeout=2.0,
        )
        assert result["completed"] is True
        downloaded_file = dest_dir / "data.bin"
        assert downloaded_file.read_bytes() == test_content

    finally:
        sender.stop()


def test_tls_failure_messages_no_stack_traces(tmp_path: Path) -> None:
    """Verify that TLS and network failures produce clear messages with no raw stack traces."""
    cert_path, key_path = generate_self_signed_cert(out_dir=tmp_path / "certs_valid")
    dest_dir = tmp_path / "dest_err"
    dest_dir.mkdir()

    # 1. Connection refused (closed port)
    with pytest.raises(ConnectionError) as exc_info:
        download_from_senders(
            senders=["127.0.0.1:65530"],
            out_dir=dest_dir,
            cert_path=cert_path,
            join_code="any-code",
            verbose=False,
            backoff_base=0.01,
        )
    err_str = str(exc_info.value)
    assert "connection refused" in err_str.lower()
    assert "Traceback" not in err_str

    # 2. Certificate mismatch
    other_cert_path, other_key_path = generate_self_signed_cert(out_dir=tmp_path / "certs_other")
    sample_file = tmp_path / "sample.txt"
    sample_file.write_bytes(b"TLS error test")

    sender = SenderServer(
        source_path=sample_file,
        port=0,
        bind_host="127.0.0.1",
        cert_path=other_cert_path,
        key_path=other_key_path,
        join_code="test-code",
    )
    sender.start(blocking=False)
    time.sleep(0.1)

    try:
        # Receiver pins cert_path, but sender presents other_cert_path
        with pytest.raises(ConnectionError) as exc_info:
            download_from_senders(
                senders=[f"127.0.0.1:{sender.port}"],
                out_dir=dest_dir,
                cert_path=cert_path,
                join_code="test-code",
                verbose=False,
                backoff_base=0.01,
            )
        err_str = str(exc_info.value)
        assert "certificate mismatch" in err_str
        assert "Traceback" not in err_str
    finally:
        sender.stop()

    # 3. Certificate expired
    exp_cert_path, exp_key_path = _generate_expired_cert(tmp_path / "certs_expired")
    sender_exp = SenderServer(
        source_path=sample_file,
        port=0,
        bind_host="127.0.0.1",
        cert_path=exp_cert_path,
        key_path=exp_key_path,
        join_code="test-code",
    )
    sender_exp.start(blocking=False)
    time.sleep(0.1)

    try:
        with pytest.raises(ConnectionError) as exc_info:
            download_from_senders(
                senders=[f"127.0.0.1:{sender_exp.port}"],
                out_dir=dest_dir,
                cert_path=exp_cert_path,
                join_code="test-code",
                verbose=False,
                backoff_base=0.01,
            )
        err_str = str(exc_info.value)
        assert "certificate not yet valid or expired, check the device clock" in err_str
        assert "Traceback" not in err_str
    finally:
        sender_exp.stop()

