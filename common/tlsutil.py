"""TLS configuration utilities for P2P Swarm.

Enforces transport layer security according to Section 14.1:
- Minimum TLS 1.2 (ssl.TLSVersion.TLSv1_2).
- The receiver pins trust to the sender's certificate (one-way certificate pinning):
  verify_mode = CERT_REQUIRED, trusted certificate loaded as only trust anchor,
  check_hostname = False (peers are addressed by IP).
- Never uses CERT_NONE or disables certificate verification, even in tests.
- Note: Peer transport security uses TLS with one-way certificate pinning
  plus mutual join-code authentication at the application layer.
"""

from pathlib import Path
import socket
import ssl
from typing import Union


def create_server_ssl_context(
    cert_path: Union[str, Path],
    key_path: Union[str, Path],
) -> ssl.SSLContext:
    """Create and configure server-side TLS context for senders.

    Args:
        cert_path: Path to server certificate PEM.
        key_path: Path to server private key PEM.

    Returns:
        Configured ssl.SSLContext.

    Raises:
        FileNotFoundError: If cert_path or key_path does not exist.
        ssl.SSLError: If certificate or key cannot be loaded.
    """
    cert = Path(cert_path).resolve()
    key = Path(key_path).resolve()

    if not cert.exists():
        raise FileNotFoundError(f"TLS certificate file not found: '{cert}'")
    if not key.exists():
        raise FileNotFoundError(f"TLS private key file not found: '{key}'")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    # Load server certificate chain and private key
    context.load_cert_chain(certfile=str(cert), keyfile=str(key))

    return context


def create_client_ssl_context(
    trusted_cert_path: Union[str, Path],
) -> ssl.SSLContext:
    """Create and configure client-side TLS context for receivers.

    Pins trust strictly to the provided certificate file.
    Enforces CERT_REQUIRED and disables check_hostname (Section 14.1)
    because swarm peers connect directly via IP addresses on ad-hoc networks.

    Args:
        trusted_cert_path: Path to the pinned sender certificate PEM.

    Returns:
        Configured ssl.SSLContext with certificate pinning enabled.

    Raises:
        FileNotFoundError: If trusted_cert_path does not exist.
        ssl.SSLError: If certificate cannot be loaded into verify locations.
    """
    cert = Path(trusted_cert_path).resolve()
    if not cert.exists():
        raise FileNotFoundError(f"Pinned TLS certificate file not found: '{cert}'")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    # Strict certificate pinning:
    # 1. Require valid certificate matching trust anchor
    context.verify_mode = ssl.CERT_REQUIRED
    # 2. check_hostname=False because peers connect via LAN IPs, not CA-issued domain names
    context.check_hostname = False
    # 3. Load the pinned certificate as the only trusted CA anchor
    context.load_verify_locations(cafile=str(cert))

    return context


def format_tls_error(err: Exception) -> str:
    """Map TLS and network connection failures to clear messages without raw stack traces.

    Mapped cases:
    - Certificate mismatch (sender certificate does not match the pinned certificate)
    - Certificate not yet valid or expired, check the device clock
    - Connection refused (sender is not running or port is closed)
    - Connection timed out
    """
    if isinstance(err, ssl.SSLCertVerificationError):
        msg = (getattr(err, "verify_message", "") or str(err)).lower()
        code = getattr(err, "verify_code", None)
        # 10: X509_V_ERR_CERT_HAS_EXPIRED, 9: X509_V_ERR_CERT_NOT_YET_VALID
        if code in (9, 10) or "expired" in msg or "not yet valid" in msg:
            return "TLS error: certificate not yet valid or expired, check the device clock"
        return "TLS error: certificate mismatch (sender certificate does not match the pinned certificate)"

    if isinstance(err, ssl.SSLError):
        err_str = str(err).lower()
        if "expired" in err_str or "not yet valid" in err_str:
            return "TLS error: certificate not yet valid or expired, check the device clock"
        if "verify failed" in err_str or "certificate" in err_str or "unknown ca" in err_str:
            return "TLS error: certificate mismatch (sender certificate does not match the pinned certificate)"
        return f"TLS error: {getattr(err, 'strerror', None) or str(err)}"

    if isinstance(err, ConnectionRefusedError):
        return "connection refused: sender is not running or port is closed"

    if isinstance(err, (TimeoutError, socket.timeout)):
        return "connection timed out"

    return str(err)

