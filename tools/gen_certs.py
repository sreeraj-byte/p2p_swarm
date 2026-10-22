"""Certificate generation tool for P2P Swarm.

Generates self-signed TLS certificates for local swarm nodes compatible with
Python 3.13 strict certificate verification.

Key Requirements (Section 14.1):
- Subject Alternative Names (SAN) for 'localhost', '127.0.0.1', and any specified IPs.
- Basic Constraints: CA:TRUE (so it can act as the pinned trust anchor).
- Key Usage: Digital Signature, Key Encipherment, Certificate Signing, CRL Signing.
- Extended Key Usage: Server Auth, Client Auth.
- Subject Key Identifier (SKI) and Authority Key Identifier (AKI).
- Secure private key permissions (0600 on POSIX).
"""

import argparse
from datetime import datetime, timedelta, timezone
import ipaddress
import os
from pathlib import Path
import sys
from typing import List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def generate_self_signed_cert(
    out_dir: Path,
    additional_ips: Optional[List[str]] = None,
    days: int = 365,
) -> Tuple[Path, Path]:
    """Generate self-signed certificate and private key.

    Args:
        out_dir: Directory where cert.pem and key.pem will be written.
        additional_ips: Optional list of additional IP addresses or hostnames.
        days: Validity period in days.

    Returns:
        Tuple of (cert_path, key_path).
    """
    target = Path(out_dir).resolve()
    target.mkdir(parents=True, exist_ok=True)

    # 1. Generate RSA 2048-bit Private Key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    # 2. Build Subject and Issuer
    subject_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "p2p-swarm-root"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "P2P Swarm Network"),
    ])

    # 3. Build Subject Alternative Name (SAN) list
    san_entries: List[x509.GeneralName] = [
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
    ]

    if additional_ips:
        for item in additional_ips:
            item = item.strip()
            if not item:
                continue
            try:
                ip_obj = ipaddress.ip_address(item)
                san_entries.append(x509.IPAddress(ip_obj))
            except ValueError:
                # Hostname or DNS name
                san_entries.append(x509.DNSName(item))

    # 4. Key Identifiers
    ski = x509.SubjectKeyIdentifier.from_public_key(public_key)
    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key)

    now = datetime.now(timezone.utc)
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(subject_name)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=days))
        # Basic Constraints: CA:TRUE (critical=True for Python 3.13 trust anchor verification)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        # Key Usage (critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        # Extended Key Usage (Server + Client Auth)
        .add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH,
                ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=False,
        )
        # Subject Alternative Names (SAN)
        .add_extension(
            x509.SubjectAlternativeName(san_entries),
            critical=False,
        )
        # SKI and AKI
        .add_extension(ski, critical=False)
        .add_extension(aki, critical=False)
    )

    # 5. Self-sign certificate with SHA-256
    certificate = cert_builder.sign(
        private_key=private_key,
        algorithm=hashes.SHA256(),
    )

    cert_path = target / "cert.pem"
    key_path = target / "key.pem"

    cert_bytes = certificate.public_bytes(serialization.Encoding.PEM)
    key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    cert_path.write_bytes(cert_bytes)
    key_path.write_bytes(key_bytes)

    # 6. Apply restrictive file permissions on the private key (POSIX)
    if os.name == "posix":
        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass

    return cert_path, key_path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate self-signed TLS certificates for P2P Swarm."
    )
    parser.add_argument(
        "--out",
        type=str,
        default="certs",
        help="Target output directory for cert.pem and key.pem (default: certs)",
    )
    parser.add_argument(
        "--ip",
        type=str,
        nargs="*",
        default=[],
        help="Additional IP addresses to include in SAN list (e.g. 192.168.1.100)",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=365,
        help="Certificate validity duration in days (default: 365)",
    )

    args = parser.parse_args()
    out_dir = Path(args.out)

    print(f"Generating P2P Swarm certificate in '{out_dir}'...")
    cert_path, key_path = generate_self_signed_cert(
        out_dir=out_dir,
        additional_ips=args.ip,
        days=args.days,
    )

    print(f"[OK] Certificate written to: {cert_path}")
    print(f"[OK] Private key written to: {key_path}")
    print("\nSecurity Instructions:")
    print("  - Senders require BOTH cert.pem and key.pem.")
    print("  - Receivers require ONLY cert.pem to pin trust.")
    print("  - Do NOT share key.pem with receivers or across untrusted channels.\n")


if __name__ == "__main__":
    main()
