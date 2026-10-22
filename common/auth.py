"""Authentication, key derivation, and rate limiting for P2P Swarm.

Implements Sections 7.3, 7.4, and 14.2:
- Mutual join-code authentication: challenge-response with HMAC-SHA256 and constant-time comparison.
- Key derivation using Scrypt (N=2^14, r=8, p=1, dklen=32, salt=b"p2p-swarm/auth/v1").
- Per-IP rate limiting: refuses connections for AUTH_BLOCK_SECONDS after AUTH_MAX_FAILURES failures.
- Resettable rate limiter state for tests.
- Secure join code acquisition from P2P_JOIN_CODE, getpass, or CLI flag with warning.
"""

from collections import defaultdict
import getpass
import hashlib
import hmac
import os
import sys
import threading
import time
from typing import Dict, List, Optional, Tuple

import config


class AuthError(Exception):
    """Raised when peer authentication fails or challenge-response verification fails."""
    pass


def derive_auth_key(join_code: str) -> bytes:
    """Derive 32-byte authentication key from join code via Scrypt (Section 7.4).

    Args:
        join_code: Shared out-of-band secret string.

    Returns:
        32-byte derived auth_key.
    """
    if not join_code:
        raise ValueError("Join code cannot be empty.")
    return hashlib.scrypt(
        join_code.encode("utf-8"),
        salt=b"p2p-swarm/auth/v1",
        n=2**14,
        r=8,
        p=1,
        dklen=32,
    )


def derive_report_key(auth_key: bytes) -> bytes:
    """Derive telemetry report signing key from auth key via HMAC-SHA256 (Section 7.4)."""
    return hmac.new(auth_key, b"report", hashlib.sha256).digest()


def compute_client_proof(auth_key: bytes, nonce: bytes, device_id: str) -> str:
    """Compute receiver HELLO authentication proof (Section 7.3 Step 3).

    proof = HMAC-SHA256(auth_key, nonce_bytes || device_id_utf8)
    """
    data = nonce + device_id.encode("utf-8")
    return hmac.new(auth_key, data, hashlib.sha256).hexdigest()


def verify_client_proof(auth_key: bytes, nonce: bytes, device_id: str, client_proof: str) -> bool:
    """Verify receiver proof in constant time using hmac.compare_digest (Section 7.3 Step 4)."""
    expected = compute_client_proof(auth_key, nonce, device_id)
    return hmac.compare_digest(client_proof, expected)


def compute_server_proof(auth_key: bytes, nonce: bytes, device_id: str) -> str:
    """Compute sender WELCOME mutual authentication proof (Section 7.3 Step 5).

    proof_server = HMAC-SHA256(auth_key, b"server" || nonce_bytes || receiver_device_id_utf8)
    """
    data = b"server" + nonce + device_id.encode("utf-8")
    return hmac.new(auth_key, data, hashlib.sha256).hexdigest()


def verify_server_proof(auth_key: bytes, nonce: bytes, device_id: str, server_proof: str) -> bool:
    """Verify sender mutual proof in constant time using hmac.compare_digest (Section 7.3 Step 5)."""
    expected = compute_server_proof(auth_key, nonce, device_id)
    return hmac.compare_digest(server_proof, expected)


class AuthRateLimiter:
    """Thread-safe per-IP rate limiter protecting senders against brute-force attacks (Section 14.2).

    Blocks an IP address for AUTH_BLOCK_SECONDS after AUTH_MAX_FAILURES failed handshakes.
    Supports state reset for localhost integration tests.
    """

    def __init__(
        self,
        max_failures: int = config.AUTH_MAX_FAILURES,
        block_duration: float = config.AUTH_BLOCK_SECONDS,
    ) -> None:
        self.max_failures = max_failures
        self.block_duration = block_duration
        self._failures: Dict[str, List[float]] = defaultdict(list)
        self._blocked_until: Dict[str, float] = {}
        self._lock = threading.Lock()

    def is_blocked(self, ip: str) -> Tuple[bool, float]:
        """Check if an IP is currently blocked.

        Returns:
            Tuple of (is_blocked, remaining_seconds).
        """
        now = time.time()
        with self._lock:
            blocked_until = self._blocked_until.get(ip, 0.0)
            if now < blocked_until:
                return True, blocked_until - now
            if ip in self._blocked_until:
                # Block expired
                del self._blocked_until[ip]
            return False, 0.0

    def record_failure(self, ip: str) -> bool:
        """Record an authentication failure from an IP.

        Returns:
            True if this failure resulted in a new IP block, False otherwise.
        """
        now = time.time()
        with self._lock:
            # Clean up failure timestamps older than block_duration
            window_cutoff = now - self.block_duration
            self._failures[ip] = [t for t in self._failures[ip] if t > window_cutoff]
            self._failures[ip].append(now)

            if len(self._failures[ip]) >= self.max_failures:
                self._blocked_until[ip] = now + self.block_duration
                self._failures[ip].clear()
                return True
            return False

    def record_success(self, ip: str) -> None:
        """Clear failures on successful authentication."""
        with self._lock:
            self._failures.pop(ip, None)

    def reset(self) -> None:
        """Reset all rate limiter tracking state (crucial for localhost tests)."""
        with self._lock:
            self._failures.clear()
            self._blocked_until.clear()


# Default singleton instance used across the sender server
default_rate_limiter = AuthRateLimiter()


def get_join_code(code_arg: Optional[str] = None) -> str:
    """Securely resolve join code from argument, environment, or interactive prompt.

    Security rule: Never log, store in cleartext files, or broadcast the join code.
    """
    if code_arg:
        print(
            "[WARNING] Passing the join code via command-line arguments (--code) can expose "
            "it to other users on the system via 'ps'. Use the P2P_JOIN_CODE environment "
            "variable or interactive prompt instead.",
            file=sys.stderr,
        )
        return code_arg

    env_code = os.environ.get("P2P_JOIN_CODE")
    if env_code:
        return env_code

    try:
        entered = getpass.getpass("Enter P2P Swarm Join Code: ")
        if not entered:
            raise ValueError("Join code cannot be empty.")
        return entered
    except (EOFError, KeyboardInterrupt):
        raise ValueError("Join code prompt aborted.")
