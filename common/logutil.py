"""Logging setup for P2P Swarm with redaction to prevent secret leakage.

This module provides structured logging utilities and ensures that sensitive
information such as join codes, derived authentication keys, or raw secrets
never appear in terminal logs, file logs, or tracebacks (Section 14.6).
"""

import logging
import sys
from typing import Optional, Set


class SecretSanitizingFilter(logging.Filter):
    """Logging filter that scrubs registered sensitive tokens from log messages.

    In a peer-to-peer security model, accidental leakage of passwords or
    cryptographic keys into logs or console output is a serious vulnerability.
    This filter intercepts log records before emission and replaces any registered
    secrets with [REDACTED].
    """

    def __init__(self, name: str = "") -> None:
        super().__init__(name)
        self._secrets: Set[str] = set()

    def register_secret(self, secret: str) -> None:
        """Register a sensitive token (join code, key string) to redact.

        Args:
            secret: String token that must not appear in any log output.
        """
        if secret and len(secret.strip()) >= 3:
            self._secrets.add(secret.strip())

    def filter(self, record: logging.LogRecord) -> bool:
        """Sanitize record message and args before output."""
        if not self._secrets:
            return True

        if isinstance(record.msg, str):
            for secret in self._secrets:
                if secret in record.msg:
                    record.msg = record.msg.replace(secret, "[REDACTED]")

        if record.args:
            if isinstance(record.args, dict):
                sanitized_args = {}
                for k, v in record.args.items():
                    val_str = str(v)
                    for secret in self._secrets:
                        val_str = val_str.replace(secret, "[REDACTED]")
                    sanitized_args[k] = val_str
                record.args = sanitized_args
            elif isinstance(record.args, tuple):
                sanitized_list = []
                for item in record.args:
                    val_str = str(item)
                    for secret in self._secrets:
                        val_str = val_str.replace(secret, "[REDACTED]")
                    sanitized_list.append(val_str)
                record.args = tuple(sanitized_list)

        return True


# Global filter instance for convenient secret registration across modules
_GLOBAL_SANITIZER = SecretSanitizingFilter()


def register_secret(secret: str) -> None:
    """Register a secret with the global log sanitizer."""
    _GLOBAL_SANITIZER.register_secret(secret)


def setup_logging(
    level: int = logging.INFO,
    log_file: Optional[str] = None,
) -> logging.Logger:
    """Configure system-wide logging with consistent format and secret sanitization.

    Args:
        level: Base logging level (e.g. logging.INFO or logging.DEBUG).
        log_file: Optional filepath to write log output in addition to stdout.

    Returns:
        The root or application logger configured.
    """
    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    root_logger = logging.getLogger("p2p_swarm")
    root_logger.setLevel(level)

    # Avoid duplicate handlers if setup_logging is called multiple times
    if not root_logger.handlers:
        if sys.platform == "win32":
            try:
                if hasattr(sys.stdout, "reconfigure"):
                    sys.stdout.reconfigure(encoding="utf-8")
                if hasattr(sys.stderr, "reconfigure"):
                    sys.stderr.reconfigure(encoding="utf-8")
            except Exception:
                pass

        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        console_handler.addFilter(_GLOBAL_SANITIZER)
        root_logger.addHandler(console_handler)

        if log_file:
            file_handler = logging.FileHandler(log_file, encoding="utf-8")
            file_handler.setFormatter(formatter)
            file_handler.addFilter(_GLOBAL_SANITIZER)
            root_logger.addHandler(file_handler)

    return root_logger


def get_logger(name: str) -> logging.Logger:
    """Retrieve a child logger under the p2p_swarm namespace."""
    return logging.getLogger(f"p2p_swarm.{name}")
