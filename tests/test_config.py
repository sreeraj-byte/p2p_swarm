"""Unit tests for Phase 0 scaffolding: configuration constants and logging."""

import logging
from common.logutil import SecretSanitizingFilter, get_logger, setup_logging
import config


def test_protocol_constants() -> None:
    """Verify essential protocol constants adhere to Section 5."""
    assert config.PROTOCOL_VERSION == 1
    assert config.DEFAULT_PIECE_SIZE == 65536
    assert config.MIN_PIECE_SIZE == 16384
    assert config.MAX_PIECE_SIZE == 4194304
    assert config.MAX_PIECES == 100000


def test_network_and_timeout_constants() -> None:
    """Verify networking ports, timeouts, and buffer caps."""
    assert config.DEFAULT_TCP_PORT == 6881
    assert config.DISCOVERY_PORT == 50000
    assert config.DEFAULT_WEB_PORT == 8080
    assert config.HEARTBEAT_INTERVAL == 2.0
    assert config.OFFLINE_AFTER == 8.0
    assert config.DEVICE_EXPIRY_AFTER == 60.0
    assert config.DEFAULT_MIN_SENDERS == 2
    assert config.DEFAULT_DISCOVER_TIMEOUT == 20.0
    assert config.HANDSHAKE_TIMEOUT == 10.0
    assert config.SOCKET_TIMEOUT == 30.0
    assert config.REQUEST_TIMEOUT == 5.0
    assert config.MAX_DEVICE_IDS_PER_IP == 8
    assert config.MAX_CONCURRENT_CONNECT_ATTEMPTS == 4


def test_security_limits_constants() -> None:
    """Verify security caps for auth failure rates, strikes, and message sizes."""
    assert config.AUTH_MAX_FAILURES == 5
    assert config.AUTH_BLOCK_SECONDS == 60.0
    assert config.HASH_STRIKES_TO_BAN == 3
    assert config.MAX_DISCOVERY_PACKET_BYTES == 1024
    assert config.MAX_HEADER_BYTES == 65536
    assert config.MAX_METADATA_BYTES == 16777216
    assert config.MAX_REPORT_BYTES == 65536
    assert config.REPORT_INTERVAL == 0.5
    assert config.REPORT_CLOCK_SKEW == 30.0
    assert config.MAX_DEVICES == 256
    assert config.MAX_EVENTS == 200
    assert config.PIECE_MAP_MAX_CELLS == 400


def test_secret_sanitizing_logger() -> None:
    """Verify that sensitive tokens are redacted from log messages."""
    filter_instance = SecretSanitizingFilter()
    secret = "alpha-bravo-swarm-key-9988"
    filter_instance.register_secret(secret)

    # Test string message replacement
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg=f"Connected using join code {secret} successfully.",
        args=(),
        exc_info=None,
    )
    filter_instance.filter(record)
    assert secret not in record.msg
    assert "[REDACTED]" in record.msg

    # Test args replacement
    record_with_args = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg="Join code: %s",
        args=(secret,),
        exc_info=None,
    )
    filter_instance.filter(record_with_args)
    assert secret not in record_with_args.args[0]
    assert "[REDACTED]" in record_with_args.args[0]
