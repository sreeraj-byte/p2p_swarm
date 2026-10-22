"""Wire protocol framing and message definitions for P2P Swarm.

This module implements the length-prefixed framing and JSON message structure
specified in Section 7 of PROJECT_SPEC.md.

Framing format:
  [4 bytes: header_len (big-endian uint32)]
  [4 bytes: payload_len (big-endian uint32)]
  [header_len bytes: UTF-8 encoded JSON header]
  [payload_len bytes: optional raw binary payload]

Security checks:
  - Header and payload lengths are strictly validated before memory allocation
    to prevent memory exhaustion Denial of Service (DoS) attacks.
  - Message parsing handles streaming TCP socket fragments and complete messages.
"""

import json
import socket
import struct
from typing import Any, Dict, Optional, Tuple

import config


class ProtocolError(Exception):
    """Raised when a framing violation, malformed message, or protocol error occurs."""
    pass


class ConnectionClosedError(ProtocolError):
    """Raised when the peer socket closes unexpectedly during read."""
    pass


# Struct packing format: two unsigned 32-bit big-endian integers
PREFIX_FORMAT = "!II"
PREFIX_SIZE = struct.calcsize(PREFIX_FORMAT)  # exactly 8 bytes

# Allowed wire protocol message types (Section 7.2)
VALID_MESSAGE_TYPES = {
    "CHALLENGE",
    "HELLO",
    "WELCOME",
    "GET_METADATA",
    "METADATA",
    "REQUEST",
    "PIECE",
    "ERROR",
    "BYE",
}

# Standard error codes (Section 7.2)
ERROR_CODES = {
    "AUTH_FAILED",
    "RATE_LIMITED",
    "BUSY",
    "BAD_REQUEST",
    "BAD_INDEX",
    "VERSION",
    "INTERNAL",
}


def pack_message(header: Dict[str, Any], payload: bytes = b"") -> bytes:
    """Serialize a message into its 8-byte length prefix, JSON header, and binary payload.

    Args:
        header: Dictionary containing message fields. Must include 'type'.
        payload: Optional binary payload (e.g. raw piece bytes or canonical metadata).

    Returns:
        Bytes ready for transmission over a TCP socket.

    Raises:
        ProtocolError: If header lacks 'type' or message exceeds size caps.
    """
    if "type" not in header:
        raise ProtocolError("Protocol message header must contain a 'type' field.")

    msg_type = header["type"]
    if msg_type not in VALID_MESSAGE_TYPES:
        raise ProtocolError(f"Unknown message type: {msg_type}")

    try:
        header_bytes = json.dumps(header, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    except (TypeError, ValueError) as err:
        raise ProtocolError(f"Failed to serialize header to JSON: {err}") from err

    header_len = len(header_bytes)
    payload_len = len(payload)

    if header_len > config.MAX_HEADER_BYTES:
        raise ProtocolError(
            f"Header size ({header_len} bytes) exceeds MAX_HEADER_BYTES ({config.MAX_HEADER_BYTES})"
        )

    # Validate payload length according to message type caps
    if msg_type == "PIECE" and payload_len > config.MAX_PIECE_PAYLOAD:
        raise ProtocolError(
            f"PIECE payload ({payload_len} bytes) exceeds MAX_PIECE_PAYLOAD ({config.MAX_PIECE_PAYLOAD})"
        )
    elif msg_type == "METADATA" and payload_len > config.MAX_METADATA_BYTES:
        raise ProtocolError(
            f"METADATA payload ({payload_len} bytes) exceeds MAX_METADATA_BYTES ({config.MAX_METADATA_BYTES})"
        )
    elif msg_type not in ("PIECE", "METADATA") and payload_len > 0:
        raise ProtocolError(f"Message type {msg_type} cannot have a binary payload.")

    prefix = struct.pack(PREFIX_FORMAT, header_len, payload_len)
    return prefix + header_bytes + payload


def unpack_prefix(prefix_bytes: bytes) -> Tuple[int, int]:
    """Parse the 8-byte framing prefix into header and payload lengths.

    Args:
        prefix_bytes: Exactly 8 bytes from socket read.

    Returns:
        Tuple of (header_len, payload_len).

    Raises:
        ProtocolError: If prefix length is invalid.
    """
    if len(prefix_bytes) != PREFIX_SIZE:
        raise ProtocolError(f"Expected {PREFIX_SIZE} bytes for prefix, received {len(prefix_bytes)}")
    header_len, payload_len = struct.unpack(PREFIX_FORMAT, prefix_bytes)
    return header_len, payload_len


def parse_message_bytes(
    raw_bytes: bytes,
    max_payload_len: int = config.MAX_PIECE_PAYLOAD,
) -> Tuple[Dict[str, Any], bytes, int]:
    """Parse a single framed message from a byte buffer.

    Useful for in-memory testing and buffer parsing without an active socket.

    Args:
        raw_bytes: Byte buffer containing at least one framed message.
        max_payload_len: Maximum permitted payload length for the expected message.

    Returns:
        Tuple of (header_dict, payload_bytes, total_bytes_consumed).

    Raises:
        ProtocolError: On framing, size, or JSON violation.
    """
    if len(raw_bytes) < PREFIX_SIZE:
        raise ProtocolError("Buffer too small for message prefix.")

    header_len, payload_len = unpack_prefix(raw_bytes[:PREFIX_SIZE])

    # Pre-allocation bounds check (Section 7.1)
    if header_len > config.MAX_HEADER_BYTES:
        raise ProtocolError(
            f"Header length {header_len} exceeds MAX_HEADER_BYTES ({config.MAX_HEADER_BYTES})"
        )
    if payload_len > max_payload_len:
        raise ProtocolError(
            f"Payload length {payload_len} exceeds permitted cap ({max_payload_len})"
        )

    total_len = PREFIX_SIZE + header_len + payload_len
    if len(raw_bytes) < total_len:
        raise ProtocolError(f"Incomplete message: need {total_len} bytes, have {len(raw_bytes)}")

    header_raw = raw_bytes[PREFIX_SIZE : PREFIX_SIZE + header_len]
    try:
        header = json.loads(header_raw.decode("utf-8"))
    except Exception as err:
        raise ProtocolError(f"Invalid JSON in message header: {err}") from err

    if not isinstance(header, dict) or "type" not in header:
        raise ProtocolError("Header must be a JSON object containing a 'type' field.")

    msg_type = header["type"]
    if msg_type not in VALID_MESSAGE_TYPES:
        raise ProtocolError(f"Unknown message type: {msg_type}")

    payload = raw_bytes[PREFIX_SIZE + header_len : total_len]
    return header, payload, total_len


def _recv_exact(sock: socket.socket, num_bytes: int) -> bytes:
    """Read exactly num_bytes from a TCP stream, looping until complete.

    In TCP, recv() may return fewer bytes than requested depending on network
    fragmentation. This helper guarantees the exact byte count is retrieved.

    Args:
        sock: Connected TCP or SSL socket.
        num_bytes: Number of bytes to read.

    Returns:
        Bytes read.

    Raises:
        ConnectionClosedError: If socket closes before all bytes are received.
    """
    buffer = bytearray()
    while len(buffer) < num_bytes:
        chunk = sock.recv(num_bytes - len(buffer))
        if not chunk:
            raise ConnectionClosedError("Socket closed prematurely while reading data.")
        buffer.extend(chunk)
    return bytes(buffer)


def send_message(sock: socket.socket, header: Dict[str, Any], payload: bytes = b"") -> None:
    """Send a framed message over a socket using sendall.

    Args:
        sock: Connected socket.
        header: Message header dict.
        payload: Optional payload bytes.

    Raises:
        ProtocolError: If packing fails.
        OSError: If socket write fails.
    """
    data = pack_message(header, payload)
    sock.sendall(data)


def recv_message(
    sock: socket.socket,
    max_payload_len: int = config.MAX_PIECE_PAYLOAD,
) -> Tuple[Dict[str, Any], bytes]:
    """Receive a framed message from a socket, enforcing size caps before allocation.

    Args:
        sock: Connected socket.
        max_payload_len: Upper bound on acceptable payload length.

    Returns:
        Tuple of (header_dict, payload_bytes).

    Raises:
        ConnectionClosedError: If connection closed.
        ProtocolError: If size caps exceeded or message malformed.
    """
    # 1. Read the 8-byte prefix
    prefix_bytes = _recv_exact(sock, PREFIX_SIZE)
    header_len, payload_len = unpack_prefix(prefix_bytes)

    # 2. Strict bounds check before reading or allocating payload
    if header_len > config.MAX_HEADER_BYTES:
        raise ProtocolError(
            f"Peer sent header_len={header_len} exceeding limit ({config.MAX_HEADER_BYTES})"
        )
    if payload_len > max_payload_len:
        raise ProtocolError(
            f"Peer sent payload_len={payload_len} exceeding limit ({max_payload_len})"
        )

    # 3. Read header and parse JSON
    header_bytes = _recv_exact(sock, header_len)
    try:
        header = json.loads(header_bytes.decode("utf-8"))
    except Exception as err:
        raise ProtocolError(f"Malformed JSON in header: {err}") from err

    if not isinstance(header, dict) or "type" not in header:
        raise ProtocolError("Header must be a dictionary with 'type' field.")

    msg_type = header["type"]
    if msg_type not in VALID_MESSAGE_TYPES:
        raise ProtocolError(f"Unrecognized message type: {msg_type}")

    # 4. Read payload if present
    payload = _recv_exact(sock, payload_len) if payload_len > 0 else b""
    return header, payload


# Message Builders for Convenience and Consistency
def make_challenge(device_id: str, name: str, nonce: str) -> Dict[str, Any]:
    """Build CHALLENGE message header (Section 7.2)."""
    return {
        "v": config.PROTOCOL_VERSION,
        "type": "CHALLENGE",
        "device_id": device_id,
        "name": name,
        "nonce": nonce,
    }


def make_hello(device_id: str, name: str, role: str, proof: str) -> Dict[str, Any]:
    """Build HELLO message header (Section 7.2)."""
    return {
        "v": config.PROTOCOL_VERSION,
        "type": "HELLO",
        "device_id": device_id,
        "name": name,
        "role": role,
        "proof": proof,
    }


def make_welcome(proof: str, swarm_id: str) -> Dict[str, Any]:
    """Build WELCOME message header (Section 7.2)."""
    return {
        "v": config.PROTOCOL_VERSION,
        "type": "WELCOME",
        "proof": proof,
        "swarm_id": swarm_id,
    }


def make_get_metadata() -> Dict[str, Any]:
    """Build GET_METADATA message header."""
    return {"type": "GET_METADATA"}


def make_metadata_header(swarm_id: str) -> Dict[str, Any]:
    """Build METADATA message header."""
    return {"type": "METADATA", "swarm_id": swarm_id}


def make_request(index: int) -> Dict[str, Any]:
    """Build REQUEST message header."""
    return {"type": "REQUEST", "index": index}


def make_piece_header(index: int, length: int) -> Dict[str, Any]:
    """Build PIECE message header."""
    return {"type": "PIECE", "index": index, "length": length}


def make_error(code: str, message: str) -> Dict[str, Any]:
    """Build ERROR message header."""
    if code not in ERROR_CODES:
        code = "INTERNAL"
    return {"type": "ERROR", "code": code, "message": message}


def make_bye() -> Dict[str, Any]:
    """Build BYE message header."""
    return {"type": "BYE"}
