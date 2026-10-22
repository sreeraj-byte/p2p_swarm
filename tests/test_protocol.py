"""Unit tests for wire protocol framing, bounds enforcement, and message builders.

Covers Section 7.1 and Section 7.2 requirements:
- 8-byte framing prefix (!II)
- JSON header parsing
- Pre-allocation bounds check (MAX_HEADER_BYTES and max payload)
- Message builders
- Handling byte fragmentation and stream reads
"""

import json
import socket
import threading
import pytest

from common.protocol import (
    ConnectionClosedError,
    ProtocolError,
    make_bye,
    make_challenge,
    make_error,
    make_get_metadata,
    make_hello,
    make_metadata_header,
    make_piece_header,
    make_request,
    make_welcome,
    pack_message,
    parse_message_bytes,
    recv_message,
    send_message,
    unpack_prefix,
)
import config


def test_unpack_prefix() -> None:
    """Test 8-byte prefix packing and unpacking."""
    prefix_bytes = (100).to_bytes(4, "big") + (500).to_bytes(4, "big")
    h_len, p_len = unpack_prefix(prefix_bytes)
    assert h_len == 100
    assert p_len == 500


def test_pack_and_parse_roundtrip() -> None:
    """Test standard message serialization and in-memory parsing."""
    header = make_challenge(device_id="abc12345", name="Sender-1", nonce="deadbeef01020304")
    packed = pack_message(header)

    parsed_header, payload, consumed = parse_message_bytes(packed)
    assert parsed_header["type"] == "CHALLENGE"
    assert parsed_header["device_id"] == "abc12345"
    assert parsed_header["nonce"] == "deadbeef01020304"
    assert payload == b""
    assert consumed == len(packed)


def test_pack_and_parse_piece_with_payload() -> None:
    """Test PIECE message with binary payload."""
    test_payload = b"Hello, P2P Swarm piece payload data!" * 10
    header = make_piece_header(index=7, length=len(test_payload))
    packed = pack_message(header, payload=test_payload)

    parsed_header, parsed_payload, consumed = parse_message_bytes(packed)
    assert parsed_header["type"] == "PIECE"
    assert parsed_header["index"] == 7
    assert parsed_header["length"] == len(test_payload)
    assert parsed_payload == test_payload
    assert consumed == len(packed)


def test_reject_oversized_header_before_allocation() -> None:
    """Pre-allocation check: reject messages with header_len > MAX_HEADER_BYTES."""
    huge_header_len = config.MAX_HEADER_BYTES + 1
    fake_prefix = huge_header_len.to_bytes(4, "big") + (0).to_bytes(4, "big")
    with pytest.raises(ProtocolError, match="exceeds MAX_HEADER_BYTES"):
        parse_message_bytes(fake_prefix + b"x" * 20)


def test_reject_oversized_payload_before_allocation() -> None:
    """Pre-allocation check: reject messages with payload_len > max_payload_len."""
    header = {"type": "PIECE", "index": 0, "length": config.MAX_PIECE_PAYLOAD + 10}
    hdr_bytes = json.dumps(header).encode("utf-8")
    oversized_prefix = len(hdr_bytes).to_bytes(4, "big") + (config.MAX_PIECE_PAYLOAD + 10).to_bytes(4, "big")
    buffer = oversized_prefix + hdr_bytes

    with pytest.raises(ProtocolError, match="exceeds permitted cap"):
        parse_message_bytes(buffer, max_payload_len=config.MAX_PIECE_PAYLOAD)


def test_reject_payload_on_disallowed_message_type() -> None:
    """Messages other than PIECE and METADATA must not carry a binary payload."""
    header = make_bye()
    with pytest.raises(ProtocolError, match="cannot have a binary payload"):
        pack_message(header, payload=b"illegal-payload")


def test_reject_unknown_message_type() -> None:
    """Reject messages with unapproved type names."""
    with pytest.raises(ProtocolError, match="Unknown message type"):
        pack_message({"type": "MALICIOUS_TYPE"})


def test_message_builders() -> None:
    """Verify all message builder helpers construct required fields."""
    hello = make_hello("dev1", "Receiver", "receiver", "proof123")
    assert hello["type"] == "HELLO"
    assert hello["proof"] == "proof123"

    welcome = make_welcome("proof456", "swarm99")
    assert welcome["type"] == "WELCOME"
    assert welcome["swarm_id"] == "swarm99"

    get_meta = make_get_metadata()
    assert get_meta["type"] == "GET_METADATA"

    meta_hdr = make_metadata_header("swarm99")
    assert meta_hdr["type"] == "METADATA"

    req = make_request(42)
    assert req["type"] == "REQUEST"
    assert req["index"] == 42

    err = make_error("AUTH_FAILED", "Invalid join code")
    assert err["type"] == "ERROR"
    assert err["code"] == "AUTH_FAILED"


def test_socket_send_recv_roundtrip() -> None:
    """Test live socket transmission over loopback, validating streaming TCP recv."""
    sock_server, sock_client = socket.socketpair()

    try:
        payload = b"Stream chunk data covering TCP packet fragmentation" * 200
        header = make_piece_header(index=1, length=len(payload))

        def client_worker():
            send_message(sock_client, header, payload)

        thread = threading.Thread(target=client_worker)
        thread.start()

        received_header, received_payload = recv_message(sock_server)
        thread.join()

        assert received_header["type"] == "PIECE"
        assert received_header["index"] == 1
        assert received_payload == payload
    finally:
        sock_server.close()
        sock_client.close()


class FakeByteByByteSocket:
    """Mock socket that yields at most one byte per recv() call to simulate extreme TCP fragmentation."""

    def __init__(self, data: bytes) -> None:
        self._data = bytearray(data)

    def recv(self, num_bytes: int) -> bytes:
        if not self._data:
            return b""
        # Return at most 1 byte regardless of num_bytes requested
        byte = bytes([self._data.pop(0)])
        return byte


class FakeSocketWithCutoff:
    """Mock socket that closes (returns b'') after delivering a specified number of bytes."""

    def __init__(self, data: bytes, cutoff: int) -> None:
        self._data = bytearray(data[:cutoff])

    def recv(self, num_bytes: int) -> bytes:
        if not self._data:
            return b""
        to_send = min(num_bytes, len(self._data))
        chunk = bytes(self._data[:to_send])
        del self._data[:to_send]
        return chunk


def test_recv_message_byte_by_byte() -> None:
    """Protocol test: fake socket delivering exactly one byte at a time must be reassembled properly."""
    payload = b"SingleByteByByteDeliveryVerification" * 5
    header = make_piece_header(index=3, length=len(payload))
    wire_data = pack_message(header, payload)

    fake_sock = FakeByteByByteSocket(wire_data)
    hdr, pld = recv_message(fake_sock)

    assert hdr["type"] == "PIECE"
    assert hdr["index"] == 3
    assert pld == payload


def test_recv_message_closed_mid_message() -> None:
    """Protocol test: connection closing mid-message must raise ConnectionClosedError."""
    header = make_challenge(device_id="dev123", name="test", nonce="abcd" * 8)
    wire_data = pack_message(header)

    # Cut off stream halfway through the header
    halfway = len(wire_data) // 2
    fake_sock = FakeSocketWithCutoff(wire_data, cutoff=halfway)

    with pytest.raises(ConnectionClosedError, match="Socket closed prematurely"):
        recv_message(fake_sock)


def test_recv_message_invalid_json_header() -> None:
    """Protocol test: header containing invalid JSON must raise ProtocolError."""
    bad_header_raw = b"{not: valid json at all!"
    prefix = len(bad_header_raw).to_bytes(4, "big") + (0).to_bytes(4, "big")
    wire_data = prefix + bad_header_raw

    fake_sock = FakeByteByByteSocket(wire_data)
    with pytest.raises(ProtocolError, match="Malformed JSON in header"):
        recv_message(fake_sock)


def test_recv_message_non_object_header() -> None:
    """Protocol test: header that is valid JSON but not a JSON object must raise ProtocolError."""
    # JSON list instead of JSON dictionary object
    bad_header_raw = json.dumps([1, 2, 3]).encode("utf-8")
    prefix = len(bad_header_raw).to_bytes(4, "big") + (0).to_bytes(4, "big")
    wire_data = prefix + bad_header_raw

    fake_sock = FakeByteByByteSocket(wire_data)
    with pytest.raises(ProtocolError, match="Header must be a dictionary"):
        recv_message(fake_sock)
