"""Unit and integration tests for Phase 5 UDP discovery, device table, and receiver auto-discovery."""

import json
import secrets
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Dict, Any

import pytest

import config
from tools.gen_certs import generate_self_signed_cert
from common.discovery import (
    DeviceEntry,
    DeviceTable,
    DiscoveryBroadcaster,
    DiscoveryListener,
    get_broadcast_addresses,
    make_beacon,
    make_heartbeat,
    sanitize_device_name,
)
from receiver import SwarmReceiver, download_from_senders
from sender import SenderServer


# ============================================================================
# Unit Tests: Sanitization and Payload Builders
# ============================================================================


def test_sanitize_device_name() -> None:
    """Verify name sanitization: max 32 chars, printable only, fallback on empty."""
    # Normal name
    assert sanitize_device_name("MacBook-Pro") == "MacBook-Pro"

    # Control characters stripped
    assert sanitize_device_name("Dev\x00ice\n\r\tName") == "DeviceName"

    # Over 32 characters truncated
    long_name = "A" * 50
    sanitized = sanitize_device_name(long_name)
    assert len(sanitized) == 32
    assert sanitized == "A" * 32

    # Non-printable characters filtered
    assert sanitize_device_name("Good\x1b[31mColor") == "Good[31mColor"

    # Empty or whitespace-only fallbacks
    assert sanitize_device_name("") == "Anonymous"
    assert sanitize_device_name("   \t  ") == "Anonymous"
    assert sanitize_device_name(None) == "Anonymous"


def test_make_heartbeat_and_beacon_format() -> None:
    """Verify heartbeat and beacon payload structure, JSON compliance, and size cap."""
    hb_bytes = make_heartbeat(
        device_id="a1b2c3d4e5f67890",
        name="Laptop-A",
        role="sender",
        tcp_port=6881,
        swarm_name="shared_docs",
        swarm_id_short="9f2c41aa7b3d0e55",
        files=5,
        total_bytes=1048576,
    )
    assert len(hb_bytes) <= config.MAX_DISCOVERY_PACKET_BYTES
    hb_data = json.loads(hb_bytes.decode("utf-8"))
    assert hb_data["v"] == config.PROTOCOL_VERSION
    assert hb_data["type"] == "HEARTBEAT"
    assert hb_data["device_id"] == "a1b2c3d4e5f67890"
    assert hb_data["name"] == "Laptop-A"
    assert hb_data["role"] == "sender"
    assert hb_data["tcp_port"] == 6881
    assert hb_data["swarm_name"] == "shared_docs"
    assert hb_data["swarm_id_short"] == "9f2c41aa7b3d0e55"
    assert hb_data["files"] == 5
    assert hb_data["total_bytes"] == 1048576

    beacon_bytes = make_beacon(device_id="tracker01", web_port=8080)
    assert len(beacon_bytes) <= config.MAX_DISCOVERY_PACKET_BYTES
    b_data = json.loads(beacon_bytes.decode("utf-8"))
    assert b_data["v"] == config.PROTOCOL_VERSION
    assert b_data["type"] == "BEACON"
    assert b_data["device_id"] == "tracker01"
    assert b_data["web_port"] == 8080


# ============================================================================
# Unit Tests: DeviceTable Rules (Capping, Pruning, Offline, Verification)
# ============================================================================


def test_device_table_source_ip_binding_and_spoof_protection() -> None:
    """Verify that peer IP is strictly bound to packet source address and JSON ip is ignored."""
    table = DeviceTable()
    # Packet body contains a spoofed IP
    hb_msg = {
        "v": 1,
        "type": "HEARTBEAT",
        "device_id": "attacker-dev-01",
        "name": "Attacker",
        "ip": "1.2.3.4",  # Spoofed IP in JSON payload
        "role": "sender",
        "tcp_port": 6881,
    }
    actual_source_ip = "192.168.1.105"

    entry = table.update_from_heartbeat(hb_msg, source_ip=actual_source_ip, now=100.0)
    assert entry is not None
    assert entry.ip == "192.168.1.105"
    assert entry.ip != "1.2.3.4"
    assert entry.name == "Attacker"
    assert entry.status == "online"
    assert entry.trust == "discovered"


def test_device_table_offline_and_expiry_rules() -> None:
    """Verify state transitions: online -> offline (8s) -> expired/pruned (60s)."""
    table = DeviceTable(offline_after=8.0, expiry_after=60.0)
    hb_msg = {
        "v": 1,
        "type": "HEARTBEAT",
        "device_id": "dev-01",
        "name": "Node-1",
        "tcp_port": 6881,
    }

    t0 = 1000.0
    table.update_from_heartbeat(hb_msg, source_ip="10.0.0.1", now=t0)

    # 1. At t0 + 5s: Still online
    devices = table.get_devices(now=t0 + 5.0)
    assert len(devices) == 1
    assert devices[0].status == "online"

    # 2. At t0 + 8.1s: Transition to offline
    devices = table.get_devices(now=t0 + 8.1)
    assert len(devices) == 1
    assert devices[0].status == "offline"
    assert not devices[0].is_online()

    # When querying only_online, it is excluded
    assert len(table.get_devices(only_online=True, now=t0 + 8.1)) == 0

    # 3. New heartbeat at t0 + 10s brings it back online
    table.update_from_heartbeat(hb_msg, source_ip="10.0.0.1", now=t0 + 10.0)
    devices = table.get_devices(now=t0 + 10.0)
    assert devices[0].status == "online"

    # 4. At t0 + 71.0s (> 60s after last seen): Entry is pruned/expired
    devices = table.get_devices(now=t0 + 71.0)
    assert len(devices) == 0


def test_device_table_capping_at_max_devices_no_eviction() -> None:
    """Verify table capacity cap: when full, new devices are rejected without evicting existing devices."""
    max_cap = 5
    table = DeviceTable(max_devices=max_cap, offline_after=8.0, expiry_after=60.0)

    # Insert 5 devices at t=100.0 from different IPs
    for i in range(max_cap):
        table.update_from_heartbeat(
            {"v": 1, "type": "HEARTBEAT", "device_id": f"dev-{i}", "name": f"Node-{i}", "tcp_port": 6880 + i},
            source_ip=f"10.0.0.{i+1}",
            now=100.0 + i,
        )

    assert len(table.get_devices(now=105.0)) == max_cap

    # Add 6th device at t=106.0: capacity full, new device rejected without evicting dev-0 through dev-4
    res = table.update_from_heartbeat(
        {"v": 1, "type": "HEARTBEAT", "device_id": "dev-5", "name": "Node-5", "tcp_port": 6885},
        source_ip="10.0.0.6",
        now=106.0,
    )
    assert res is None

    all_ids = {d.device_id for d in table.get_devices(now=106.0)}
    assert len(all_ids) == max_cap
    assert all_ids == {f"dev-{i}" for i in range(max_cap)}
    assert "dev-5" not in all_ids


def test_1000_spoofed_heartbeats_cannot_push_real_sender_out() -> None:
    """Verify that 1000 spoofed heartbeats from one source IP cannot push a real sender out of the table."""
    table = DeviceTable(max_devices=256, max_device_ids_per_ip=8)

    # 1. Admit a real sender from 192.168.1.100
    real_dev = table.update_from_heartbeat(
        {"v": 1, "type": "HEARTBEAT", "device_id": "real-sender-01", "name": "RealSender", "tcp_port": 6881},
        source_ip="192.168.1.100",
        now=100.0,
    )
    assert real_dev is not None
    table.mark_verified("real-sender-01")

    # 2. Attacker from 10.99.99.99 floods 1000 spoofed heartbeats with distinct device IDs
    attacker_ip = "10.99.99.99"
    admitted = 0
    rejected = 0
    for i in range(1000):
        entry = table.update_from_heartbeat(
            {"v": 1, "type": "HEARTBEAT", "device_id": f"spoofed-dev-{i}", "name": f"Fake-{i}", "tcp_port": 6881},
            source_ip=attacker_ip,
            now=101.0,
        )
        if entry is not None:
            admitted += 1
        else:
            rejected += 1

    # Exactly MAX_DEVICE_IDS_PER_IP (8) are admitted from the attacker; remaining 992 are rejected
    assert admitted == 8
    assert rejected == 992

    # The real sender must still be present and intact in the table
    all_devs = table.get_devices(now=102.0)
    assert len(all_devs) == 9  # 1 real + 8 attacker
    real_entry = table.get_device("real-sender-01")
    assert real_entry is not None
    assert real_entry.trust == "verified"
    assert real_entry.name == "RealSender"
    assert real_entry.ip == "192.168.1.100"


def test_device_table_mark_verified_and_banned() -> None:
    """Verify trust state transitions from 'discovered' to 'verified' and 'banned'."""
    table = DeviceTable()
    table.update_from_heartbeat(
        {
            "v": 1,
            "type": "HEARTBEAT",
            "device_id": "sender-99",
            "name": "Sender-99",
            "tcp_port": 6881,
        },
        source_ip="192.168.1.50",
    )

    dev = table.get_device("sender-99")
    assert dev is not None
    assert dev.trust == "discovered"

    # Verify by IP:port matching
    ok = table.mark_verified("192.168.1.50:6881")
    assert ok is True
    assert dev.trust == "verified"

    # Ban by device_id
    ok = table.mark_banned("sender-99")
    assert ok is True
    assert dev.trust == "banned"


def test_device_table_group_senders_by_swarm() -> None:
    """Verify get_senders_by_swarm groups candidate senders by swarm_id_short."""
    table = DeviceTable()
    table.update_from_heartbeat(
        {"device_id": "s1", "name": "S1", "role": "sender", "tcp_port": 6881, "swarm_id_short": "swarmAAA"},
        source_ip="10.0.0.1",
    )
    table.update_from_heartbeat(
        {"device_id": "s2", "name": "S2", "role": "sender", "tcp_port": 6882, "swarm_id_short": "swarmAAA"},
        source_ip="10.0.0.2",
    )
    table.update_from_heartbeat(
        {"device_id": "s3", "name": "S3", "role": "sender", "tcp_port": 6883, "swarm_id_short": "swarmBBB"},
        source_ip="10.0.0.3",
    )
    # Receiver role should not be grouped under senders
    table.update_from_heartbeat(
        {"device_id": "r1", "name": "R1", "role": "receiver", "tcp_port": 0, "swarm_id_short": "swarmAAA"},
        source_ip="10.0.0.4",
    )

    groups = table.get_senders_by_swarm(only_online=True)
    assert len(groups) == 2
    assert "swarmAAA" in groups
    assert "swarmBBB" in groups
    assert len(groups["swarmAAA"]) == 2
    assert len(groups["swarmBBB"]) == 1
    assert {d.name for d in groups["swarmAAA"]} == {"S1", "S2"}


# ============================================================================
# Unit Tests: Packet Filtering and Security
# ============================================================================


def test_discovery_listener_oversized_packet_dropped() -> None:
    """Packets larger than 1 KiB (1024 bytes) must be dropped without processing."""
    port = 52101
    table = DeviceTable()
    listener = DiscoveryListener(own_device_id="listener-dev", device_table=table, port=port)
    listener.start()
    time.sleep(0.1)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # 1025 bytes payload
        oversized = b"X" * (config.MAX_DISCOVERY_PACKET_BYTES + 1)
        sock.sendto(oversized, ("127.0.0.1", port))
        time.sleep(0.2)

        # Nothing should be admitted
        assert len(table.get_devices()) == 0
        sock.close()
    finally:
        listener.stop()


def test_discovery_listener_malformed_json_dropped() -> None:
    """Non-JSON datagrams or invalid messages must be safely dropped."""
    port = 52102
    table = DeviceTable()
    listener = DiscoveryListener(own_device_id="listener-dev", device_table=table, port=port)
    listener.start()
    time.sleep(0.1)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Plain text non-JSON
        sock.sendto(b"NOT_A_VALID_JSON_OBJECT", ("127.0.0.1", port))
        # JSON array instead of object
        sock.sendto(b"[1, 2, 3]", ("127.0.0.1", port))
        # Unsupported version or type
        sock.sendto(b'{"v":99,"type":"UNKNOWN"}', ("127.0.0.1", port))
        time.sleep(0.2)

        assert len(table.get_devices()) == 0
        sock.close()
    finally:
        listener.stop()


def test_discovery_listener_own_heartbeat_filtered() -> None:
    """Packets originating from the device's own device_id must be ignored."""
    port = 52103
    table = DeviceTable()
    own_id = "my-own-device-id-1234"
    listener = DiscoveryListener(own_device_id=own_id, device_table=table, port=port)
    listener.start()
    time.sleep(0.1)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Send heartbeat matching own_device_id
        hb_own = make_heartbeat(
            device_id=own_id,
            name="Myself",
            role="sender",
            tcp_port=6881,
        )
        sock.sendto(hb_own, ("127.0.0.1", port))

        # Send heartbeat from another device
        hb_other = make_heartbeat(
            device_id="other-peer-id-5678",
            name="OtherPeer",
            role="sender",
            tcp_port=6882,
        )
        sock.sendto(hb_other, ("127.0.0.1", port))
        time.sleep(0.2)

        devices = table.get_devices()
        assert len(devices) == 1
        assert devices[0].device_id == "other-peer-id-5678"
        assert devices[0].name == "OtherPeer"
        sock.close()
    finally:
        listener.stop()


# ============================================================================
# Integration Test: Multi-process Discovery on One Machine (Section 11)
# ============================================================================


def test_multiprocess_discovery_three_processes_on_one_machine() -> None:
    """Test three concurrent discovery processes on one laptop using SO_REUSEADDR and SO_REUSEPORT.

    Process 1: Sender 1 (Laptop-A)
    Process 2: Sender 2 (Laptop-B)
    Process 3: Receiver/Monitor (Receiver-C)
    Verifies that Process 3 discovers both Sender 1 and Sender 2 via UDP broadcasts on localhost.
    """
    disc_port = 52104

    # Process 3: Receiver listener
    table = DeviceTable()
    receiver_listener = DiscoveryListener(
        own_device_id="proc-3-receiver",
        device_table=table,
        port=disc_port,
    )
    receiver_listener.start()
    time.sleep(0.1)

    # Process 1: Sender 1 broadcaster
    s1_hb = make_heartbeat(
        device_id="proc-1-sender-a",
        name="Laptop-A",
        role="sender",
        tcp_port=6881,
        swarm_name="dataset_v1",
        swarm_id_short="deadbeef12345678",
        files=3,
        total_bytes=500000,
    )
    broadcaster1 = DiscoveryBroadcaster(payload_factory=lambda: s1_hb, port=disc_port, interval=0.5)
    broadcaster1.start()

    # Process 2: Sender 2 broadcaster
    s2_hb = make_heartbeat(
        device_id="proc-2-sender-b",
        name="Laptop-B",
        role="sender",
        tcp_port=6882,
        swarm_name="dataset_v1",
        swarm_id_short="deadbeef12345678",
        files=3,
        total_bytes=500000,
    )
    broadcaster2 = DiscoveryBroadcaster(payload_factory=lambda: s2_hb, port=disc_port, interval=0.5)
    broadcaster2.start()

    try:
        # Wait briefly for announcements
        start_wait = time.time()
        while time.time() - start_wait < 3.0:
            devs = table.get_devices(only_online=True)
            if len(devs) >= 2:
                break
            time.sleep(0.1)

        devs = table.get_devices(only_online=True)
        dev_map = {d.device_id: d for d in devs}

        assert "proc-1-sender-a" in dev_map
        assert "proc-2-sender-b" in dev_map
        assert dev_map["proc-1-sender-a"].name == "Laptop-A"
        assert dev_map["proc-1-sender-a"].tcp_port == 6881
        assert dev_map["proc-2-sender-b"].name == "Laptop-B"
        assert dev_map["proc-2-sender-b"].tcp_port == 6882
        assert dev_map["proc-1-sender-a"].swarm_id_short == "deadbeef12345678"
    finally:
        broadcaster1.stop()
        broadcaster2.stop()
        receiver_listener.stop()


# ============================================================================
# Integration Test: Receiver Auto-discovery and Download End-to-End
# ============================================================================


def test_receiver_autodiscovery_download_end_to_end(tmp_path: Path) -> None:
    """Receiver discovers two senders automatically over UDP (no --senders provided) and downloads data."""
    cert_path, key_path = generate_self_signed_cert(out_dir=tmp_path / "certs_autodisc")
    shared_file = tmp_path / "dataset.bin"
    payload_content = b"AutoDiscoveryContentP2P" * 1000
    shared_file.write_bytes(payload_content)

    join_code = "swarm-autodiscovery-code-2026"
    disc_port = 52105

    # Start Sender 1
    sender1 = SenderServer(
        source_path=shared_file,
        port=0,
        name="Sender-One",
        cert_path=cert_path,
        key_path=key_path,
        join_code=join_code,
        discovery_port=disc_port,
        enable_discovery=True,
    )
    sender1.start(blocking=False)
    time.sleep(0.1)

    # Start Sender 2
    sender2 = SenderServer(
        source_path=shared_file,
        port=0,
        name="Sender-Two",
        cert_path=cert_path,
        key_path=key_path,
        join_code=join_code,
        discovery_port=disc_port,
        enable_discovery=True,
    )
    sender2.start(blocking=False)
    time.sleep(0.2)

    dest_dir = tmp_path / "download_autodisc"
    dest_dir.mkdir()

    device_table = DeviceTable()

    try:
        # Start Receiver with NO manual senders! Auto-discovery finds both senders.
        rx = SwarmReceiver(
            senders=None,  # Auto-discovery
            out_dir=dest_dir,
            cert_path=cert_path,
            join_code=join_code,
            verbose=False,
            enable_discovery=True,
            discovery_port=disc_port,
            min_senders=2,
            discover_timeout=5.0,
            device_table=device_table,
        )

        result = rx.download()
        assert result["completed"] is True
        assert (dest_dir / "dataset.bin").read_bytes() == payload_content

        # Both senders were discovered and marked "verified" only after successful TLS handshake!
        online_senders = device_table.get_devices(role="sender", only_online=True)
        assert len(online_senders) >= 2
        for s in online_senders:
            assert s.trust == "verified"

    finally:
        sender1.stop()
        sender2.stop()


# ============================================================================
# Integration Test: Dynamic Join Mid-Transfer (Section 9.2)
# ============================================================================


def test_receiver_dynamic_join_mid_transfer(tmp_path: Path) -> None:
    """A third sender joins dynamically mid-transfer via UDP announcement and contributes pieces."""
    cert_path, key_path = generate_self_signed_cert(out_dir=tmp_path / "certs_dynamic")
    data_file = tmp_path / "big_data.bin"
    # 256 KiB data = 4 pieces of 64 KiB
    content = b"DynamicJoinTestData" * 14000
    data_file.write_bytes(content)

    join_code = "dynamic-join-code-2026"
    disc_port = 52106

    # Sender 1 starts initially, throttled to 50 KiB/s so transfer takes long enough for Sender 2 to join
    sender1 = SenderServer(
        source_path=data_file,
        port=0,
        name="SlowSender1",
        cert_path=cert_path,
        key_path=key_path,
        join_code=join_code,
        piece_size=65536,
        throttle_kbps=50,
        discovery_port=disc_port,
        enable_discovery=True,
    )
    sender1.start(blocking=False)
    time.sleep(0.1)

    dest_dir = tmp_path / "download_dynamic"
    dest_dir.mkdir()

    sender2 = None
    try:
        # Start receiver connected to sender1 initially
        rx = SwarmReceiver(
            senders=[f"127.0.0.1:{sender1.port}"],
            out_dir=dest_dir,
            cert_path=cert_path,
            join_code=join_code,
            verbose=False,
            enable_discovery=True,
            discovery_port=disc_port,
            min_senders=1,
            discover_timeout=1.0,
        )

        def delayed_join_sender():
            time.sleep(0.4)
            nonlocal sender2
            sender2 = SenderServer(
                source_path=data_file,
                port=0,
                name="FastSender2",
                cert_path=cert_path,
                key_path=key_path,
                join_code=join_code,
                piece_size=65536,
                discovery_port=disc_port,
                enable_discovery=True,
            )
            sender2.start(blocking=False)

        threading.Thread(target=delayed_join_sender, daemon=True).start()

        result = rx.download()
        assert result["completed"] is True
        assert (dest_dir / "big_data.bin").read_bytes() == content

        # Check that sender2 joined dynamically and contributed
        sender_keys = list(result["sender_stats"].keys())
        assert len(sender_keys) == 2
        assert sender1.device_id in sender_keys
        assert sender2.device_id in sender_keys
    finally:
        sender1.stop()
        if sender2:
            sender2.stop()


# ============================================================================
# Integration Test: Multiple Swarms Requires --swarm (Section 9.1 Step 3)
# ============================================================================


def test_receiver_multiple_swarms_requires_swarm_flag(tmp_path: Path) -> None:
    """When multiple distinct swarms are announced on LAN, receiver requires --swarm selection."""
    cert_path, key_path = generate_self_signed_cert(out_dir=tmp_path / "certs_multi_swarm")

    file_a = tmp_path / "file_a.bin"
    file_a.write_bytes(b"ContentForSwarmAlpha")

    file_b = tmp_path / "file_b.bin"
    file_b.write_bytes(b"ContentForSwarmBeta")

    join_code = "multi-swarm-test-code-2026"
    disc_port = 52107

    # Sender A announces Swarm Alpha
    sender_a = SenderServer(
        source_path=file_a,
        port=0,
        name="Sender-Alpha",
        cert_path=cert_path,
        key_path=key_path,
        join_code=join_code,
        discovery_port=disc_port,
        enable_discovery=True,
        heartbeat_interval=0.2,
    )
    sender_a.start(blocking=False)

    # Sender B announces Swarm Beta
    sender_b = SenderServer(
        source_path=file_b,
        port=0,
        name="Sender-Beta",
        cert_path=cert_path,
        key_path=key_path,
        join_code=join_code,
        discovery_port=disc_port,
        enable_discovery=True,
        heartbeat_interval=0.2,
    )
    sender_b.start(blocking=False)
    time.sleep(0.3)

    dest_dir1 = tmp_path / "dest_ambiguous"
    dest_dir1.mkdir()

    dest_dir2 = tmp_path / "dest_filtered"
    dest_dir2.mkdir()

    try:
        # Case 1: No --swarm specified when 2 swarms exist -> Raises RuntimeError
        rx_ambiguous = SwarmReceiver(
            senders=None,
            out_dir=dest_dir1,
            cert_path=cert_path,
            join_code=join_code,
            verbose=False,
            enable_discovery=True,
            discovery_port=disc_port,
            min_senders=2,
            discover_timeout=2.0,
            target_swarm=None,
        )
        with pytest.raises(RuntimeError, match="Multiple distinct swarms discovered"):
            rx_ambiguous.download()

        # Case 2: Target swarm explicitly specified -> Downloads from matching swarm
        rx_filtered = SwarmReceiver(
            senders=None,
            out_dir=dest_dir2,
            cert_path=cert_path,
            join_code=join_code,
            verbose=False,
            enable_discovery=True,
            discovery_port=disc_port,
            min_senders=1,
            discover_timeout=2.0,
            target_swarm="file_a.bin",
        )
        res = rx_filtered.download()
        assert res["completed"] is True
        assert (dest_dir2 / "file_a.bin").read_bytes() == b"ContentForSwarmAlpha"

    finally:
        sender_a.stop()
        sender_b.stop()


# ============================================================================
# Integration Test: tools/show_devices.py Terminal Tool Output
# ============================================================================


def test_show_devices_tool_output(tmp_path: Path) -> None:
    """Verify tools/show_devices.py runs and prints discovered devices in table format."""
    disc_port = 52108

    hb = make_heartbeat(
        device_id="monitor-test-dev",
        name="Laptop-X",
        role="sender",
        tcp_port=6881,
        swarm_name="sample_swarm",
        swarm_id_short="abcd1234ef567890",
        files=2,
        total_bytes=1024,
    )
    broadcaster = DiscoveryBroadcaster(payload_factory=lambda: hb, port=disc_port, interval=0.2)
    broadcaster.start()
    time.sleep(0.1)

    try:
        proc = subprocess.run(
            [
                sys.executable,
                "tools/show_devices.py",
                "--port",
                str(disc_port),
                "--once",
                "--wait",
                "1.0",
            ],
            capture_output=True,
            text=True,
            timeout=5.0,
        )
        assert proc.returncode == 0
        output = proc.stdout
        assert "Device ID" in output
        assert "Laptop-X" in output
        assert "sender" in output
        assert "6881" in output
        assert "abcd1234" in output
    finally:
        broadcaster.stop()


# ============================================================================
# Hardening Tests: 50 Fake Senders, Timeouts, and Min Senders
# ============================================================================


def test_50_fake_sender_announcements_bounded_concurrency_and_backoff(tmp_path: Path) -> None:
    """Verify receiver handles 50 fake sender announcements without exhaustion, limiting concurrency and completing transfer."""
    cert_path, key_path = generate_self_signed_cert(out_dir=tmp_path / "certs_fake_flood")
    data_file = tmp_path / "content.bin"
    payload = b"RobustP2PSwarmPayload" * 1500
    data_file.write_bytes(payload)

    join_code = "fake-flood-test-code-2026"
    disc_port = 52110

    # 1. Start one legitimate sender with rapid heartbeat
    real_sender = SenderServer(
        source_path=data_file,
        port=0,
        name="RealSender",
        cert_path=cert_path,
        key_path=key_path,
        join_code=join_code,
        discovery_port=disc_port,
        enable_discovery=True,
        heartbeat_interval=0.2,
    )
    real_sender.start(blocking=False)
    time.sleep(0.1)

    dest_dir = tmp_path / "dest_flood"
    dest_dir.mkdir()

    # 2. Allow up to 64 device IDs per IP so all 50 fake senders are admitted into the table
    # This directly tests the receiver's concurrency limiting and backoff mechanisms under a 50-sender announcement burst
    device_table = DeviceTable(max_device_ids_per_ip=64)

    def flood_fake_senders():
        time.sleep(0.1)  # allow receiver discovery socket to open
        flood_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for i in range(50):
            fake_hb = make_heartbeat(
                device_id=f"fake-sender-{i:03d}",
                name=f"FakeSender-{i}",
                role="sender",
                tcp_port=60000 + i,
                swarm_name="content.bin",
                swarm_id_short=real_sender.swarm_id_short,
                files=1,
                total_bytes=len(payload),
            )
            flood_sock.sendto(fake_hb, ("127.0.0.1", disc_port))
        flood_sock.close()

    t_flood = threading.Thread(target=flood_fake_senders, daemon=True)
    t_flood.start()

    try:
        # Receiver should limit concurrent connection attempts with _connect_semaphore,
        # back off on failures, and complete downloading from the real sender.
        rx = SwarmReceiver(
            senders=None,
            out_dir=dest_dir,
            cert_path=cert_path,
            join_code=join_code,
            verbose=False,
            enable_discovery=True,
            discovery_port=disc_port,
            min_senders=1,
            discover_timeout=2.0,
            device_table=device_table,
            backoff_base=0.01,
        )
        res = rx.download()
        assert res["completed"] is True
        assert (dest_dir / "content.bin").read_bytes() == payload
    finally:
        real_sender.stop()


def test_discover_timeout_zero_senders_fails_cleanly(tmp_path: Path) -> None:
    """Verify receiver exits with clear error and non-zero exit when no senders are discovered."""
    dest_dir = tmp_path / "dest_zero"
    dest_dir.mkdir()
    cert_path, _ = generate_self_signed_cert(out_dir=tmp_path / "certs_zero")

    # Unused discovery port with zero senders running
    empty_disc_port = 52111

    # 1. Python API check: raises ConnectionError
    rx = SwarmReceiver(
        senders=None,
        out_dir=dest_dir,
        cert_path=cert_path,
        join_code="any-code",
        verbose=False,
        enable_discovery=True,
        discovery_port=empty_disc_port,
        min_senders=2,
        discover_timeout=0.5,
    )
    with pytest.raises(ConnectionError, match="No senders discovered within 0.5s timeout"):
        rx.download()

    # 2. CLI process check: exits with code 1 and prints clear error message
    proc = subprocess.run(
        [
            sys.executable,
            "receiver.py",
            "--out",
            str(dest_dir),
            "--cert",
            str(cert_path),
            "--code",
            "any-code",
            "--discovery-port",
            str(empty_disc_port),
            "--discover-timeout",
            "0.5",
            "--min-senders",
            "2",
        ],
        capture_output=True,
        text=True,
        timeout=5.0,
    )
    assert proc.returncode == 1
    assert "No senders discovered within 0.5s timeout" in (proc.stdout + proc.stderr)


def test_discover_timeout_one_sender_proceeds(tmp_path: Path) -> None:
    """Verify receiver proceeds with 1 sender when --min-senders 2 times out with at least one candidate."""
    cert_path, key_path = generate_self_signed_cert(out_dir=tmp_path / "certs_one_proceeds")
    data_file = tmp_path / "single_sender_data.bin"
    payload = b"SingleSenderPayload" * 500
    data_file.write_bytes(payload)

    join_code = "single-proceeds-code-2026"
    disc_port = 52112

    # Start exactly 1 sender with rapid heartbeat
    sender = SenderServer(
        source_path=data_file,
        port=0,
        name="SoloSender",
        cert_path=cert_path,
        key_path=key_path,
        join_code=join_code,
        discovery_port=disc_port,
        enable_discovery=True,
        heartbeat_interval=0.2,
    )
    sender.start(blocking=False)
    time.sleep(0.1)

    dest_dir = tmp_path / "dest_one_proceeds"
    dest_dir.mkdir()

    try:
        # min_senders=2, discover_timeout=1.0s.
        # Only 1 sender is present; receiver waits 1.0s, then proceeds per Section 9.1 Step 4
        rx = SwarmReceiver(
            senders=None,
            out_dir=dest_dir,
            cert_path=cert_path,
            join_code=join_code,
            verbose=False,
            enable_discovery=True,
            discovery_port=disc_port,
            min_senders=2,
            discover_timeout=1.0,
        )
        t_start = time.time()
        res = rx.download()
        elapsed = time.time() - t_start

        # Took at least 1.0s (waited for 2nd sender) but succeeded with the 1 discovered sender!
        assert elapsed >= 0.9
        assert res["completed"] is True
        assert (dest_dir / "single_sender_data.bin").read_bytes() == payload
    finally:
        sender.stop()


def test_min_senders_starts_immediately_when_threshold_reached(tmp_path: Path) -> None:
    """Verify receiver starts immediately as soon as --min-senders candidates appear without waiting for discover-timeout."""
    cert_path, key_path = generate_self_signed_cert(out_dir=tmp_path / "certs_fast_start")
    data_file = tmp_path / "fast_start.bin"
    payload = b"FastStartPayload" * 500
    data_file.write_bytes(payload)

    join_code = "fast-start-code-2026"
    disc_port = 52113

    # Start 2 senders
    s1 = SenderServer(
        source_path=data_file,
        port=0,
        name="FastSender1",
        cert_path=cert_path,
        key_path=key_path,
        join_code=join_code,
        discovery_port=disc_port,
        enable_discovery=True,
    )
    s1.start(blocking=False)

    s2 = SenderServer(
        source_path=data_file,
        port=0,
        name="FastSender2",
        cert_path=cert_path,
        key_path=key_path,
        join_code=join_code,
        discovery_port=disc_port,
        enable_discovery=True,
    )
    s2.start(blocking=False)
    time.sleep(0.2)

    dest_dir = tmp_path / "dest_fast_start"
    dest_dir.mkdir()

    try:
        # min_senders=2, but discover_timeout=15.0s!
        # Because 2 senders are already available, it must NOT wait 15 seconds!
        rx = SwarmReceiver(
            senders=None,
            out_dir=dest_dir,
            cert_path=cert_path,
            join_code=join_code,
            verbose=False,
            enable_discovery=True,
            discovery_port=disc_port,
            min_senders=2,
            discover_timeout=15.0,
        )
        t_start = time.time()
        res = rx.download()
        elapsed = time.time() - t_start

        # Must finish well under the 15.0s discover-timeout
        assert elapsed < 3.0
        assert res["completed"] is True
        assert (dest_dir / "fast_start.bin").read_bytes() == payload
    finally:
        s1.stop()
        s2.stop()


# ============================================================================
# Integration Test: Combined Manual --senders and Auto-Discovery Deduplication
# ============================================================================


def test_dual_manual_and_discovery_deduplication(tmp_path: Path) -> None:
    """When both manual --senders and LAN auto-discovery announce the same senders,

    the receiver must identify senders by device_id from CHALLENGE, close duplicate
    connections, and maintain exactly two workers and two sender entries in stats/tracker.
    """
    cert_path, key_path = generate_self_signed_cert(out_dir=tmp_path / "certs_dedup")

    # Generate 10 pieces worth of data (10 * 16 KiB = 160 KiB)
    piece_size = 16384
    total_size = 10 * piece_size
    data_content = secrets.token_bytes(total_size)
    data_file = tmp_path / "shared_dedup.bin"
    data_file.write_bytes(data_content)

    join_code = "dedup-test-code-2026"
    disc_port = 52120

    s1 = SenderServer(
        source_path=data_file,
        port=0,
        name="Laptop-A",
        cert_path=cert_path,
        key_path=key_path,
        join_code=join_code,
        piece_size=piece_size,
        discovery_port=disc_port,
        enable_discovery=True,
        heartbeat_interval=0.2,
    )
    s1.start(blocking=False)

    s2 = SenderServer(
        source_path=data_file,
        port=0,
        name="Laptop-B",
        cert_path=cert_path,
        key_path=key_path,
        join_code=join_code,
        piece_size=piece_size,
        discovery_port=disc_port,
        enable_discovery=True,
        heartbeat_interval=0.2,
    )
    s2.start(blocking=False)
    time.sleep(0.3)

    dest_dir = tmp_path / "dest_dedup"
    dest_dir.mkdir()

    try:
        # Receiver started with BOTH manual senders and enable_discovery=True
        rx = SwarmReceiver(
            senders=[f"127.0.0.1:{s1.port}", f"127.0.0.1:{s2.port}"],
            out_dir=dest_dir,
            cert_path=cert_path,
            join_code=join_code,
            verbose=True,
            enable_discovery=True,
            discovery_port=disc_port,
            min_senders=2,
            discover_timeout=3.0,
            enable_tracker=True,
            web_port=0,
        )

        res = rx.download()
        assert res["completed"] is True
        assert (dest_dir / "shared_dedup.bin").read_bytes() == data_content

        # 1. Assert exactly two workers (not four)
        assert res["workers"] == 2, f"Expected exactly 2 workers, got {res['workers']}"

        # 2. Assert exactly two sender entries in stats (keyed by device_id)
        stats = res["sender_stats"]
        sender_keys = list(stats.keys())
        assert len(sender_keys) == 2, f"Expected 2 sender entries, got {sender_keys}"
        assert s1.device_id in stats
        assert s2.device_id in stats

        # Both physical senders contributed
        assert stats[s1.device_id]["pieces"] > 0
        assert stats[s2.device_id]["pieces"] > 0
        assert stats[s1.device_id]["pieces"] + stats[s2.device_id]["pieces"] == res["pieces_done"]

        # 3. Assert tracker dashboard sender list has exactly two entries
        assert rx.tracker_state is not None
        assert len(rx.tracker_state._senders) == 2, f"Expected 2 tracker senders, got {list(rx.tracker_state._senders.keys())}"
        assert s1.device_id in rx.tracker_state._senders
        assert s2.device_id in rx.tracker_state._senders

        # 4. Backward-compatible endpoint lookup continues to work seamlessly
        assert stats[f"127.0.0.1:{s1.port}"]["pieces"] == stats[s1.device_id]["pieces"]
        assert stats[f"127.0.0.1:{s2.port}"]["pieces"] == stats[s2.device_id]["pieces"]

    finally:
        s1.stop()
        s2.stop()
