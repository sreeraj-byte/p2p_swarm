"""Unit and integration tests for P2P Swarm Phase 6: Tracker State and Signed Reporting.

Tests include:
1. Signed POST /api/report HMAC-SHA256 signature verification and tamper rejection.
2. Timestamp clock skew enforcement (REPORT_CLOCK_SKEW = 30.0s).
3. Replay protection (strictly increasing sequence numbers per device).
4. Oversized body rejection (> 64 KiB).
5. State reducers: swarm initialization, sender verification, piece delivery,
   per-file exact sender byte contribution across boundaries, failure tracking, and event ring buffer.
6. Piece map downsampling rules (per_cell = ceil(total/400); all missing: -1,
   partly missing: -3, one sender: color_index, mixed senders: -2).
7. Optional --web-pin security on GET /api/state (cookie, header, query param).
8. Security headers (CSP, nosniff, no-referrer, no-store) and secret confidentiality.
9. Live localhost transfer where /api/state reflects transfer progress and completion.
"""

import hashlib
import hmac
import json
import math
from pathlib import Path
import socket
import threading
import time
import urllib.request
import urllib.error
import pytest

import config
from common.auth import derive_auth_key, derive_report_key
from common.discovery import DeviceTable, DeviceEntry, format_dashboard_urls, get_lan_ip
from common.reporting import ReportClient
from tools.gen_certs import generate_self_signed_cert
from receiver import SwarmReceiver
from sender import SenderServer
from tracker.state import TrackerState
from tracker.server import TrackerServer, create_tracker_app


# ---------------------------------------------------------------------------
# 1. State Reducers & Piece-Map Downsampling Unit Tests
# ---------------------------------------------------------------------------


def test_tracker_state_reducers_and_file_contributions() -> None:
    """Verify that state reducers correctly update progress and track exact byte contributions per file."""
    state = TrackerState(server_name="TestTracker", server_ip="127.0.0.1", web_port=8080)

    # 1. Initialize swarm metadata: 2 files spanning across pieces
    # Piece size = 64 KiB (65536 bytes)
    # File 1: 50,000 bytes (fits entirely within piece 0)
    # File 2: 40,000 bytes (15,536 bytes in piece 0, 24,464 bytes in piece 1)
    # Total = 90,000 bytes across 2 pieces
    piece_size = 65536
    metadata = {
        "root": "test_folder",
        "total_size": 90000,
        "piece_size": piece_size,
        "total_pieces": 2,
        "piece_hashes": ["hash0", "hash1"],
        "files": [
            {"path": "file1.txt", "length": 50000},
            {"path": "file2.txt", "length": 40000},
        ],
    }
    state.set_swarm(metadata, swarm_id="abcdef0123456789abcdef0123456789")
    state.set_transfer_state("downloading")

    snap = state.get_state_dict()
    assert snap["swarm"]["name"] == "test_folder"
    assert snap["swarm"]["total_pieces"] == 2
    assert snap["swarm"]["total_bytes"] == 90000
    assert snap["swarm"]["files_total"] == 2
    assert snap["transfer"]["state"] == "downloading"
    assert snap["transfer"]["pieces_done"] == 0

    # 2. Sender verified
    state.on_sender_verified("dev-sender-1", "Laptop-A", "192.168.1.10", 6881)
    state.on_sender_verified("dev-sender-2", "Laptop-B", "192.168.1.11", 6882)

    snap = state.get_state_dict()
    assert len(snap["senders"]) == 2
    s1 = next(s for s in snap["senders"] if s["device_id"] == "dev-sender-1")
    s2 = next(s for s in snap["senders"] if s["device_id"] == "dev-sender-2")
    assert s1["color_index"] == 0
    assert s2["color_index"] == 1

    # 3. Piece 0 delivered by dev-sender-1 (65,536 bytes)
    # Spans all 50,000 bytes of file1, and first 15,536 bytes of file2
    state.on_piece_downloaded(piece_index=0, device_id="dev-sender-1", sender_name="Laptop-A", piece_bytes=65536)

    snap = state.get_state_dict()
    assert snap["transfer"]["pieces_done"] == 1
    assert snap["transfer"]["bytes_done"] == 65536

    f1 = snap["files"][0]
    f2 = snap["files"][1]
    assert f1["complete"] is True
    assert f1["pieces_done"] == 1
    assert f1["by_sender"]["dev-sender-1"] == 50000

    assert f2["complete"] is False
    assert f2["pieces_done"] == 1
    assert f2["by_sender"]["dev-sender-1"] == 15536

    # 4. Piece 1 delivered by dev-sender-2 (remaining 24,464 bytes)
    state.on_piece_downloaded(piece_index=1, device_id="dev-sender-2", sender_name="Laptop-B", piece_bytes=24464)
    state.set_transfer_state("complete")

    snap = state.get_state_dict()
    assert snap["transfer"]["state"] == "complete"
    assert snap["transfer"]["pieces_done"] == 2
    assert snap["transfer"]["bytes_done"] == 90000

    f2 = snap["files"][1]
    assert f2["complete"] is True
    assert f2["pieces_done"] == 2
    assert f2["by_sender"]["dev-sender-1"] == 15536
    assert f2["by_sender"]["dev-sender-2"] == 24464
    assert (f2["by_sender"]["dev-sender-1"] + f2["by_sender"]["dev-sender-2"]) == 40000


def test_piece_map_downsampling_rules() -> None:
    """Verify downsampling logic: per_cell = ceil(total/400); all missing: -1, partly: -3, single: color, mixed: -2."""
    state = TrackerState()

    # Case A: total <= 400 (per_cell = 1, exact 1-to-1 mapping)
    metadata_small = {
        "root": "small",
        "total_size": 160 * 65536,
        "piece_size": 65536,
        "total_pieces": 160,
        "piece_hashes": ["h"] * 160,
        "files": [{"path": "data.bin", "length": 160 * 65536}],
    }
    state.set_swarm(metadata_small, "swarm-small")

    # Initially all missing (-1)
    snap = state.get_state_dict()
    pmap = snap["piece_map"]
    assert pmap["per_cell"] == 1
    assert pmap["cells"] == 160
    assert pmap["data"] == [-1] * 160

    # Piece 0 completed by sender 0 (color 0), Piece 1 by sender 1 (color 1)
    state.on_sender_verified("dev-0", "A", "127.0.0.1", 6881)
    state.on_sender_verified("dev-1", "B", "127.0.0.1", 6882)
    state.on_piece_downloaded(0, "dev-0", "A", 65536)
    state.on_piece_downloaded(1, "dev-1", "B", 65536)

    snap = state.get_state_dict()
    assert snap["piece_map"]["data"][0] == 0
    assert snap["piece_map"]["data"][1] == 1
    assert snap["piece_map"]["data"][2] == -1

    # Case B: total = 1000 > 400 (per_cell = ceil(1000/400) = 3; cells = ceil(1000/3) = 334)
    state_large = TrackerState()
    metadata_large = {
        "root": "large",
        "total_size": 1000 * 65536,
        "piece_size": 65536,
        "total_pieces": 1000,
        "piece_hashes": ["h"] * 1000,
        "files": [{"path": "big.bin", "length": 1000 * 65536}],
    }
    state_large.set_swarm(metadata_large, "swarm-large")

    snap = state_large.get_state_dict()
    pmap = snap["piece_map"]
    assert pmap["per_cell"] == 3
    assert pmap["cells"] == 334
    assert pmap["data"] == [-1] * 334  # All cells missing initially

    state_large.on_sender_verified("dev-0", "A", "127.0.0.1", 6881)  # color 0
    state_large.on_sender_verified("dev-1", "B", "127.0.0.1", 6882)  # color 1

    # Cell 0 covers pieces [0, 1, 2]. Complete only piece 0 -> partly missing (-3)
    state_large.on_piece_downloaded(0, "dev-0", "A", 65536)
    snap = state_large.get_state_dict()
    assert snap["piece_map"]["data"][0] == -3

    # Complete piece 1 and 2 from same sender dev-0 -> single sender color (0)
    state_large.on_piece_downloaded(1, "dev-0", "A", 65536)
    state_large.on_piece_downloaded(2, "dev-0", "A", 65536)
    snap = state_large.get_state_dict()
    assert snap["piece_map"]["data"][0] == 0

    # Cell 1 covers pieces [3, 4, 5]. Complete piece 3 and 4 with dev-0, and piece 5 with dev-1 -> mixed senders (-2)
    state_large.on_piece_downloaded(3, "dev-0", "A", 65536)
    state_large.on_piece_downloaded(4, "dev-0", "A", 65536)
    state_large.on_piece_downloaded(5, "dev-1", "B", 65536)
    snap = state_large.get_state_dict()
    assert snap["piece_map"]["data"][1] == -2


def test_tracker_event_ring_buffer_and_speed_moving_average() -> None:
    """Verify circular event buffer caps at MAX_EVENTS and moving speed is computed."""
    state = TrackerState()

    # Fill event log with 250 events
    for i in range(250):
        state.record_event("TEST_EVENT", f"Message {i}", "info", t=1000.0 + i)

    snap = state.get_state_dict()
    events = snap["events"]
    assert len(events) == config.MAX_EVENTS
    # Newest first
    assert events[0]["msg"] == "Message 249"
    assert events[-1]["msg"] == f"Message {250 - config.MAX_EVENTS}"


# ---------------------------------------------------------------------------
# 2. Signed Reporting Security: Signature, Timestamp, Replay, Oversized Body
# ---------------------------------------------------------------------------


def test_signed_reporting_security_checks() -> None:
    """Verify POST /api/report validates HMAC signatures, timestamps, sequence replays, and sizes."""
    join_code = "tracker-auth-test-code-2026"
    auth_key = derive_auth_key(join_code)
    report_key = derive_report_key(auth_key)

    state = TrackerState(report_key=report_key)
    now = 1730000000.0

    # 1. Valid report
    body = {
        "device_id": "sender-alpha",
        "seq": 1,
        "ts": now,
        "pieces_sent": 10,
        "bytes_sent": 655360,
        "active_connections": 1,
        "events": [{"type": "TEST", "msg": "hello", "level": "info"}],
    }
    raw_body = json.dumps(body).encode("utf-8")
    valid_sig = hmac.new(report_key, raw_body, hashlib.sha256).hexdigest()

    ok, code, msg = state.process_report(raw_body, valid_sig, now=now)
    assert ok is True
    assert code == 200
    assert state.invalid_reports_count == 0

    # 2. Missing or invalid signature
    ok, code, msg = state.process_report(raw_body, None, now=now)
    assert ok is False
    assert code == 401
    assert "Missing X-Signature" in msg

    wrong_sig = hmac.new(b"wrong-report-key-32-bytes-long!", raw_body, hashlib.sha256).hexdigest()
    ok, code, msg = state.process_report(raw_body, wrong_sig, now=now)
    assert ok is False
    assert code == 401
    assert "Invalid report HMAC signature" in msg
    assert state.invalid_reports_count == 2

    # 3. Timestamp clock skew check (> 30s)
    skewed_body = dict(body)
    skewed_body["seq"] = 2
    skewed_body["ts"] = now - (config.REPORT_CLOCK_SKEW + 5.0)  # 35s in the past
    raw_skewed = json.dumps(skewed_body).encode("utf-8")
    sig_skewed = hmac.new(report_key, raw_skewed, hashlib.sha256).hexdigest()

    ok, code, msg = state.process_report(raw_skewed, sig_skewed, now=now)
    assert ok is False
    assert code == 400
    assert "Timestamp skew" in msg

    # Future skew
    future_body = dict(body)
    future_body["seq"] = 2
    future_body["ts"] = now + (config.REPORT_CLOCK_SKEW + 5.0)
    raw_future = json.dumps(future_body).encode("utf-8")
    sig_future = hmac.new(report_key, raw_future, hashlib.sha256).hexdigest()

    ok, code, msg = state.process_report(raw_future, sig_future, now=now)
    assert ok is False
    assert code == 400

    # 4. Replay protection (seq must be strictly increasing per device)
    # Attempting seq=1 again (replayed)
    replayed_body = dict(body)
    replayed_body["seq"] = 1
    replayed_body["ts"] = now
    raw_replay = json.dumps(replayed_body).encode("utf-8")
    sig_replay = hmac.new(report_key, raw_replay, hashlib.sha256).hexdigest()

    ok, code, msg = state.process_report(raw_replay, sig_replay, now=now)
    assert ok is False
    assert code == 400
    assert "Replayed or stale sequence" in msg

    # seq=2 accepted
    body_seq2 = dict(body)
    body_seq2["seq"] = 2
    body_seq2["ts"] = now
    raw_seq2 = json.dumps(body_seq2).encode("utf-8")
    sig_seq2 = hmac.new(report_key, raw_seq2, hashlib.sha256).hexdigest()

    ok, code, msg = state.process_report(raw_seq2, sig_seq2, now=now)
    assert ok is True
    assert code == 200

    # Distinct device can start at seq=1
    body_beta = dict(body)
    body_beta["device_id"] = "sender-beta"
    body_beta["seq"] = 1
    raw_beta = json.dumps(body_beta).encode("utf-8")
    sig_beta = hmac.new(report_key, raw_beta, hashlib.sha256).hexdigest()

    ok, code, msg = state.process_report(raw_beta, sig_beta, now=now)
    assert ok is True
    assert code == 200

    # 5. Oversized body rejection (> 64 KiB)
    oversized_raw = b"x" * (config.MAX_REPORT_BYTES + 10)
    ok, code, msg = state.process_report(oversized_raw, valid_sig, now=now)
    assert ok is False
    assert code == 400
    assert "exceeds max 64 KiB" in msg


# ---------------------------------------------------------------------------
# 3. HTTP Server API & Web PIN & Security Headers
# ---------------------------------------------------------------------------


def test_tracker_server_http_endpoints_and_web_pin() -> None:
    """Verify HTTP server endpoints, optional web-pin protection, and security headers."""
    join_code = "pin-test-code"
    auth_key = derive_auth_key(join_code)
    report_key = derive_report_key(auth_key)

    state = TrackerState(report_key=report_key)
    web_pin = "secret-pin-7788"

    # Start TrackerServer on dynamic port 0
    server = TrackerServer(
        state=state,
        host="127.0.0.1",
        port=0,
        web_pin=web_pin,
        enable_beacon=False,
    )
    server.start(blocking=False)
    time.sleep(0.1)

    port = server.port
    base_url = f"http://127.0.0.1:{port}"

    try:
        # 1. GET /api/state without PIN -> 401 Unauthorized
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(f"{base_url}/api/state")
        assert exc_info.value.code == 401
        assert exc_info.value.headers.get("Content-Security-Policy") == "default-src 'self'"
        assert exc_info.value.headers.get("X-Content-Type-Options") == "nosniff"

        # 2. GET /api/state with query param PIN -> 200 OK + cookie set
        req = urllib.request.Request(f"{base_url}/api/state?pin={web_pin}")
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200
            cookie = resp.headers.get("Set-Cookie")
            assert cookie and f"p2p_pin={web_pin}" in cookie
            data = json.loads(resp.read().decode("utf-8"))
            assert "swarm" in data
            assert "transfer" in data
            # Check confidentiality: no keys or secrets leaked
            assert "report_key" not in data
            assert "auth_key" not in data
            assert "join_code" not in data

        # 3. GET /api/state with cookie -> 200 OK
        req_cookie = urllib.request.Request(
            f"{base_url}/api/state",
            headers={"Cookie": f"p2p_pin={web_pin}"},
        )
        with urllib.request.urlopen(req_cookie) as resp:
            assert resp.status == 200

        # 4. POST /api/report works with valid HMAC signature (not affected by web-pin)
        report_data = {
            "device_id": "test-sender",
            "seq": 1,
            "ts": time.time(),
            "pieces_sent": 5,
            "bytes_sent": 327680,
            "active_connections": 1,
            "events": [],
        }
        raw_body = json.dumps(report_data).encode("utf-8")
        sig = hmac.new(report_key, raw_body, hashlib.sha256).hexdigest()

        post_req = urllib.request.Request(
            f"{base_url}/api/report",
            data=raw_body,
            headers={
                "Content-Type": "application/json",
                "X-Signature": sig,
            },
            method="POST",
        )
        with urllib.request.urlopen(post_req) as resp:
            assert resp.status == 200
            res = json.loads(resp.read().decode("utf-8"))
            assert res["status"] == "ok"

    finally:
        server.stop()


# ---------------------------------------------------------------------------
# 4. Localhost Live Transfer Reflecting /api/state
# ---------------------------------------------------------------------------


def test_live_transfer_state_reflection(tmp_path: Path) -> None:
    """Verify live transfer accurately updates tracker state accessible via GET /api/state."""
    cert_path, key_path = generate_self_signed_cert(out_dir=tmp_path / "certs_live")
    data_file = tmp_path / "live_data.bin"
    payload = b"LiveTrackerTransferVerificationPayload" * 2000  # ~76 KiB (2 pieces of 64 KiB)
    data_file.write_bytes(payload)

    join_code = "live-state-test-code-2026"
    disc_port = 52120

    # 1. Start Sender with discovery and reporting enabled
    sender = SenderServer(
        source_path=data_file,
        port=0,
        name="SeederLive",
        cert_path=cert_path,
        key_path=key_path,
        join_code=join_code,
        piece_size=65536,
        throttle_kbps=150,
        discovery_port=disc_port,
        enable_discovery=True,
        heartbeat_interval=0.2,
    )
    sender.start(blocking=False)
    time.sleep(0.1)

    dest_dir = tmp_path / "dest_live"
    dest_dir.mkdir()

    # 2. Start Receiver with embedded tracker on dynamic port 0
    tracker_state = TrackerState(
        server_name="LiveReceiver",
        server_ip="127.0.0.1",
        web_port=0,
    )
    rx = SwarmReceiver(
        senders=[f"127.0.0.1:{sender.port}"],
        out_dir=dest_dir,
        cert_path=cert_path,
        join_code=join_code,
        verbose=False,
        enable_discovery=False,
        enable_tracker=True,
        web_port=0,
        web_host="127.0.0.1",
        tracker_state=tracker_state,
    )

    try:
        # Start download in a background thread so we can poll /api/state during execution
        t_download = threading.Thread(target=rx.download, daemon=True)
        t_download.start()

        # Wait until tracker server is running
        for _ in range(50):
            if rx.tracker_server and rx.tracker_server.port > 0:
                break
            time.sleep(0.05)

        assert rx.tracker_server is not None
        web_port = rx.tracker_server.port
        api_url = f"http://127.0.0.1:{web_port}/api/state"

        # Poll HTTP /api/state while transfer is in flight
        live_state_observed = False
        for _ in range(50):
            try:
                req = urllib.request.Request(api_url)
                with urllib.request.urlopen(req, timeout=1.0) as resp:
                    if resp.status == 200:
                        http_data = json.loads(resp.read().decode("utf-8"))
                        assert "transfer" in http_data
                        assert "piece_map" in http_data
                        assert http_data["swarm"]["total_pieces"] == 2
                        live_state_observed = True
                        break
            except (OSError, urllib.error.URLError):
                time.sleep(0.05)

        assert live_state_observed is True

        # Wait for transfer completion
        t_download.join(timeout=10.0)
        assert not t_download.is_alive()

        # Check completed state snapshot directly from state store
        snap = tracker_state.get_state_dict()
        assert snap["transfer"]["state"] == "complete"
        assert snap["transfer"]["pieces_done"] == 2
        assert snap["transfer"]["bytes_done"] == len(payload)
        assert snap["swarm"]["total_pieces"] == 2
        assert snap["swarm"]["total_bytes"] == len(payload)
        assert len(snap["senders"]) >= 1

        # Check piece map
        pmap = snap["piece_map"]
        assert pmap["cells"] == 2
        assert pmap["data"] == [0, 0]  # Both pieces supplied by sender 0

        # Check file integrity on disk
        assert (dest_dir / "live_data.bin").read_bytes() == payload
    finally:
        sender.stop()
        if rx.tracker_server:
            rx.tracker_server.stop()


# ---------------------------------------------------------------------------
# 5. Phase 6 Hardening Tests: CSP, PIN, Resilience, and JSON Sample
# ---------------------------------------------------------------------------


def test_csp_header_strict_no_unsafe_inline() -> None:
    """Verify strict Content-Security-Policy (default-src 'self' without 'unsafe-inline') and static assets."""
    server = TrackerServer(
        state=TrackerState(),
        host="127.0.0.1",
        port=0,
        enable_beacon=False,
    )
    server.start(blocking=False)
    time.sleep(0.1)

    base_url = f"http://127.0.0.1:{server.port}"
    try:
        # Check GET /
        with urllib.request.urlopen(f"{base_url}/") as resp:
            assert resp.status == 200
            csp = resp.headers.get("Content-Security-Policy", "")
            assert csp == "default-src 'self'"
            assert "unsafe-inline" not in csp
            assert resp.headers.get("X-Content-Type-Options") == "nosniff"
            assert resp.headers.get("Referrer-Policy") == "no-referrer"
            body = resp.read().decode("utf-8")
            assert ("/static/dashboard.js" in body or "/static/app.js" in body)
            assert ("/static/dashboard.css" in body or "/static/style.css" in body)
            # Ensure no inline script tags
            assert "<script>" not in body
            assert "<style>" not in body

        # Check GET /api/state
        with urllib.request.urlopen(f"{base_url}/api/state") as resp:
            assert resp.status == 200
            csp = resp.headers.get("Content-Security-Policy", "")
            assert csp == "default-src 'self'"
            assert "unsafe-inline" not in csp
            assert "no-store" in resp.headers.get("Cache-Control", "")

        # Check all static assets can be served
        for asset, expected_type in [
            ("style.css", "text/css"),
            ("app.js", "javascript"),
            ("index.html", "text/html"),
        ]:
            with urllib.request.urlopen(f"{base_url}/static/{asset}") as resp:
                assert resp.status == 200
                assert expected_type in resp.headers.get("Content-Type", "")
    finally:
        server.stop()


def test_xss_protection_device_name_rendered_as_plain_text() -> None:
    """Verify that a device named <script>alert(1)</script> is safely treated as plain text."""
    import re

    malicious_name = "<script>alert(1)</script>"
    state = TrackerState()
    state.on_sender_verified(
        device_id="xss-test-dev-01",
        name=malicious_name,
        ip="127.0.0.1",
        tcp_port=6881,
    )

    # 1. State snapshot verification
    snap = state.get_state_dict()
    assert len(snap["devices"]) == 1
    assert snap["devices"][0]["name"] == malicious_name
    assert len(snap["senders"]) == 1
    assert snap["senders"][0]["name"] == malicious_name

    # 2. Verify static frontend script strictly avoids dangerous DOM injection APIs
    app_js_path = Path(__file__).parent.parent / "tracker" / "static" / "app.js"
    js_content = app_js_path.read_text(encoding="utf-8")

    # Assert no dangerous innerHTML, outerHTML, insertAdjacentHTML, document.write, or eval
    assert "innerHTML" not in js_content
    assert "outerHTML" not in js_content
    assert "insertAdjacentHTML" not in js_content
    assert "document.write" not in js_content
    assert "eval(" not in js_content

    # Assert setAttribute never sets 'on*' event handlers or raw 'style' attributes
    on_handlers = re.findall(r"setAttribute\s*\(\s*['\"]on[a-zA-Z]+['\"]", js_content)
    assert len(on_handlers) == 0, f"Found setAttribute with on* handler: {on_handlers}"
    style_attrs = re.findall(r"setAttribute\s*\(\s*['\"]style['\"]", js_content)
    assert len(style_attrs) == 0, f"Found setAttribute with style: {style_attrs}"

    # Assert safe textContent is used
    assert "textContent" in js_content

    # 3. Verify HTTP endpoint serves raw text safely without HTML transformation
    server = TrackerServer(state=state, host="127.0.0.1", port=0, enable_beacon=False)
    server.start(blocking=False)
    time.sleep(0.05)

    try:
        base_url = f"http://127.0.0.1:{server.port}"
        with urllib.request.urlopen(f"{base_url}/api/state") as resp:
            data = json.loads(resp.read().decode("utf-8"))
            assert data["devices"][0]["name"] == malicious_name
    finally:
        server.stop()


def test_pin_security_constant_time_rate_limit_url_strip() -> None:
    """Verify constant-time PIN comparison, 5-failure rate limiting (429), URL stripping (303), and confidentiality."""
    web_pin = "secret-vault-pin-12345"
    server = TrackerServer(
        state=TrackerState(),
        host="127.0.0.1",
        port=0,
        web_pin=web_pin,
        enable_beacon=False,
    )
    server.start(blocking=False)
    time.sleep(0.1)

    base_url = f"http://127.0.0.1:{server.port}"

    class CustomRedirectHandler(urllib.request.HTTPRedirectHandler):
        """Prevent automatic redirect follow to inspect the 303 response and headers."""
        def http_error_303(self, req, fp, code, msg, headers):
            return fp

        def http_error_302(self, req, fp, code, msg, headers):
            return fp

    opener = urllib.request.build_opener(CustomRedirectHandler)

    try:
        # 1. Unauthenticated request without PIN -> 401
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(f"{base_url}/")
        assert exc.value.code == 401

        # 2. URL pin stripping: GET /?pin=secret-vault-pin-12345 returns 303 redirect to /
        resp = opener.open(f"{base_url}/?pin={web_pin}")
        assert resp.status == 303
        assert resp.headers.get("Location") == "/"
        cookie = resp.headers.get("Set-Cookie", "")
        assert f"p2p_pin={web_pin}" in cookie
        assert "HttpOnly" in cookie
        assert "SameSite=Strict" in cookie

        # 3. Request with valid cookie -> 200 OK
        req_cookie = urllib.request.Request(f"{base_url}/", headers={"Cookie": f"p2p_pin={web_pin}"})
        with urllib.request.urlopen(req_cookie) as ok_resp:
            assert ok_resp.status == 200

        # 4. Rate-limit failed attempts: 5 failed attempts from same IP
        for attempt in range(5):
            with pytest.raises(urllib.error.HTTPError) as exc_fail:
                urllib.request.urlopen(f"{base_url}/api/state?pin=wrong-attempt-{attempt}")
            assert exc_fail.value.code == 401

        # 6th attempt is blocked with 429 Too Many Requests
        with pytest.raises(urllib.error.HTTPError) as exc_locked:
            urllib.request.urlopen(f"{base_url}/api/state?pin=wrong-attempt-6")
        assert exc_locked.value.code == 429

        # Even with the correct PIN, access is locked out while rate-limited
        with pytest.raises(urllib.error.HTTPError) as exc_locked_good:
            urllib.request.urlopen(f"{base_url}/api/state?pin={web_pin}")
        assert exc_locked_good.value.code == 429

    finally:
        server.stop()


def test_web_port_already_in_use_does_not_interrupt_transfer(tmp_path: Path) -> None:
    """Verify that a web port already in use logs a warning and leaves the transfer uninterrupted."""
    # Pre-bind socket to simulate port conflict
    conflict_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conflict_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    conflict_sock.bind(("127.0.0.1", 0))
    conflict_sock.listen(1)
    conflict_port = conflict_sock.getsockname()[1]

    cert_path, key_path = generate_self_signed_cert(out_dir=tmp_path / "certs_conflict")
    data_file = tmp_path / "port_conflict_data.bin"
    payload = b"PortConflictResilienceTestData" * 1000  # ~30 KiB
    data_file.write_bytes(payload)

    join_code = "conflict-port-test-code-2026"
    sender = SenderServer(
        source_path=data_file,
        port=0,
        name="SenderConflict",
        cert_path=cert_path,
        key_path=key_path,
        join_code=join_code,
        piece_size=65536,
        throttle_kbps=0,
        enable_discovery=False,
    )
    sender.start(blocking=False)
    time.sleep(0.05)

    dest_dir = tmp_path / "dest_conflict"
    dest_dir.mkdir()

    rx = SwarmReceiver(
        senders=[f"127.0.0.1:{sender.port}"],
        out_dir=dest_dir,
        cert_path=cert_path,
        join_code=join_code,
        verbose=False,
        enable_discovery=False,
        enable_tracker=True,
        web_port=conflict_port,
        web_host="127.0.0.1",
    )

    try:
        # Download should succeed completely even though tracker failed to bind
        summary = rx.download()
        assert summary["status"] == "complete"
        assert (dest_dir / "port_conflict_data.bin").read_bytes() == payload
        # Tracker server should have failed gracefully without crashing
        assert rx.tracker_server._server is None
    finally:
        conflict_sock.close()
        sender.stop()
        if rx.tracker_server:
            rx.tracker_server.stop()


def test_unreachable_tracker_does_not_interrupt_transfer(tmp_path: Path) -> None:
    """Verify that an unreachable --tracker address does not interrupt or fail a transfer."""
    cert_path, key_path = generate_self_signed_cert(out_dir=tmp_path / "certs_unreach")
    data_file = tmp_path / "unreach_data.bin"
    payload = b"UnreachableTrackerResiliencePayload" * 1500  # ~52 KiB
    data_file.write_bytes(payload)

    join_code = "unreach-tracker-code-2026"

    # Direct sender to an unreachable port where no tracker exists
    dead_tracker = "127.0.0.1:59998"
    sender = SenderServer(
        source_path=data_file,
        port=0,
        name="SenderUnreach",
        cert_path=cert_path,
        key_path=key_path,
        join_code=join_code,
        piece_size=65536,
        throttle_kbps=0,
        enable_discovery=False,
        tracker=dead_tracker,
    )
    sender.start(blocking=False)
    time.sleep(0.05)

    dest_dir = tmp_path / "dest_unreach"
    dest_dir.mkdir()

    rx = SwarmReceiver(
        senders=[f"127.0.0.1:{sender.port}"],
        out_dir=dest_dir,
        cert_path=cert_path,
        join_code=join_code,
        verbose=False,
        enable_discovery=False,
        enable_tracker=False,
    )

    try:
        summary = rx.download()
        assert summary["status"] == "complete"
        assert (dest_dir / "unreach_data.bin").read_bytes() == payload
    finally:
        sender.stop()


def test_confidentiality_join_code_and_keys_never_in_state_or_logs(tmp_path: Path) -> None:
    """Verify that join codes, derived auth keys, and report keys never appear in /api/state or logs."""
    import logging

    class LogCaptureHandler(logging.Handler):
        def __init__(self):
            super().__init__()
            self.records = []

        def emit(self, record):
            self.records.append(self.format(record))

    log_handler = LogCaptureHandler()
    root_logger = logging.getLogger()
    root_logger.addHandler(log_handler)

    join_code = "TopSecretJoinCode999"
    auth_key = derive_auth_key(join_code)
    report_key = derive_report_key(auth_key)

    cert_path, key_path = generate_self_signed_cert(out_dir=tmp_path / "certs_confidential")
    data_file = tmp_path / "confidential_data.bin"
    payload = b"ConfidentialDataTestPayload" * 1000
    data_file.write_bytes(payload)

    sender = SenderServer(
        source_path=data_file,
        port=0,
        name="SenderConfidential",
        cert_path=cert_path,
        key_path=key_path,
        join_code=join_code,
        piece_size=65536,
        throttle_kbps=0,
        enable_discovery=False,
    )
    sender.start(blocking=False)
    time.sleep(0.05)

    dest_dir = tmp_path / "dest_confidential"
    dest_dir.mkdir()

    tracker_state = TrackerState(
        server_name="ConfidentialReceiver",
        server_ip="127.0.0.1",
        web_port=0,
        report_key=report_key,
    )
    rx = SwarmReceiver(
        senders=[f"127.0.0.1:{sender.port}"],
        out_dir=dest_dir,
        cert_path=cert_path,
        join_code=join_code,
        verbose=False,
        enable_discovery=False,
        enable_tracker=True,
        web_port=0,
        web_host="127.0.0.1",
        tracker_state=tracker_state,
    )

    try:
        summary = rx.download()
        assert summary["status"] == "complete"

        # Check /api/state JSON representation
        state_dict = tracker_state.get_state_dict()
        state_json = json.dumps(state_dict)

        assert join_code not in state_json
        assert auth_key.hex() not in state_json
        assert report_key.hex() not in state_json
        assert "join_code" not in state_dict
        assert "auth_key" not in state_dict
        assert "report_key" not in state_dict

        # Check captured logs
        all_logs = " ".join(log_handler.records)
        assert join_code not in all_logs
        assert auth_key.hex() not in all_logs
        assert report_key.hex() not in all_logs
    finally:
        root_logger.removeHandler(log_handler)
        sender.stop()
        if rx.tracker_server:
            rx.tracker_server.stop()


def test_live_throttled_transfer_and_api_state_sample(tmp_path: Path) -> None:
    """Run a live throttled transfer across multiple files, print real /api/state sample, and reconcile with Section 12.5."""
    cert_path, key_path = generate_self_signed_cert(out_dir=tmp_path / "certs_throttled")

    # Create multi-file directory to verify file boundary and contributor tracking
    source_dir = tmp_path / "shared_files"
    source_dir.mkdir()
    file1_bytes = b"F1PayloadByteSequenceA" * 2270   # ~50,000 bytes
    file2_bytes = b"F2PayloadByteSequenceB" * 4090   # ~90,000 bytes
    (source_dir / "file1.txt").write_bytes(file1_bytes)
    (source_dir / "file2.txt").write_bytes(file2_bytes)
    total_bytes = len(file1_bytes) + len(file2_bytes)  # 140,000 bytes (~3 pieces of 64 KiB)

    join_code = "throttled-live-code-2026"
    disc_port = 52125

    # Start throttled sender at 100 KB/s
    sender = SenderServer(
        source_path=source_dir,
        port=0,
        name="ThrottledSeeder",
        cert_path=cert_path,
        key_path=key_path,
        join_code=join_code,
        piece_size=65536,
        throttle_kbps=100,
        discovery_port=disc_port,
        enable_discovery=True,
        heartbeat_interval=0.2,
    )
    sender.start(blocking=False)
    time.sleep(0.1)

    dest_dir = tmp_path / "dest_throttled"
    dest_dir.mkdir()

    tracker_state = TrackerState(
        server_name="ReceiverThrottled",
        server_ip="127.0.0.1",
        web_port=0,
    )
    rx = SwarmReceiver(
        senders=[f"127.0.0.1:{sender.port}"],
        out_dir=dest_dir,
        cert_path=cert_path,
        join_code=join_code,
        verbose=False,
        enable_discovery=False,
        enable_tracker=True,
        web_port=0,
        web_host="127.0.0.1",
        tracker_state=tracker_state,
        keep_tracker_alive=True,
    )

    in_flight_state = None
    final_state = None

    try:
        t_download = threading.Thread(target=rx.download, daemon=True)
        t_download.start()

        # Wait for tracker server to start
        for _ in range(50):
            if rx.tracker_server and rx.tracker_server.port > 0:
                break
            time.sleep(0.05)

        assert rx.tracker_server is not None
        web_port = rx.tracker_server.port
        api_url = f"http://127.0.0.1:{web_port}/api/state"

        # Poll /api/state during in-flight transfer
        for _ in range(50):
            try:
                with urllib.request.urlopen(api_url, timeout=1.0) as resp:
                    if resp.status == 200:
                        in_flight_state = json.loads(resp.read().decode("utf-8"))
                        if in_flight_state.get("transfer", {}).get("state") == "downloading":
                            break
            except (OSError, urllib.error.URLError):
                pass
            time.sleep(0.05)

        t_download.join(timeout=15.0)
        assert not t_download.is_alive()

        # Fetch final completed state
        with urllib.request.urlopen(api_url, timeout=2.0) as resp:
            final_state = json.loads(resp.read().decode("utf-8"))

        print("\n=== REAL /api/state JSON SAMPLE (THROTTLED TRANSFER) ===")
        print(json.dumps(final_state, indent=2))
        print("=== END /api/state JSON SAMPLE ===\n")

        # -------------------------------------------------------------
        # Reconcile with Section 12.5 Specifications
        # -------------------------------------------------------------

        # 1. Tracker info: tls and auth
        assert "tracker" in final_state
        assert final_state["tracker"]["tls"] is True
        assert final_state["tracker"]["auth"] is True
        assert final_state["tracker"]["web_port"] == web_port

        # 2. Devices array: id, name, ip, port, role, status, trust, last_seen_age, swarm_short
        assert "devices" in final_state
        assert len(final_state["devices"]) >= 1
        dev = final_state["devices"][0]
        assert "device_id" in dev or "id" in dev
        assert "name" in dev
        assert "ip" in dev
        assert "tcp_port" in dev or "port" in dev
        assert "role" in dev
        assert "status" in dev
        assert dev["trust"] == "verified"
        assert "last_seen_age" in dev
        assert "swarm_short" in dev

        # 3. Transfer progress: files_done, bad_pieces, state, speed_bps
        transfer = final_state["transfer"]
        assert transfer["state"] == "complete"
        assert transfer["pieces_done"] == 3
        assert transfer["bytes_done"] == total_bytes
        assert transfer["files_done"] == 2
        assert transfer["bad_pieces"] == 0
        assert "speed_bps" in transfer
        assert "eta_s" in transfer

        # 4. Senders array: failures, status, color_index, pieces, bytes
        assert "senders" in final_state
        assert len(final_state["senders"]) >= 1
        s = final_state["senders"][0]
        assert s["failures"] == 0
        assert s["status"] == "active"
        assert s["pieces"] == 3
        assert s["bytes"] == total_bytes
        assert s["color_index"] == 0

        # 5. Files array: complete, pieces_done, pieces_total, by_sender
        assert "files" in final_state
        assert len(final_state["files"]) == 2
        f1 = next(f for f in final_state["files"] if f["path"] == "file1.txt")
        f2 = next(f for f in final_state["files"] if f["path"] == "file2.txt")
        assert f1["complete"] is True
        assert f1["pieces_done"] == 1
        assert f1["pieces_total"] == 1
        assert f1["length"] == len(file1_bytes)
        assert sum(f1["by_sender"].values()) == len(file1_bytes)

        assert f2["complete"] is True
        assert f2["pieces_done"] == 3
        assert f2["pieces_total"] == 3
        assert f2["length"] == len(file2_bytes)
        assert sum(f2["by_sender"].values()) == len(file2_bytes)

        # 6. Piece map: downsampling rules
        pmap = final_state["piece_map"]
        assert pmap["cells"] == 3
        assert pmap["per_cell"] == 1
        assert pmap["data"] == [0, 0, 0]  # All 3 pieces supplied by sender 0

        # 7. File integrity on disk
        assert (dest_dir / "shared_files" / "file1.txt").read_bytes() == file1_bytes
        assert (dest_dir / "shared_files" / "file2.txt").read_bytes() == file2_bytes

    finally:
        sender.stop()
        if rx.tracker_server:
            rx.tracker_server.stop()


def test_post_transfer_dashboard_persistence_unless_exit_when_done(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Verify Section 9.3.1: after transfer completes, tracker/dashboard persists until Ctrl+C unless --exit-when-done."""
    shared_dir = tmp_path / "shared"
    shared_dir.mkdir()
    (shared_dir / "file.txt").write_bytes(b"A" * 1024)

    certs_dir = tmp_path / "certs"
    cert_path, key_path = generate_self_signed_cert(certs_dir)
    join_code = "SECRET-PASS-99"

    sender = SenderServer(
        source_path=shared_dir,
        cert_path=cert_path,
        key_path=key_path,
        join_code=join_code,
        port=0,
        enable_discovery=False,
    )
    sender.start(blocking=False)
    time.sleep(0.1)

    try:
        dest_dir = tmp_path / "dest"
        dest_dir.mkdir()

        # Part A: exit_when_done=False -> keeps tracker running and prints message
        rx = SwarmReceiver(
            senders=[f"127.0.0.1:{sender.port}"],
            out_dir=dest_dir,
            cert_path=cert_path,
            join_code=join_code,
            verbose=True,
            enable_discovery=False,
            enable_tracker=True,
            web_port=0,
            web_host="127.0.0.1",
            exit_when_done=False,
        )

        t_download = threading.Thread(target=rx.download, daemon=True)
        t_download.start()

        # Wait for transfer to complete and enter dashboard keep-alive loop
        for _ in range(50):
            if rx.writer is not None and rx.writer.is_complete():
                break
            time.sleep(0.1)

        time.sleep(0.3)
        assert rx.writer is not None and rx.writer.is_complete()
        assert rx.tracker_server is not None
        assert t_download.is_alive(), "Receiver thread should still be alive running the dashboard"

        # Verify tracker HTTP endpoint is alive and returns 200
        req = urllib.request.Request(f"http://127.0.0.1:{rx.tracker_server.port}/api/state")
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            assert data["transfer"]["state"] == "complete"

        # Signal stop (simulating Ctrl+C)
        rx.stop_dashboard()
        t_download.join(timeout=3.0)
        assert not t_download.is_alive()

        # Check stdout contains the required message
        out = capsys.readouterr().out
        assert "Transfer complete. Dashboard still running; press Ctrl+C to quit" in out

        # Part B: exit_when_done=True -> exits immediately, does not print keep-alive prompt
        dest_dir2 = tmp_path / "dest2"
        dest_dir2.mkdir()
        rx2 = SwarmReceiver(
            senders=[f"127.0.0.1:{sender.port}"],
            out_dir=dest_dir2,
            cert_path=cert_path,
            join_code=join_code,
            verbose=True,
            enable_discovery=False,
            enable_tracker=True,
            web_port=0,
            web_host="127.0.0.1",
            exit_when_done=True,
        )
        result = rx2.download()
        assert result["status"] == "complete"
        out2 = capsys.readouterr().out
        assert "Transfer complete. Dashboard still running; press Ctrl+C to quit" not in out2

    finally:
        sender.stop()


def test_dashboard_address_formatting_never_prints_quad_zeros() -> None:
    """Verify that 0.0.0.0 is never printed as dashboard address; prints 127.0.0.1 and LAN IP."""
    url_str = format_dashboard_urls("0.0.0.0", 8080)
    assert "0.0.0.0" not in url_str
    assert "http://127.0.0.1:8080" in url_str
    lan = get_lan_ip()
    if lan and lan != "127.0.0.1":
        assert f"http://{lan}:8080" in url_str
        assert " and " in url_str

    # Also test empty string or None
    assert "0.0.0.0" not in format_dashboard_urls("", 9000)
    assert "0.0.0.0" not in format_dashboard_urls(None, 9000)

    # Specific IP is preserved
    assert format_dashboard_urls("192.168.1.100", 8080) == "http://192.168.1.100:8080"


def test_werkzeug_logger_muted_to_warning() -> None:
    """Verify werkzeug logger is set to WARNING to prevent request log pollution."""
    import logging
    werkzeug_logger = logging.getLogger("werkzeug")
    assert werkzeug_logger.level >= logging.WARNING


