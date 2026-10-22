"""Flask-based HTTP Tracker and Monitor Server for P2P Swarm.

Implements Sections 12, 12.5, 13, and 14.4:
- GET / and static assets.
- GET /api/state: JSON state snapshot matching Section 12.5.
- POST /api/report: Signed telemetry reports from senders (HMAC-SHA256).
- Optional --web-pin protection for web dashboard and GET /api/state.
- Security headers on every response (CSP, nosniff, no-referrer, no-store for API).
- Periodic UDP BEACON broadcasting on DISCOVERY_PORT so peers learn the tracker.
- Clean threaded server lifecycle (start, stop) using Werkzeug make_server.
"""

import hmac
import json
import logging
import socket
import threading
import time
from typing import Any, Dict, List, Optional

from flask import Flask, Response, make_response, request
from werkzeug.serving import make_server

import config
from common.discovery import DiscoveryBroadcaster, format_dashboard_urls, make_beacon
from tracker.state import TrackerState

# Mute werkzeug HTTP request logs so lines like POST /api/report ... 200 do not interleave with progress bars
logging.getLogger("werkzeug").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)


def create_tracker_app(
    state: TrackerState,
    web_pin: Optional[str] = None,
) -> Flask:
    """Create configured Flask application for tracker and monitor."""
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    app = Flask(__name__, static_folder="static", static_url_path="/static")

    pin_lock = threading.Lock()
    pin_failures: Dict[str, List[float]] = {}
    PIN_MAX_FAILURES = 5
    PIN_BLOCK_SECONDS = 60.0

    def _constant_time_compare(a: Optional[str], b: Optional[str]) -> bool:
        if not a or not b:
            return False
        return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))

    def _is_rate_limited(client_ip: str) -> bool:
        now = time.time()
        with pin_lock:
            if client_ip not in pin_failures:
                return False
            pin_failures[client_ip] = [t for t in pin_failures[client_ip] if now - t < PIN_BLOCK_SECONDS]
            return len(pin_failures[client_ip]) >= PIN_MAX_FAILURES

    def _record_failure(client_ip: str) -> None:
        now = time.time()
        with pin_lock:
            if client_ip not in pin_failures:
                pin_failures[client_ip] = []
            pin_failures[client_ip].append(now)

    def _reset_failures(client_ip: str) -> None:
        with pin_lock:
            pin_failures.pop(client_ip, None)

    @app.after_request
    def apply_security_headers(response: Response) -> Response:
        """Apply required security headers (Section 13)."""
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        if request.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        return response

    @app.route("/", methods=["GET"])
    def index() -> Response:
        """Dashboard HTML index."""
        client_ip = request.remote_addr or "127.0.0.1"

        if web_pin:
            if _is_rate_limited(client_ip):
                return make_response("Too many failed PIN attempts. Please wait.", 429)

            # Check query param first to strip it via redirect
            query_pin = request.args.get("pin")
            if query_pin is not None:
                if _constant_time_compare(query_pin, web_pin):
                    _reset_failures(client_ip)
                    # Redirect to / to strip ?pin= from the browser URL after first use
                    resp = make_response("", 303)
                    resp.headers["Location"] = "/"
                    resp.set_cookie("p2p_pin", web_pin, httponly=True, samesite="Strict", path="/")
                    return resp
                else:
                    _record_failure(client_ip)
                    html_prompt = (
                        "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
                        "<title>P2P Swarm - PIN Required</title><link rel='stylesheet' href='/static/style.css'></head>"
                        "<body><div class='pin-box'><h2>P2P Swarm Dashboard</h2>"
                        "<form method='GET' action='/'><label for='pin'>Enter Web PIN:</label>"
                        "<input type='password' id='pin' name='pin' autofocus required>"
                        "<button type='submit'>Access</button></form></div></body></html>"
                    )
                    return make_response(html_prompt, 401)

            # Check cookie or header
            cookie_pin = request.cookies.get("p2p_pin")
            header_pin = request.headers.get("X-PIN") or request.headers.get("X-Web-PIN")
            if (cookie_pin and _constant_time_compare(cookie_pin, web_pin)) or \
               (header_pin and _constant_time_compare(header_pin, web_pin)):
                _reset_failures(client_ip)
            else:
                html_prompt = (
                    "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
                    "<title>P2P Swarm - PIN Required</title><link rel='stylesheet' href='/static/style.css'></head>"
                    "<body><div class='pin-box'><h2>P2P Swarm Dashboard</h2>"
                    "<form method='GET' action='/'><label for='pin'>Enter Web PIN:</label>"
                    "<input type='password' id='pin' name='pin' autofocus required>"
                    "<button type='submit'>Access</button></form></div></body></html>"
                )
                return make_response(html_prompt, 401)

        return app.send_static_file("index.html")

    @app.route("/api/state", methods=["GET"])
    def get_state() -> Response:
        """Return current JSON state snapshot matching Section 12.5."""
        client_ip = request.remote_addr or "127.0.0.1"

        if web_pin:
            if _is_rate_limited(client_ip):
                return make_response(
                    json.dumps({"error": "Too many failed PIN attempts. Please wait."}),
                    429,
                    {"Content-Type": "application/json"},
                )

            authenticated = False

            # Check cookie
            cookie_pin = request.cookies.get("p2p_pin")
            if cookie_pin and _constant_time_compare(cookie_pin, web_pin):
                authenticated = True

            # Check header
            header_pin = request.headers.get("X-PIN") or request.headers.get("X-Web-PIN")
            if not authenticated and header_pin and _constant_time_compare(header_pin, web_pin):
                authenticated = True

            # Check query param
            query_pin = request.args.get("pin")
            if not authenticated and query_pin is not None:
                if _constant_time_compare(query_pin, web_pin):
                    authenticated = True
                else:
                    _record_failure(client_ip)
                    return make_response(
                        json.dumps({"error": "Unauthorized: Invalid Web PIN"}),
                        401,
                        {"Content-Type": "application/json"},
                    )

            if not authenticated:
                return make_response(
                    json.dumps({"error": "Unauthorized: Web PIN required"}),
                    401,
                    {"Content-Type": "application/json"},
                )

            _reset_failures(client_ip)

        state_data = state.get_state_dict()
        resp = make_response(
            json.dumps(state_data, separators=(",", ":")),
            200,
            {"Content-Type": "application/json"},
        )
        if web_pin and request.args.get("pin") and _constant_time_compare(request.args.get("pin"), web_pin):
            resp.set_cookie("p2p_pin", web_pin, httponly=True, samesite="Strict", path="/")
        return resp

    @app.route("/api/report", methods=["POST"])
    def post_report() -> Response:
        """Receive and verify signed telemetry report from sender (Section 12.2)."""
        # Enforce body size limit before large allocations
        content_length = request.content_length
        if content_length is not None and content_length > config.MAX_REPORT_BYTES:
            return make_response(
                json.dumps({"error": f"Payload too large (max {config.MAX_REPORT_BYTES} bytes)"}),
                400,
                {"Content-Type": "application/json"},
            )

        raw_body = request.get_data(cache=False)
        sig_header = request.headers.get("X-Signature")

        success, status_code, message = state.process_report(raw_body, sig_header)
        payload = {"status": "ok" if success else "error", "message": message}
        return make_response(
            json.dumps(payload),
            status_code,
            {"Content-Type": "application/json"},
        )

    return app


class TrackerServer:
    """Manages the lifecycle of the Flask HTTP server and UDP BEACON broadcaster."""

    def __init__(
        self,
        state: TrackerState,
        host: str = "0.0.0.0",
        port: int = config.DEFAULT_WEB_PORT,
        web_pin: Optional[str] = None,
        discovery_port: int = config.DISCOVERY_PORT,
        device_id: Optional[str] = None,
        enable_beacon: bool = True,
    ) -> None:
        self.state = state
        self.host = host
        self.port = port
        self.web_pin = web_pin
        self.discovery_port = discovery_port
        self.device_id = device_id or state.server_name
        self.enable_beacon = enable_beacon

        self.app = create_tracker_app(self.state, web_pin=self.web_pin)
        self._server = None
        self._thread: Optional[threading.Thread] = None
        self._broadcaster: Optional[DiscoveryBroadcaster] = None

    def start(self, blocking: bool = False) -> None:
        """Start HTTP server and UDP beacon broadcaster."""
        # 1. Start HTTP Server using Werkzeug
        try:
            # Test-bind socket first to avoid Werkzeug printing "Address already in use" and calling sys.exit(1)
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            test_sock.bind((self.host, self.port))
            if self.port == 0:
                self.port = test_sock.getsockname()[1]
            test_sock.close()

            self._server = make_server(self.host, self.port, self.app, threaded=True)
            self.port = self._server.port
            self.state.web_port = self.port
        except (OSError, SystemExit) as e:
            logger.warning(
                "Tracker HTTP server failed to bind on %s:%d: %s. Continuing transfer without tracker.",
                self.host, self.port, e,
            )
            self._server = None
            return

        # 2. Start UDP BEACON broadcaster (Section 11)
        if self.enable_beacon:
            def make_b() -> bytes:
                return make_beacon(
                    device_id=self.device_id,
                    web_port=self.port,
                )

            self._broadcaster = DiscoveryBroadcaster(
                payload_factory=make_b,
                port=self.discovery_port,
                interval=config.HEARTBEAT_INTERVAL,
            )
            self._broadcaster.start()

        logger.info("Tracker server running at %s (PIN=%s)", format_dashboard_urls(self.host, self.port), bool(self.web_pin))

        if blocking:
            self._server.serve_forever()
        else:
            self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
            self._thread.start()

    def stop(self) -> None:
        """Shut down HTTP server and stop UDP beacon broadcaster."""
        if self._broadcaster:
            self._broadcaster.stop()
            self._broadcaster = None

        if self._server:
            self._server.shutdown()
            self._server = None

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
            self._thread = None
