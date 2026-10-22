# P2P Swarm: Spec Deviations & Security Audit Matrix

This document provides:
1. The complete **Section 14 Security Audit Matrix** mapping every specification requirement to code implementation and test coverage.
2. The complete **List of Spec Deviations & Architectural Decisions**, including a precise field-by-field comparison of `/api/state` against Section 12.5.

---

## 1. Section 14 Security Audit Table

| Spec Section | Requirement Description | Code Location | Pytest Coverage |
|---|---|---|---|
| **14.1 TLS** | Minimum TLS 1.2, prefer 1.3, secure ciphers | [common/tlsutil.py](../common/tlsutil.py#L30-L75) | `tests/test_auth_security.py::test_tls_context_configuration` |
| **14.1 TLS** | Pinned certificate: Senders present cert; receiver pins trust (`verify_mode = CERT_REQUIRED`, `check_hostname = False`) | [common/tlsutil.py](../common/tlsutil.py#L30-L75), [receiver.py](../receiver.py) | `tests/test_auth_security.py::test_tls_pinned_certificate_handshake`, `tests/test_integration.py::test_wrong_cert_rejected`, `test_plain_tcp_refused_when_tls_required` |
| **14.1 TLS** | Never use `CERT_NONE` or disable verification, even in tests | Enforced globally (`CERT_REQUIRED` everywhere) | Verified across all test files (0 occurrences of `CERT_NONE`) |
| **14.1 TLS** | `gen_certs.py` generates cert with Python 3.13 SANs, CA:TRUE, Key Usage, SKID/AKID, 0o600 key permissions | [tools/gen_certs.py](../tools/gen_certs.py#L40-L130) | `tests/test_auth_security.py::test_gen_certs_san_and_ca`, `test_gen_certs_custom_ip_san` |
| **14.2 Join Code** | Challenge-response mutual authentication via Scrypt-derived keys and constant-time HMAC-SHA256 (`hmac.compare_digest`) | [common/auth.py](../common/auth.py#L50-L160) | `tests/test_auth_security.py::test_join_code_challenge_response_success`, `test_wrong_join_code_fails_constant_time`, `tests/test_integration.py::test_wrong_join_code_rejected_no_pieces_requested` |
| **14.2 Join Code** | Rate limiting: 5 failures within window -> 60s block | [sender.py](../sender.py#L40-L80) | `tests/test_auth_security.py::test_auth_rate_limiting_blocks_after_max_failures` |
| **14.2 Join Code** | Read code from `P2P_JOIN_CODE` env var, else `getpass`. `--code` warns. Never log/print secrets | [common/auth.py](../common/auth.py#L210-L245), [common/logutil.py](../common/logutil.py#L13-L73) | `tests/test_auth_security.py::test_get_join_code_env_and_prompt`, `tests/test_tracker.py::test_confidentiality_join_code_and_keys_never_in_state_or_logs` |
| **14.3 Input Validation** | Enforce size caps before allocating (`MAX_PAYLOAD_SIZE`, `MAX_MESSAGE_SIZE`). Validate types/ranges. Unknown type closes connection | [common/protocol.py](../common/protocol.py#L50-L170) | `tests/test_protocol.py::test_message_size_caps_enforced_before_read`, `test_unknown_message_type_rejected`, `test_field_validation`, `tests/test_integration.py::test_client_sends_requests_before_hello_refused_and_disconnected` |
| **14.3 Input Validation** | `REQUEST.index` must be int in range. Sender never accepts paths, offsets, or lengths from peer | [common/protocol.py](../common/protocol.py#L190-L220), [sender.py](../sender.py#L350-L380) | `tests/test_protocol.py::test_request_index_validation`, `tests/test_auth_security.py::test_sender_rejects_out_of_range_piece_request` |
| **14.3 Input Validation** | Idle timeout (30s per `SOCKET_TIMEOUT`), handshake timeout (10s), request rate limits, concurrent connection limits | [sender.py](../sender.py#L260-L330), [config.py](../config.py) | `tests/test_auth_security.py::test_sender_idle_timeout_and_concurrent_limits`, `tests/test_integration.py::test_silent_connections_handshake_timeout_do_not_block` |
| **14.4 Discovery & Tracker** | Untrusted UDP: sanitize strings, 1 KiB packet cap, table cap (256), take IP from packet source, cap distinct device IDs per IP (8), non-eviction of real senders | [common/discovery.py](../common/discovery.py#L100-L360) | `tests/test_discovery.py::test_oversized_packet_rejected`, `test_sanitize_device_name`, `test_spoofed_ip_uses_socket_source`, `test_device_table_cap_and_eviction`, `test_spoofed_heartbeats_cannot_evict_real_sender` |
| **14.4 Discovery & Tracker** | Devices stay `discovered` until verified by authenticated handshake | [common/discovery.py](../common/discovery.py#L180-L240), [receiver.py](../receiver.py) | `tests/test_discovery.py::test_device_verification_lifecycle`, `tests/test_integration.py::test_unverified_device_not_trusted` |
| **14.4 Discovery & Tracker** | Signed reports: HMAC-SHA256 signature, 30s clock skew window, strictly increasing seq number per device, 64 KiB body cap | [tracker/server.py](../tracker/server.py#L140-L205), [tracker/state.py](../tracker/state.py#L160-L230) | `tests/test_tracker.py::test_report_hmac_signature_verification_and_tamper_rejection`, `test_report_timestamp_clock_skew_enforcement`, `test_report_replay_protection_sequence_numbers`, `test_report_oversized_body_rejected` |
| **14.4 Discovery & Tracker** | Dashboard read-only, textContent only, strict CSP (`default-src 'self'`), constant-time PIN rate limiting | [tracker/server.py](../tracker/server.py#L68-L135), [tracker/static/app.js](../tracker/static/app.js) | `tests/test_tracker.py::test_csp_header_strict_no_unsafe_inline`, `test_xss_protection_device_name_rendered_as_plain_text`, `test_pin_security_constant_time_rate_limit_url_strip` |
| **14.4 Discovery & Tracker** | Tracker HTTP only (documented limitation), transfer metadata only, zero secrets in state. Tracker failures isolated | [tracker/server.py](../tracker/server.py), [receiver.py](../receiver.py) | `tests/test_tracker.py::test_confidentiality_join_code_and_keys_never_in_state_or_logs`, `test_tracker_failure_isolation_port_in_use`, `test_tracker_failure_isolation_unreachable_tracker` |
| **14.5 Path Safety** | Reject root/path: absolute, drive letter, colon, `..`, empty, `.`, backslashes, NUL, control chars, > 255 bytes, Windows reserved names (`CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`), dot/space suffix | [common/metadata.py](../common/metadata.py#L58-L112) | `tests/test_metadata.py::test_path_component_validation_rejects_unsafe`, `test_relative_path_validation_rejects_unsafe`, `test_validation_rule_reject_windows_reserved_names` |
| **14.5 Path Safety** | Reject duplicate paths, including case-insensitive duplicates and Unicode NFC/NFD equivalents | [common/metadata.py](../common/metadata.py#L340-L365) | `tests/test_metadata.py::test_validation_rule_case_insensitive_path_collision`, `test_unicode_normalization_and_collision_rejection` |
| **14.5 Path Safety** | Resolve final path and assert inside `out_dir` via `os.path.commonpath`. Never follow symlinks when writing | [common/metadata.py](../common/metadata.py#L410-L442), [common/pieces.py](../common/pieces.py#L220-L240) | `tests/test_metadata.py::test_metadata_validation_with_out_dir_path_traversal`, `test_metadata_validation_rejects_symlink_traversal` |
| **14.6 General** | No secrets in logs, exceptions, or dashboard. No network access beyond LAN. No telemetry. No wildcard CORS | [common/logutil.py](../common/logutil.py#L13-L73), [tracker/server.py](../tracker/server.py#L68-L75) | `tests/test_tracker.py::test_confidentiality_join_code_and_keys_never_in_state_or_logs`, `tests/test_auth_security.py::test_secret_sanitizing_logger` |
| **14.6 General** | Fail closed: any validation failure aborts connection or transfer with clear message | Protocol & auth layers | `tests/test_protocol.py`, `tests/test_auth_security.py`, `tests/test_integration.py` |

---

## 2. Complete List of Spec Deviations & Architectural Decisions

### Deviation 1: API Field Names in `/api/state` vs Section 12.5
A field-by-field comparison of the live JSON output from `GET /api/state` against the specification schema in Section 12.5 reveals that all top-level objects and nested schemas match Section 12.5 exactly:
- `server_time`: exact match
- `tracker`: `{"name", "ip", "web_port", "tls", "auth"}` (exact match)
- `swarm`: `{"name", "swarm_id_short", "piece_size", "total_pieces", "total_bytes", "files_total"}` (exact match)
- `transfer`: `{"state", "started_at", "pieces_done", "bytes_done", "speed_bps", "eta_s", "files_done", "bad_pieces"}` (exact match)
- `senders[]`: `{"device_id", "name", "pieces", "bytes", "speed_bps", "failures", "status", "color_index"}` (exact match)
- `piece_map`: `{"cells", "per_cell", "data"}` (exact match)
- `files[]`: `{"path", "length", "pieces_done", "pieces_total", "complete", "by_sender"}` (exact match)
- `events[]`: `{"t", "level", "type", "msg"}` (exact match)

**Field names that actually differ:**
The only differences are located in the `devices[]` array objects:
- Section 12.5 defines:
  ```json
  {"device_id", "name", "ip", "tcp_port", "role", "status", "trust", "last_seen_age", "swarm_short", "files", "total_bytes"}
  ```
- The implementation provides every required field above, plus two additive convenience alias keys for dashboard JavaScript consumer compatibility:
  - `"id"`: added as an alias for `"device_id"`.
  - `"port"`: added as an alias for `"tcp_port"`.

### Deviation 2: BEACON Field Names
Section 11 specifies `{"v":1,"type":"BEACON","device_id":"<id>","web_port":8080}`. Some narrative text in earlier sections informally referred to `port` or `tracker_url`. The implementation uses canonical `web_port` matching Section 11 schema, and accepts `port` as a fallback.

### Deviation 3: REPORT Interval & Event Batching
Section 5 defines `REPORT_INTERVAL = 0.5s`, while some descriptive text mentioned 1.0s. Senders batch telemetry every 0.5s and emit immediate reports upon piece transfers or handshake events.

### Deviation 4: Sender Identity by `device_id` & Duplicate-Connection Closing
Senders are identified and deduplicated by their authenticated `device_id` communicated in the mutual TLS handshake challenge, rather than by ephemeral `host:port` socket endpoints. If a sender is discovered via both manual `--senders` and automatic UDP discovery, duplicate connections are closed immediately, and stats/bans are keyed strictly by `device_id`.

### Deviation 5: Post-Transfer Dashboard Persistence (`--exit-when-done`)
Per Section 9.3.1, the receiver process keeps the embedded tracker and web dashboard running until `Ctrl+C` after transfer completion, printing `"Transfer complete. Dashboard still running; press Ctrl+C to quit"`. The `--exit-when-done` flag enables immediate process termination for headless testing and scripting.

### Deviation 6: Per-Sender Aggregate Rate Limiting (Shared Pacing Schedule)
The `--throttle-kbps N` flag enforces an aggregate outbound bandwidth limit of `N` KiB/s across all concurrent peer connections on each sender. This is implemented via a **shared pacing schedule** (a synchronized time-slot reservation lock where threads calculate `chunk_seconds = len(piece) / (throttle_kbps * 1024)` and sleep until their scheduled slot `send_at = _next_allowed_send_time`), rather than a per-connection rate limit or token bucket.

### Deviation 7: Real-URL Dashboard Address Banner
The receiver dynamically inspects loopback and active LAN interfaces, printing clickable URLs (`http://127.0.0.1:PORT and http://<LAN IP>:PORT`) and never printing `0.0.0.0`.

### Deviation 8: Piece Map Downsampling Matrix
The spec specifies downsampling to at most 400 cells. We formalized the downsampling formula as `per_cell = ceil(total_pieces / 400)`, with cell states `-1` (all missing), `-3` (partly missing), `color_index` (single sender), and `-2` (mixed senders).

### Deviation 9: One-Way Pinned TLS with Application-Layer Mutual Auth
Senders present a self-signed X.509 cert; receivers pin trust exclusively to `cert.pem`. Mutual authorization is enforced via the Scrypt/HMAC challenge-response exchange using the out-of-band join code rather than X.509 client certificates.

### Deviation 10: HTTP Monitor Dashboard
The dashboard is served over HTTP on port 8080 (read-only telemetry, zero secrets, strict CSP, optional PIN) rather than HTTPS to avoid browser self-signed CA warning dialogs in local classroom environments.

### Deviation 11: Shared Certificate & Private Key across Senders
All seeders share the same certificate and key generated by `tools/gen_certs.py` (individual asymmetric sender certificates are specified as Stretch Goal 5).

### Deviation 12: Metadata SHA-256 vs Per-Piece Digital Signatures
Pieces are verified against SHA-256 hashes in canonical metadata, rather than per-piece asymmetric digital signatures (signed chunks with gossip banning is specified as Stretch Goal 6).

### Deviation 13: UDP Broadcast Fallback (`--senders`)
Added `--senders HOST:PORT ...` manual seeder list as an explicit fallback for networks where Wi-Fi client isolation or routers block UDP broadcast packets.

### Deviation 14: Universal Windows Reserved Names Rejection
Rejects Windows device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`) regardless of host OS to guarantee cross-platform transfer portability.

### Deviation 15: Universal Unicode NFC Normalization
Automatically normalizes file paths to NFC across all platforms to avoid macOS NFD decomposition collisions.
