# P2P Swarm: Build Specification for an AI Coding Agent

> Paste this whole document as your first message, or save it in your project folder as `PROJECT_SPEC.md` and tell the agent: "Read PROJECT_SPEC.md fully, then follow Section 0."

---

## 0. Working agreement (read first)

You are building a **college Computer Networks project** end to end. The person you are working for is a student who must understand, demo, and defend every part of the code in a viva. Follow these rules for the whole project:

1. **Plan first.** Before writing any code, produce a written implementation plan: module list, data structures, thread model, milestones, risks, and any assumptions. Wait for my approval of the plan.
2. **Work phase by phase** (see Section 19). Finish one phase, run its tests, summarise what you did and how to run it, then **stop for my review**. Do not jump ahead.
3. **Readable code for a student.** Python type hints, short docstrings, small functions, and comments that explain *why* (not just what). No clever one-liners, no unnecessary frameworks.
4. **Ask, don't guess.** If a requirement is ambiguous or two requirements conflict, ask. List every assumption you make.
5. **Never weaken a security requirement** (Section 14) to make a test pass. Fix the test or ask me.
6. **Cross-platform:** must run on Windows 10/11, Ubuntu, and macOS with **Python 3.10+** (also verify on Python 3.13, which applies stricter TLS certificate checks by default).
7. **Do not add features** that are not in this document, except those listed under "Stretch goals" (Section 21), and only when I ask.
8. At the end of each phase, give a **suggested git commit message** and a **plain-English explanation** (5 to 10 lines) of what the new code does, so I can explain it in my viva.

---

## 1. Project summary

**P2P Swarm** is a secure, torrent-style file-sharing system for a local network (for example, a phone's mobile hotspot).

- Typical demo: **3 laptops** on one hotspot: **Sender A**, **Sender B**, and **Receiver C**.
- A and B hold **identical copies** of the same file or folder. C downloads it **from both at the same time**: the data is cut into numbered, hashed **pieces**, C pulls different pieces from A and B, verifies each one, and writes each straight into its correct position, so the file is complete when the last piece arrives.
- Devices connect directly by **IP address + TCP port**. All transfer traffic is **encrypted with TLS** and protected by a **join code**.
- Devices on the network are **discovered automatically** (UDP broadcast), with no manual IP typing.
- The receiver hosts a **web dashboard** (a "tracker/monitor") that shows the devices, who is sending to whom, which pieces came from which sender, per-file progress, and an event log. The dashboard must be viewable from any device on the hotspot (for example, a phone).
- Sender and receiver terminals also show live progress (Section 15).

**Key design principles**
- **Pull model:** the **receiver decides** which piece to request and from which sender. Senders only answer requests.
- The tracker/monitor is a **helper, not a middleman**: file data **never** passes through it. If it dies, transfers continue.
- **Discovery is untrusted.** A discovered device is not trusted until it passes TLS and the join-code handshake.

**Terminology:** *sender* = peer holding the complete data (seeder); *receiver* = downloader; *swarm* = the set of devices sharing one specific folder/file; *piece* = fixed-size byte range of the data; *metadata* = description of files + hashes; *swarm ID* = SHA-256 of the canonical metadata.

---

## 2. Scope and non-goals

**In scope:** LAN only; 1 receiver and **2 or more senders** (demo uses 2; code must support N); one swarm per run; single file **or** folder (multi-file); TLS; join code; auto-discovery; web dashboard; tests; documentation.

**Out of scope (do not build):** internet/NAT traversal, DHT, accounts/login system, desktop GUI, mobile app, streaming, bandwidth shaping beyond the demo throttle, a database, Docker.

---

## 3. Tech stack and dependencies

- **Python 3.10+**, standard library wherever possible: `socket`, `ssl`, `threading`, `queue`, `hashlib`, `hmac`, `json`, `struct`, `logging`, `argparse`, `getpass`, `pathlib`, `os`.
- **Third-party (pin versions in `requirements.txt`):** `Flask` (dashboard server), `cryptography` (certificate generation script only), `psutil` (list network interfaces for broadcast addresses), `pytest` (tests, dev only).
- **Frontend:** one static HTML page + vanilla JavaScript + CSS. **No CDN, no external fonts, no frameworks, no build step**: the hotspot may have no internet, so the dashboard must work fully offline.
- **No** `eval`, `exec`, `pickle`, `shell=True`, or dynamic imports of anything received from the network.

---

## 4. Repository layout

```
p2p_swarm/
  README.md
  requirements.txt
  config.py                  # all constants (Section 5)
  sender.py                  # CLI: serve a file/folder
  receiver.py                # CLI: download + embedded tracker/dashboard
  common/
    protocol.py              # message framing, message types, size limits
    metadata.py              # build / canonicalise / validate metadata, swarm ID
    pieces.py                # PieceReader (sender side), PieceWriter (receiver side)
    tlsutil.py               # SSL contexts for server and client
    auth.py                  # join-code key derivation, challenge-response, report signing
    discovery.py             # UDP heartbeat sender + listener + device table
    reporting.py             # batched signed HTTP reports from senders to tracker
    netutil.py               # interface/broadcast address helpers
    logutil.py               # logging setup (no secrets in logs)
  tracker/
    state.py                 # thread-safe in-memory state
    server.py                # Flask app: /api/state, /api/report, static files
    static/index.html
    static/app.js
    static/style.css
  tools/
    gen_certs.py             # generate self-signed cert + key
    make_test_data.py        # build a tricky sample folder (Section 18)
    evil_sender.py           # test-only sender that corrupts pieces (Section 18)
  tests/
    test_protocol.py  test_metadata.py  test_pieces.py  test_auth.py
    test_discovery.py test_tracker_api.py test_integration.py
  docs/
    ARCHITECTURE.md  SECURITY.md  HOTSPOT_TEST_CHECKLIST.md  REPORT_NOTES.md
```

---

## 5. Configuration constants (`config.py`)

| Constant | Value | Meaning |
|---|---|---|
| `PROTOCOL_VERSION` | 1 | Wire protocol version |
| `DEFAULT_PIECE_SIZE` | 65536 (64 KiB) | Default piece size |
| `MIN_PIECE_SIZE` / `MAX_PIECE_SIZE` | 16 KiB / 4 MiB | Allowed range |
| `MAX_PIECES` | 100000 | If the data would need more pieces, the sender picks a larger piece size (power of two) |
| `DEFAULT_TCP_PORT` | 6881 | Sender listening port |
| `DISCOVERY_PORT` | 50000 (UDP) | Heartbeats and beacons |
| `HEARTBEAT_INTERVAL` | 2 s | Announce period |
| `OFFLINE_AFTER` | 8 s | No heartbeat for this long means the device is offline |
| `DEFAULT_WEB_PORT` | 8080 | Dashboard HTTP port |
| `MAX_HEADER_BYTES` | 65536 | Max JSON header of any message |
| `MAX_PIECE_PAYLOAD` | = piece size | Max payload of a `PIECE` message |
| `MAX_METADATA_BYTES` | 16 MiB | Max payload of a `METADATA` message |
| `SOCKET_TIMEOUT` | 30 s | Idle/read timeout on peer connections |
| `MAX_FILES` | 10000 | Max files in one swarm |
| `MAX_TOTAL_BYTES` | 50 GiB | Max total size in one swarm |
| `MAX_CONNECTIONS_PER_SENDER` | 8 | Concurrent connections a sender accepts |
| `MAX_REQUESTS_PER_SEC` | 500 | Per-connection request rate limit |
| `AUTH_MAX_FAILURES` / `AUTH_BLOCK_SECONDS` | 5 / 60 | Failed joins before an IP is temporarily blocked |
| `HASH_STRIKES_TO_BAN` | 3 | Hash failures before a sender is banned for the session |
| `MAX_PIECE_ATTEMPTS` | 6 | Retries of one piece before the transfer fails |
| `CONNECT_RETRIES` | 3 (backoff 1, 2, 4 s) | Reconnect attempts per sender |
| `REPORT_INTERVAL` | 0.5 s | Sender status report batching |
| `REPORT_CLOCK_SKEW` | 30 s | Accepted timestamp difference on signed reports |
| `MAX_DEVICES` | 256 | Tracker device-table cap |
| `MAX_EVENTS` | 200 | Event-log ring buffer size |
| `PIECE_MAP_MAX_CELLS` | 400 | Dashboard piece-map downsampling limit |

---

## 6. Core concepts and algorithms

### 6.1 Hashing
- All hashes are **SHA-256**, stored as lowercase hex.

### 6.2 One continuous byte stream
- The shared data is treated as **one continuous byte stream**: all files, **sorted by relative path** (compare the POSIX-style UTF-8 path strings), concatenated in that order.
- The stream is cut into pieces of `piece_size` bytes. The **last piece may be shorter**. A piece may **span two or more files**.
- Both senders must compute **identical metadata** from identical copies, so ordering and canonicalisation must be fully deterministic.

### 6.3 Piece arithmetic
- `total_size` = sum of file lengths.
- `num_pieces = ceil(total_size / piece_size)` (0 if every file is empty).
- Piece `i` covers stream bytes `[i * piece_size, min((i + 1) * piece_size, total_size))`.
- Each file has a `stream_offset` (cumulative sum of earlier file lengths). A helper maps a piece to the list of `(file_index, offset_in_file, length)` slices it overlaps.

**Worked example (small numbers for illustration only):** one file of 9,500 bytes with piece size 1,000 gives 10 pieces (P0 to P9), where P9 has 500 bytes and starts at byte 9000.

### 6.4 Metadata (JSON)
```json
{
  "version": 1,
  "root": "shared",
  "piece_size": 65536,
  "total_size": 10485760,
  "files": [
    {"path": "notes/a.pdf", "length": 716800, "sha256": "<hex>"},
    {"path": "video.mp4",   "length": 9768960, "sha256": "<hex>"}
  ],
  "piece_hashes": ["<hex>", "<hex>"]
}
```
- `root` = folder name when sharing a folder (receiver writes to `<out>/<root>/<path>`); empty string `""` when sharing a single file (receiver writes to `<out>/<filename>`).
- **Canonical form:** `json.dumps(meta, sort_keys=True, separators=(",", ":"), ensure_ascii=True)` encoded as UTF-8.
- **Swarm ID** = SHA-256 of the canonical bytes (hex). The swarm ID is **never** included inside the hashed metadata. `swarm_id_short` = first 16 hex characters (used in discovery).
- The receiver must **recompute** the swarm ID itself and never trust a sender's claim.

### 6.5 Metadata validation (receiver MUST do all of this before touching the disk)
- Types and required fields are correct; `version == 1`.
- `piece_size` within `[MIN_PIECE_SIZE, MAX_PIECE_SIZE]`; `len(files) <= MAX_FILES`; `total_size <= MAX_TOTAL_BYTES`; `num_pieces <= MAX_PIECES`.
- `total_size == sum(file lengths)`; `len(piece_hashes) == ceil(total_size / piece_size)`; every hash is 64 hex chars.
- **Path safety** for `root` and every `path` (see Section 14.5).
- Enough free disk space for `total_size` (check with `shutil.disk_usage`), otherwise fail with a clear message.

### 6.6 Receiver-side writing (no separate "merge" step)
- Each file is created as `<final path>.part`, **pre-allocated to its full length**.
- When a piece is verified, write each overlapping slice **directly at its correct offset** in the correct `.part` file (positioned write, or seek+write under a per-file lock). Pieces may arrive in any order.
- Track `remaining_pieces[file_index]` (distinct pieces overlapping that file with length > 0). When it reaches 0: flush, verify the file's SHA-256 against metadata, then **rename `.part` to the final name** and emit `FILE_COMPLETE`.
- Zero-length files are created immediately (no pieces needed). Parent directories are created as required.
- **Duplicates:** a piece already marked done is ignored (check under the lock).
- Existing target files: refuse unless `--overwrite` is given.

---

## 7. Wire protocol (peer to peer, over TCP + TLS)

### 7.1 Framing
Every message is: `8-byte prefix` + `JSON header` + `optional binary payload`.
- Prefix: two unsigned 32-bit big-endian integers (`!II`): `header_len`, `payload_len`.
- Header is UTF-8 JSON object with at least `"type"`.
- Reading must loop until exactly the required number of bytes has arrived (TCP is a stream). Writing must use `sendall`.
- **Reject before allocating** anything if `header_len > MAX_HEADER_BYTES` or `payload_len` exceeds the cap allowed for the expected message type (the receiver passes the allowed maximum when it calls the read function).
- Any parsing error or protocol violation closes the connection.

### 7.2 Messages

| Type | Direction | Header fields | Payload |
|---|---|---|---|
| `CHALLENGE` | sender to receiver | `v`, `nonce` (hex, 32 random bytes), `device_id`, `name` | none |
| `HELLO` | receiver to sender | `v`, `device_id`, `name`, `role`, `proof` (hex) | none |
| `WELCOME` | sender to receiver | `v`, `proof` (hex), `swarm_id` | none |
| `GET_METADATA` | receiver to sender | none | none |
| `METADATA` | sender to receiver | `swarm_id` | canonical metadata JSON bytes |
| `REQUEST` | receiver to sender | `index` | none |
| `PIECE` | sender to receiver | `index`, `length` | piece bytes |
| `ERROR` | either | `code`, `message` | none |
| `BYE` | either | none | none |

Error codes: `AUTH_FAILED`, `RATE_LIMITED`, `BUSY`, `BAD_REQUEST`, `BAD_INDEX`, `VERSION`, `INTERNAL`.

### 7.3 Handshake sequence
1. Receiver opens TCP, completes the TLS handshake (Section 14.1).
2. Sender sends `CHALLENGE` with a fresh random nonce.
3. Receiver replies `HELLO` with `proof = HMAC-SHA256(auth_key, nonce_bytes || device_id_utf8)`.
4. Sender verifies in constant time (`hmac.compare_digest`). On failure: send `ERROR(AUTH_FAILED)`, record the failure for rate-limiting, close.
5. On success, the sender replies `WELCOME` with `proof_server = HMAC-SHA256(auth_key, b"server" || nonce_bytes || receiver_device_id_utf8)` so the **receiver can verify the sender knows the join code too (mutual authentication)**, plus its `swarm_id`.
6. Receiver sends `GET_METADATA`; sender replies `METADATA`.
7. The **first** sender's metadata defines the swarm after validation (6.5). Every **later** sender's recomputed swarm ID **must match exactly**, otherwise: disconnect, log an event `SWARM_MISMATCH`, never request pieces from it.
8. Receiver sends `REQUEST(index)` and sender answers `PIECE` or `ERROR`. Repeat. `BYE` when finished.

### 7.4 Key derivation
- `auth_key = hashlib.scrypt(join_code, salt=b"p2p-swarm/auth/v1", n=2**14, r=8, p=1, dklen=32)`.
- `report_key = HMAC-SHA256(auth_key, b"report")` (used to sign sender reports to the tracker).
- The join code is **never** sent over the network and **never** put in any broadcast.

---

## 8. Sender (`sender.py`)

Purpose: serve a file or folder to authorised receivers.

1. Load certificate and key (required; exit with a clear message if missing).
2. Read the join code (Section 16). Derive keys.
3. Scan `--path`: **do not follow symlinks** (skip with a warning); skip unreadable files with a warning; fail if there are no files. Build metadata with a **progress bar** (hashing can take a while). Compute the swarm ID.
4. Auto-choose piece size: default 64 KiB, or larger (power of two, up to the max) if `num_pieces` would exceed `MAX_PIECES`.
5. Start the TLS server on `--port` (bind `0.0.0.0`), one thread per connection, with `MAX_CONNECTIONS_PER_SENDER`, `SOCKET_TIMEOUT`, and the per-connection request rate limit. Reject over-limit connections with `ERROR(BUSY)`.
6. Start discovery heartbeats (Section 11) unless `--no-discovery`.
7. Start the status reporter (Section 12) once a tracker beacon is heard.
8. Serve requests: validate `index` is an integer in `[0, num_pieces)`; read the byte range across files via `PieceReader`; send `PIECE`. **Never** use any path or offset given by the client; only the piece index.
9. If a source file's size or modification time changed since startup, answer `ERROR(INTERNAL)` and log a warning (do not serve data that no longer matches the hashes).
10. Optional demo throttle `--throttle-kbps N`: limit upload speed so small transfers are visible on the dashboard in class.
11. Log and report: auth failures (with source IP), connections, pieces sent.

---

## 9. Receiver (`receiver.py`)

Purpose: find senders, download from all of them in parallel, verify, reassemble, and host the dashboard.

### 9.1 Startup
1. Parse arguments; read the join code; load the trusted certificate.
2. Start the **tracker/monitor** (web server + discovery listener + beacon) unless `--no-tracker`.
3. Determine senders: from `--senders host:port ...` (manual) and/or **auto-discovered** devices with `role=sender`. Group candidates by `swarm_id_short`. If several groups exist, require `--swarm NAME_OR_ID`; otherwise use the single group.
4. Wait until `--min-senders` (default 2) candidates are found or `--discover-timeout` (default 20 s) passes with at least one; otherwise exit with a clear message.

### 9.2 Connection workers
- One **worker thread per sender**. Each: connect + TLS + handshake (Section 7.3), then loop on the shared queue.
- **Dynamic join:** if a new sender (same swarm) is discovered mid-transfer and passes the handshake, start a worker for it.
- On connection errors: reconnect up to `CONNECT_RETRIES` with backoff; then mark the sender offline.

### 9.3 Work queue (the heart of the project)
- A shared `queue` of **missing piece indexes**, plus a lock-protected `done` set and `attempts[i]` counters.
- Worker loop: `while len(done) < total:` take an index (with a 1-second timeout; an empty queue does **not** end the worker, because failed pieces can be put back later), send `REQUEST`, receive `PIECE`, check `length` and **SHA-256 against metadata**.
  - **Match:** write via `PieceWriter`, add to `done`, record which sender supplied it (for the dashboard), update counters.
  - **Mismatch:** discard the bytes, put the index back, increment `attempts[i]` and the sender's **strike count**. At `HASH_STRIKES_TO_BAN` strikes the sender is **banned for the session**: close it, emit `SENDER_BANNED`.
  - **Connection error/timeout:** put the index back and handle reconnect (9.2).
  - If `attempts[i] >= MAX_PIECE_ATTEMPTS`: fail the transfer with a clear error.
- Faster senders naturally serve more pieces because each worker pulls its next piece as soon as it is free. **Do not pre-assign ranges** to senders.
- One outstanding request per connection in v1 (simple and correct).

### 9.3.1 Completion
- When all pieces are done and all files verified/renamed: print the summary (Section 15), emit `TRANSFER_COMPLETE`. Keep the dashboard running until Ctrl+C unless `--exit-when-done`.
- If every worker has exited and the transfer is incomplete: fail with exit code 1 and a clear message (unless new senders can still appear via discovery within the discovery timeout).
- Ctrl+C: stop gracefully, close sockets, leave `.part` files, print a note.

---

## 10. Piece reading and writing (`common/pieces.py`)

- `PieceReader(root_path, metadata)` reads any piece by index across file boundaries (sender side). Open files read-only; cap the number of open handles.
- `PieceWriter(out_dir, metadata)` implements Section 6.6 and is **thread-safe**: multiple worker threads write different pieces concurrently.
- Both use the same slice-mapping helper from `metadata.py`, and both are unit-tested against the same edge cases (Section 18).

---

## 11. Automatic discovery (`common/discovery.py`)

Two UDP message kinds on `DISCOVERY_PORT`, JSON, no secrets.

**HEARTBEAT** (every `HEARTBEAT_INTERVAL`, from every device):
```json
{"v":1,"type":"HEARTBEAT","device_id":"<random 16 hex>","name":"Laptop-A",
 "role":"sender","tcp_port":6881,"swarm_name":"shared",
 "swarm_id_short":"9f2c41aa7b3d0e55","files":3,"total_bytes":10485760}
```
**BEACON** (every `HEARTBEAT_INTERVAL`, from the tracker only):
```json
{"v":1,"type":"BEACON","device_id":"<tracker device id>","web_port":8080}
```
Rules:
- `device_id` is a random ID generated at each start; **identity is the device_id, never the name or IP**.
- Send each message to `255.255.255.255` **and** to the directed broadcast address of every IPv4 interface (use `psutil` for addresses and netmasks; a phone hotspot subnet may be small, for example a /28). Handle interfaces that fail without crashing.
- Listener: bind with `SO_REUSEADDR` (and `SO_REUSEPORT` where available) so several processes can be tested on one laptop. Ignore messages from the device's own `device_id`.
- The **sender's IP is taken from the UDP packet's source address**, never from the message body.
- Device table entry: `device_id`, name, ip, tcp_port, role, swarm info, `last_seen`, `status` (`online`/`offline`), `trust` (`discovered`/`verified`/`banned`).
- Offline after `OFFLINE_AFTER` seconds without a heartbeat; remove entries after a longer expiry; **cap the table at `MAX_DEVICES`**; drop oversized or malformed packets (max 1 KiB).
- Sanitise names: max 32 characters, printable characters only.
- A device becomes **verified** only after the receiver completes TLS + join-code authentication with it.
- Senders that hear the beacon learn the tracker address (source IP + `web_port`) and start reporting.
- **Fallbacks** if broadcasts are blocked (Section 16): `--senders host:port` on the receiver, and `--tracker host:port` on the sender.

---

## 12. Tracker/monitor and reporting (`tracker/`, `common/reporting.py`)

### 12.1 What it is
Runs **inside the receiver process**. It: listens to discovery, sends the beacon, keeps an in-memory **state** (one lock around all mutations), and serves the dashboard and a JSON API. It never handles file data. If it fails, transfers must continue.

### 12.2 Reports from senders
- Senders `POST /api/report` to the tracker, batched every `REPORT_INTERVAL` and only when something changed.
- Body (JSON): `{"device_id", "seq", "ts", "pieces_sent", "bytes_sent", "active_connections", "events": [...]}`.
- Header `X-Signature` = hex `HMAC-SHA256(report_key, raw_body)`.
- Tracker verifies: signature (constant time), `ts` within `REPORT_CLOCK_SKEW`, `seq` strictly increasing per device (replay protection), body size at most 64 KiB, and known/valid device. Invalid reports get 401/400 and are counted, never trusted.
- The receiver updates the state **directly in-process** (no HTTP) for downloads.

### 12.3 Event types (for the log)
`DEVICE_JOINED`, `DEVICE_LEFT`, `SENDER_VERIFIED`, `SWARM_MISMATCH`, `TRANSFER_STARTED`, `PIECE_FAILED`, `SENDER_BANNED`, `FILE_COMPLETE`, `TRANSFER_COMPLETE`, `TRANSFER_FAILED`, `AUTH_REJECTED` (a wrong join code was tried; show the source IP). Keep the last `MAX_EVENTS` in a ring buffer.

### 12.4 Metrics definitions (important)
- **Per sender:** pieces delivered, bytes delivered, current speed (moving average over about 3 seconds), hash failures, status.
- **Per file:** pieces done / total, complete or not, and **bytes contributed by each sender** (because pieces span files, "files sent by A" is not meaningful; show per-file contribution percentages instead).
- **Overall:** files complete of total, pieces done, bytes done, speed, ETA, bad pieces.

### 12.5 HTTP API (read-only for browsers)
- `GET /` and static files.
- `GET /api/state` returns:
```json
{
  "server_time": 1730000000.0,
  "tracker": {"name":"Laptop-C","ip":"192.168.43.12","web_port":8080,"tls":true,"auth":true},
  "devices": [{"device_id":"ab12","name":"Laptop-A","ip":"192.168.43.10","tcp_port":6881,
               "role":"sender","status":"online","trust":"verified","last_seen_age":1.2,
               "swarm_short":"9f2c41aa7b3d0e55","files":3,"total_bytes":10485760}],
  "swarm": {"name":"shared","swarm_id_short":"9f2c41aa7b3d0e55","piece_size":65536,
            "total_pieces":160,"total_bytes":10485760,"files_total":3},
  "transfer": {"state":"downloading","started_at":1730000000.0,"pieces_done":58,
               "bytes_done":3801088,"speed_bps":2100000,"eta_s":3,"files_done":1,"bad_pieces":0},
  "senders": [{"device_id":"ab12","name":"Laptop-A","pieces":36,"bytes":2359296,
               "speed_bps":1200000,"failures":0,"status":"active","color_index":0}],
  "piece_map": {"cells":160,"per_cell":1,"data":[0,1,0,-1,-1]},
  "files": [{"path":"notes/a.pdf","length":716800,"pieces_done":11,"pieces_total":11,
             "complete":true,"by_sender":{"ab12":400000,"cd34":316800}}],
  "events": [{"t":1730000001.0,"level":"info","type":"SENDER_VERIFIED","msg":"Laptop-A verified"}]
}
```
  `transfer.state` is one of `idle`, `discovering`, `downloading`, `complete`, `failed`.
  `piece_map.data`: `-1` = missing, otherwise the `color_index` of the sender; if more pieces than `PIECE_MAP_MAX_CELLS`, downsample into cells (`per_cell` pieces each) and use `-2` for "mixed sources", `-3` for "partly missing".
- `POST /api/report` (signed, Section 12.2). No other write endpoints. **The dashboard is strictly read-only.**
- Optional `--web-pin PIN`: if set, `/api/state` and the page require the PIN (cookie after a first successful entry).

---

## 13. Dashboard UI (`tracker/static/`)

A single page, readable on a projector and on a phone (responsive), polling `/api/state` once per second. **Never** use `innerHTML` with network-derived text: use `textContent` or equivalent.

Sections:
1. **Header:** swarm name, short swarm ID, badges for `TLS ON` and `AUTH ON`, overall progress bar, speed, ETA, state.
2. **Devices:** one card per device: status dot (online/offline), name, IP:port, role, trust badge (`discovered` / `verified` / `banned`), last seen. "Possible peer" label for discovered senders in the same swarm.
3. **Live transfer map (inline SVG):** sender nodes on the left, receiver on the right; line thickness proportional to each sender's share of delivered bytes, label with pieces and speed. Offline or banned senders are greyed out.
4. **Piece map:** a grid of cells coloured by the sender that supplied each piece (grey = missing). Colour-blind-safe palette **and** a letter (A, B, ...) on or in each sender's legend entry; tooltip shows piece number and sender. A brief highlight for failed pieces.
5. **Files:** per-file bar **stacked by sender colour** (for example "70% from A / 30% from B"), plus "Files complete: 1 of 3".
6. **Sender stats table:** pieces, bytes, speed, failures, status.
7. **Event log:** newest first, with level colours.
8. Show a clear **"Tracker unreachable" banner** if polling fails.

Security headers on every response: `Content-Security-Policy: default-src 'self'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` for the API.

---

## 14. Security requirements (all are MUST)

### 14.1 TLS
- Peer connections use TLS with `ssl.SSLContext`; **minimum TLS 1.2** (prefer 1.3), default secure ciphers.
- Senders present a certificate generated by `tools/gen_certs.py`. The receiver **pins trust to that certificate**: `verify_mode = CERT_REQUIRED`, the cert file loaded as the only trust anchor, `check_hostname = False` (peers are addressed by IP).
- **Never** use `CERT_NONE` or disable verification, not even in tests. Tests use generated certificates.
- `gen_certs.py` must produce a certificate that works with Python 3.13's strict verification: include Subject Alternative Names (`localhost`, `127.0.0.1`, plus any IPs passed with `--ip`), Basic Constraints (CA:TRUE so it can act as the trust anchor), Key Usage, Subject Key Identifier and Authority Key Identifier. Output `certs/cert.pem` and `certs/key.pem`; set restrictive permissions on the key where the OS allows. Explain in the README: copy **cert + key to the senders** and **only the cert to the receiver**.

### 14.2 Join code (second factor)
- Challenge-response exactly as Section 7.3/7.4, mutual, constant-time comparisons.
- **Rate limiting:** after `AUTH_MAX_FAILURES` failures from one IP within the window, refuse connections from it for `AUTH_BLOCK_SECONDS`.
- Read the code from the `P2P_JOIN_CODE` environment variable, else prompt with `getpass`. A `--code` argument is allowed but must print a warning that command-line arguments can be seen by other users. **Never log or print the code or derived keys.**

### 14.3 Input validation
- Enforce all size caps **before allocating** (Section 7.1). Validate every field's type and range. Unknown message types close the connection.
- `REQUEST.index` must be an int in range. The sender never accepts paths, offsets, or lengths from the peer.
- Per-connection idle timeout and request rate limit; limit concurrent connections.

### 14.4 Discovery and tracker hardening
- Discovery data is untrusted: sanitise strings, cap sizes, cap the table, take IPs from the packet source.
- Devices stay `discovered` until verified by a successful authenticated handshake.
- Reports must pass signature, timestamp, and replay checks (12.2).
- Dashboard is read-only; escape or avoid HTML; CSP headers; optional PIN.
- The tracker listens on HTTP only (documented limitation): it exposes only transfer metadata, never file contents or the join code.

### 14.5 Path safety (receiver, and when building metadata on senders)
Reject any `root` or `path` that: is absolute; contains a drive letter or colon; contains `..` or empty or `.` components; uses backslashes; contains NUL or control characters; has a component longer than 255 bytes; or is a Windows reserved name (`CON`, `PRN`, `AUX`, `NUL`, `COM1` to `COM9`, `LPT1` to `LPT9`, with or without extension) or ends with a dot or space. Reject **duplicate paths, including case-insensitive duplicates**. After joining with the output directory, **resolve the final path and assert it is inside the output directory** (`os.path.commonpath`). Never follow symlinks when writing.

### 14.6 General
- No secrets in logs, exceptions, or the dashboard. No network access beyond the LAN. No telemetry. No wildcard CORS.
- Fail closed: any validation failure aborts that connection or transfer with a clear message.

---

## 15. Terminal output (required)

**Sender screen**
```
P2P Swarm Sender | name=Laptop-A | 192.168.43.10:6881 | TLS on
Sharing: shared/ (3 files, 10.0 MB, 160 pieces of 64 KiB)  swarm=9f2c41aa
Tracker: found at 192.168.43.12:8080
Receiver Laptop-C connected (verified)
Sent piece   5/160 -> Laptop-C
Sent piece   7/160 -> Laptop-C
... [pieces sent: 93] [2.1 MB/s]
```
**Receiver screen**
```
P2P Swarm Receiver | Laptop-C | dashboard: http://192.168.43.12:8080
Discovered senders: Laptop-A (192.168.43.10), Laptop-B (192.168.43.11)  swarm=9f2c41aa
Verified Laptop-A  OK     Verified Laptop-B  OK
Piece   1/160 from Laptop-A  OK
Piece   2/160 from Laptop-B  OK
[##########----------]  50%  80/160 pieces  4.2 MB/s  ETA 00:02
File complete: notes/a.pdf
Summary: 160 pieces in 6.1 s | A: 93 (58%) | B: 67 (42%) | bad pieces: 0 | files: 3/3
```
Use plain text (no heavy TUI library). Update the progress bar in place and keep it uncluttered. On a bad piece or ban, print a clear warning line.

---

## 16. Command-line interface

```
python tools/gen_certs.py [--out certs] [--ip IP ...]

python sender.py   --path PATH [--port 6881] [--name NAME] [--cert certs/cert.pem] [--key certs/key.pem]
                   [--piece-size BYTES] [--throttle-kbps N] [--no-discovery] [--discovery-port 50000]
                   [--tracker HOST:PORT] [--code CODE]

python receiver.py --out DIR [--cert certs/cert.pem] [--senders HOST:PORT ...] [--swarm NAME_OR_ID]
                   [--min-senders 2] [--discover-timeout 20] [--web-port 8080] [--web-host 0.0.0.0]
                   [--web-pin PIN] [--no-tracker] [--exit-when-done] [--overwrite]
                   [--discovery-port 50000] [--code CODE]
```
- Join code from `P2P_JOIN_CODE` or an interactive prompt (Section 14.2).
- All IPs/ports are arguments: **no hardcoded addresses** (hotspot IPs change between sessions).
- `--help` for every script with examples. Friendly error messages (no raw stack traces for expected errors like "port in use", "cert not found", "wrong join code", "folder not found").

---

## 17. Edge cases that must be handled (and tested)

| Situation | Required behaviour |
|---|---|
| Empty folder / no readable files | Sender exits with a clear message |
| File of 0 bytes | Included in metadata; receiver creates it empty |
| File smaller than one piece | Works; shares a piece with neighbouring files |
| File ends exactly on a piece boundary | Works |
| Last piece shorter than piece size | Sender sends the short length; receiver expects it |
| Sender dies mid-transfer | Its piece returns to the queue; other sender continues |
| Sender returns / new sender appears | Dynamic join (9.2) |
| Corrupted piece from a sender | Discard, retry elsewhere, strike, ban at threshold |
| Wrong join code | Rejected, rate-limited, shown on dashboard as `AUTH_REJECTED` |
| Wrong/foreign certificate | Receiver refuses the connection |
| Senders have different data | Second sender rejected with `SWARM_MISMATCH` |
| Malicious metadata (traversal, duplicates, huge counts, bad totals) | Rejected before any file is created |
| Duplicate piece delivery | Ignored |
| Output file already exists | Error unless `--overwrite` |
| Not enough disk space | Clear error before pre-allocation |
| Source file changed after sender started | Sender refuses to serve; logs a warning |
| Port already in use | Clear error |
| Broadcast blocked / no discovery | Manual `--senders` / `--tracker` fallback works |
| Tracker unreachable from sender | Sender keeps serving; retries reporting quietly |
| Device name contains HTML/script | Shown as plain text everywhere |
| Ctrl+C | Graceful shutdown, `.part` files left in place |

---

## 18. Testing requirements

Use `pytest`. Tests must be deterministic, run offline on one machine, and finish in a reasonable time.

**Test tools**
- `tools/make_test_data.py`: creates a sample folder containing: an empty file, a 1-byte file, a file of exactly `k * piece_size` bytes, files of `piece_size - 1` and `piece_size + 1` bytes, a 5 MB random file, nested directories, and a file with a Unicode name.
- `tools/evil_sender.py`: a **test-only** sender that deliberately corrupts every Nth piece, to prove the receiver's hash checks, retries, strikes, and bans work. It must be clearly labelled as a test tool and use the same TLS/auth as real senders.

**Unit tests:** framing round-trip and size-cap rejection; metadata build is deterministic (same folder gives the same swarm ID); metadata validation rejects every malicious case in 14.5 and 6.5; piece/file slice mapping on all boundary cases; `PieceWriter` with out-of-order, duplicate, and concurrent writes ends with files byte-identical to the originals; auth success/failure; constant-time compare used; rate limiter; report signature, timestamp, and replay checks; dashboard state reducer and piece-map downsampling; name sanitisation.

**Integration tests (localhost, different ports):**
1. 2 senders + receiver, sample folder: output tree is identical (compare SHA-256 of every file); both senders contributed pieces.
2. Single-file share.
3. Kill one sender mid-transfer: transfer still completes.
4. Evil sender + good sender: transfer completes correctly, strikes recorded, evil sender banned.
5. Wrong join code: rejected; correct code accepted.
6. Cert mismatch: connection refused.
7. Mismatched data between senders: second sender rejected.
8. `/api/state` content is correct during and after a transfer; a device named `<script>alert(1)</script>` appears only as text in the API and in the page.
9. Unsigned or replayed report to `/api/report` is rejected.

**Manual test checklist (`docs/HOTSPOT_TEST_CHECKLIST.md`):** three laptops on a real phone hotspot: IP discovery, firewall prompts (allow Python on the senders and receiver), `ping` between laptops, discovery working, dashboard opened from a phone, throttled transfer with visible A/B colouring, unplug a sender mid-transfer, wrong join code attempt, and a packet-capture comparison (plaintext vs TLS) on the student's own devices.

---

## 19. Phases and acceptance criteria

Stop after each phase for review.

| Phase | Deliverable | Done when |
|---|---|---|
| **0** | Plan + scaffold: layout, `config.py`, logging, `requirements.txt`, README stub | I approve the plan; project runs `pytest` (empty) |
| **1** | Core library: `protocol.py`, `metadata.py`, `pieces.py` + unit tests | All unit tests for framing, metadata, validation, piece mapping, writer pass |
| **2** | Plain-TCP (no TLS yet) 1 sender + 1 receiver, single and multi-file, terminal output | Output tree byte-identical; edge cases from Section 17 that apply pass |
| **3** | 2+ senders, shared work queue, retries, strikes/bans, dynamic join, `evil_sender.py` | Integration tests 1, 3, 4 pass; A/B split visible in output |
| **4** | TLS + join code + `gen_certs.py` + rate limiting | Integration tests 5, 6 pass; plain TCP removed or disabled; security unit tests pass |
| **5** | Discovery: heartbeats, listener, device table, beacon, `--senders` fallback | Terminal table of live devices on localhost, then on the hotspot |
| **6** | Tracker state + signed reporting + `/api/state` | API reflects live transfers; report auth tests pass |
| **7** | Dashboard UI (Section 13) | All 8 sections work against a live transfer; XSS test passes |
| **8** | Hardening, throttle option, docs (`README`, `ARCHITECTURE`, `SECURITY`, `HOTSPOT_TEST_CHECKLIST`, `REPORT_NOTES`), full test run | Everything in Section 20 is satisfied |

---

## 20. Documentation deliverables and definition of done

- **README.md:** what it is, requirements, install, generating certs, running 2 senders + receiver (localhost demo and hotspot demo), CLI reference, troubleshooting (firewall, hotspot isolation, broadcast blocked, port in use).
- **docs/ARCHITECTURE.md:** diagrams (ASCII is fine) of components, discovery flow, handshake sequence, piece lifecycle (request, verify, write, reassemble), thread model, and state/API.
- **docs/SECURITY.md:** threat model and what each control defends against (eavesdropping, rogue peer, corrupted/poisoned pieces, spoofed discovery, forged reports, path traversal, XSS, resource exhaustion) plus **known limitations** (shared cert/key across senders, HTTP dashboard, LAN-only, no per-piece signatures).
- **docs/REPORT_NOTES.md:** limitations and future work, a "Related work" paragraph (BitTorrent, BEP 14 Local Service Discovery, smart banning in existing clients, LocalSend) explaining how this project differs, and **15 likely viva questions with short answers** based on this code (for example: pieces vs packets, why TCP, why hashes are not encryption, why the receiver pulls, how reassembly works, what TLS and the join code each protect).

**Definition of done:** all tests pass; a clean checkout can be set up from the README alone; the localhost demo and a hotspot demo both work; no requirement in Sections 7 to 17 is silently skipped (list any deviation explicitly).

---

## 21. Stretch goals (do NOT start unless I ask)

1. Selective download: choose which files to fetch (request only overlapping pieces).
2. Request pipelining (several outstanding requests per connection).
3. Resume: re-hash an existing `.part` file and request only missing pieces.
4. Receiver becomes a seeder after finishing.
5. Per-sender certificates instead of one shared cert/key.
6. **Signed pieces with verifiable bad-piece reports**: each sender signs pieces, and a failed piece plus the signature is proof that peers can verify and gossip, so the whole swarm can ban a bad sender.
7. Server-Sent Events instead of polling; QR code on the receiver to open the dashboard.
8. Whole-swarm rarest-first picking when senders hold different pieces (bitfields).

---

## Appendix A: Kickoff message (paste after the spec)

> Read the whole specification above. Do **not** write code yet. Reply with: (1) your understanding of the project in 10 lines, (2) the implementation plan for Phases 0 to 8 (modules, thread model, risks), (3) a list of every ambiguity or conflict you noticed and your proposed answer to each, and (4) the exact commands I will run to set up and test on Windows and Linux. Wait for my approval before starting Phase 0.

## Appendix B: Per-phase prompts (paste one at a time)

- **Phase 0:** "Approved. Do Phase 0 only: scaffold the repository per Section 4, `config.py` with Section 5 constants, logging setup, `requirements.txt` with pinned versions, and a README stub. Run pytest. Then stop and summarise."
- **Phase 1:** "Do Phase 1 only: `protocol.py`, `metadata.py`, `pieces.py` with unit tests covering every case in Sections 6, 7.1, 14.5 and 17 that applies. Explain the piece-to-file mapping in plain English. Stop for review."
- **Phase 2:** "Do Phase 2 only: plain-TCP sender and receiver (one sender), single file and folder, terminal output from Section 15, byte-identical output check. Stop for review."
- **Phase 3:** "Do Phase 3 only: multi-sender receiver with the shared work queue, retries, strikes and bans, dynamic join, and `evil_sender.py`. Run integration tests 1, 3 and 4. Show me the A/B piece split in the output. Stop for review."
- **Phase 4:** "Do Phase 4 only: TLS (pinned cert), `gen_certs.py` (must work on Python 3.13), join-code mutual challenge-response, rate limiting. Remove or disable plain TCP. Run integration tests 5 and 6 plus the security unit tests. Stop for review."
- **Phase 5:** "Do Phase 5 only: UDP discovery per Section 11 including directed broadcasts via psutil, device table, beacon, verified-state handling, and manual fallbacks. Show a live terminal device table. Stop for review."
- **Phase 6:** "Do Phase 6 only: tracker state, signed sender reports with replay protection, and `/api/state` exactly as specified in Section 12.5. Add tests. Stop for review."
- **Phase 7:** "Do Phase 7 only: the dashboard per Section 13 (offline, no CDN, no innerHTML with network data, CSP headers). If you can open a browser, verify it visually against a live throttled transfer and show me screenshots. Stop for review."
- **Phase 8:** "Do Phase 8 only: hardening pass against Section 14, the `--throttle-kbps` demo option, all docs from Section 20, a full test run, and a list of any spec deviations. Stop for review."
