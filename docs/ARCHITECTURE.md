# P2P Swarm: System Architecture & Design

This document details the software architecture, protocol mechanics, threading models, and data flows of the **P2P Swarm** implementation.

---

## 1. System Component Map

```
+---------------------------------------------------------------------------------+
|                                 P2P SWARM NETWORK                               |
+---------------------------------------------------------------------------------+
|                                                                                 |
|   +-----------------------+                    +----------------------------+   |
|   |   Sender A (Seeder)   |                    |     Sender B (Seeder)      |   |
|   |  - PieceReader        |                    |  - PieceReader             |   |
|   |  - TLS Server (Pinned)|                    |  - TLS Server (Pinned)     |   |
|   |  - Discovery Heartbeat|                    |  - Discovery Heartbeat     |   |
|   |  - Report Client      |                    |  - Report Client           |   |
|   +-----------+-----------+                    +--------------+-------------+   |
|               |                                               |                 |
|       TLS 1.3 | Pull Requests                         TLS 1.3 | Pull Requests   |
|       Pieces  | (64 KiB chunks)                       Pieces  | (64 KiB chunks) |
|               |                                               |                 |
|               +-----------------------+-----------------------+                 |
|                                       |                                         |
|                                       v                                         |
|                       +-------------------------------+                         |
|                       |     Receiver C (Downloader)   |                         |
|                       |  - SwarmReceiver Manager      |                         |
|                       |  - DiscoveryListener (UDP)    |                         |
|                       |  - Shared Work Queue (Pieces) |                         |
|                       |  - Worker Thread Pool         |                         |
|                       |  - PieceWriter (.part files)  |                         |
|                       |  - Embedded Tracker Server    |                         |
|                       |  - Real-Time Monitor State    |                         |
|                       +---------------+---------------+                         |
|                                       |                                         |
|                                       | HTTP Polling (1s)                       |
|                                       v                                         |
|                       +-------------------------------+                         |
|                       |    Web Dashboard (Browser)    |                         |
|                       |  - Inline SVG Topology Map    |                         |
|                       |  - Downsampled Piece Matrix   |                         |
|                       |  - Per-File Progress Bars     |                         |
|                       +-------------------------------+                         |
+---------------------------------------------------------------------------------+
```

---

## 2. Discovery Flow (UDP Broadcast)

Discovery operates over UDP on `DISCOVERY_PORT` (50000). Senders broadcast `HEARTBEAT` datagrams every 2.0 seconds (`HEARTBEAT_INTERVAL`). Sockets bind using `SO_REUSEADDR` (and `SO_REUSEPORT` where supported).

```
   Sender A (Port 6881)              Receiver C                  Sender B (Port 6882)
          |                              |                               |
          |--- UDP HEARTBEAT (1 KiB) --->|                               |
          |    {device_id, name,         |                               |
          |     swarm_short, port: 6881} |                               |
          |                              |<--- UDP HEARTBEAT (1 KiB) ----|
          |                              |     {device_id, name,         |
          |                              |      swarm_short, port: 6882} |
          |                              |                               |
          |                     [Candidate Devices]                      |
          |                     Table Capped: 256 (MAX_DEVICES)          |
          |                     IP Capped: 8/IP                          |
          |                              |                               |
          |                              |-- BEACON (Port 8080) -------->|
          |                              |   {device_id, web_port: 8080} |
```

---

## 3. Connection & Mutual Authentication Handshake Sequence

Before any metadata or piece data is requested, peer connections establish TLS 1.3 encryption and complete mutual challenge-response authentication using Scrypt-derived keys.

```
   Receiver C (Client)                                          Sender A (Server)
          |                                                             |
          |================= TCP SYN / ACK Handshake ===================|
          |                                                             |
          |----------------- TLS 1.3 ClientHello ---------------------->|
          |<---------------- TLS 1.3 ServerHello + Cert ----------------|
          |   [Verify Server Cert matches pinned cert.pem]              |
          |================= Encrypted TLS Established =================|
          |                                                             |
          |--- HELLO (client_nonce, client_name) ---------------------->|
          |                                                             |
          |                                [Generate server_nonce]      |
          |                                [Derive Scrypt auth_key]     |
          |                                [Compute server_proof]       |
          |<-- HELLO_ACK (server_nonce, server_name, server_proof) -----|
          |                                                             |
          |   [Derive Scrypt auth_key]                                  |
          |   [Verify server_proof == HMAC(auth_key, transcript)]       |
          |   [Compute client_proof = HMAC(auth_key, transcript)]       |
          |                                                             |
          |--- AUTH (client_proof) ------------------------------------>|
          |                                [Verify client_proof]        |
          |<-- AUTH_ACK ("OK", swarm_id) -------------------------------|
          |                                                             |
          |   [Device Status Marked: "VERIFIED"]                        |
          |                                                             |
          |--- GET_METADATA ------------------------------------------->|
          |<-- METADATA (Canonical JSON) -------------------------------|
          |                                                             |
```

---

## 4. Piece Lifecycle: Request, Verify, Write, Reassemble

```
   Work Queue                  Worker Thread                     Disk / PieceWriter
       |                             |                                    |
  [Pop Piece i]                      |                                    |
       |---------------------------->|                                    |
                                     |--- REQUEST(index=i) (to Sender)    |
                                     |<-- PIECE(index=i, data) (from Snd) |
                                     |                                    |
                           [SHA-256 Verification]                         |
                           Compute sha256(data)                           |
                           Assert == metadata.piece_hashes[i]             |
                                     |                                    |
                                     |--- write_piece(index=i, data) ---->|
                                                                          |
                                                      [Map Piece to Slices across Files]
                                                      For slice s in piece:
                                                        - Seek exact offset in s.path.part
                                                        - Write slice bytes
                                                        - Flush to disk
                                                                          |
                                                      [Check File Completion]
                                                      All pieces for file f received?
                                                        - Hash entire .part file
                                                        - Verify sha256 == f.sha256
                                                        - os.replace(f.path.part, f.path)
```

---

## 5. Threading Model

### Receiver Threading Model
- **Main Thread:** Orchestrates setup, spawns workers, renders Section 15 console progress bar, and awaits completion. When the download finishes, unless `--exit-when-done` is passed, the main thread keeps the tracker and dashboard alive until `Ctrl+C`, printing `"Transfer complete. Dashboard still running; press Ctrl+C to quit"`.
- **Discovery Listener Thread (`DiscoveryListener`):** Background UDP socket thread receiving `HEARTBEAT` messages, parsing payloads, and updating the thread-safe `DeviceTable` (capped at `MAX_DEVICES=256` total and `MAX_DEVICE_IDS_PER_IP=8`).
- **Worker Thread Pool (`_sender_worker` per Seeder):**
  - Identifies seeders by authenticated `device_id`.
  - Drops duplicate connections to the same `device_id` immediately to avoid redundant worker threads.
  - Pulls pieces from a shared work queue.
  - Re-queues pieces on connection drop or socket timeout (`SOCKET_TIMEOUT=30.0s`).
  - Tracks strikes (`max 3`) and bans malicious peers keyed by `device_id`.
- **Embedded Tracker Server Thread (`TrackerServer`):** Runs the Flask/Werkzeug HTTP service and UDP `BEACON` broadcaster in a daemon thread. Binds cleanly and formats real, clickable URLs (`http://127.0.0.1:PORT and http://<LAN IP>:PORT`), never displaying `0.0.0.0`.
- **Monitor State Lock (`TrackerState`):** Uses an internal `threading.Lock` to ensure linearizable, thread-safe updates from workers and reports.

### Sender Threading Model
- **Main / Accept Thread (`SenderServer`):** Listens on the server TCP port, accepts incoming TLS connections, applies IP rate-limits, and delegates to peer handler threads.
- **Peer Handler Thread (`_handle_peer` per Client):**
  - Enforces handshake timeout (`HANDSHAKE_TIMEOUT=10.0s`) and idle timeout (`SOCKET_TIMEOUT=30.0s`).
  - Handles mutual authentication handshake and transmits sender `device_id` in `CHALLENGE`.
  - Serves piece requests using thread-safe `PieceReader` instances.
  - Enforces optional bandwidth throttling (`--throttle-kbps`) as an aggregate rate limit across all peer connections per sender in KiB/s via a shared pacing schedule (synchronized time-slot reservation), rather than per connection or token bucket.
- **Telemetry Reporter Thread (`ReportClient`):** Batches upload throughput every `REPORT_INTERVAL=0.5s` and posts HMAC-signed telemetry reports to `/api/report`.
- **Discovery Broadcaster Thread (`DiscoveryBroadcaster`):** Periodically sends UDP heartbeats (`HEARTBEAT_INTERVAL=2.0s`) across all detected network interfaces.

---

## 6. State & API Architecture

The embedded monitor server provides a clean JSON API consumed by the dashboard:

```
+---------------------------------------------------------------------------------+
|                                HTTP MONITOR API                                 |
+---------------------------------------------------------------------------------+
| Endpoint           | Method | Description                                       |
+--------------------+--------+---------------------------------------------------+
| /                  | GET    | Serves static index.html dashboard                |
| /static/<file>     | GET    | Serves style.css and app.js                       |
| /api/state         | GET    | State snapshot: swarm info, devices, piece map,   |
|                    |        | files, sender stats, and event log ring-buffer    |
| /api/report        | POST   | Signed telemetry from senders (HMAC-SHA256)       |
+---------------------------------------------------------------------------------+
```
