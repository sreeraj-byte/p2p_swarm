# P2P Swarm

A high-reliability, decentralized peer-to-peer file sharing swarm designed for local networks and mobile hotspots (e.g. college laboratory and viva demonstrations).

---

## 1. Overview

**P2P Swarm** enables a downloader (receiver) to concurrently pull fixed-size byte chunks from multiple seeders (senders) holding identical copies of a file or directory. The data stream is deterministically split into 64 KiB pieces, each verified against SHA-256 hashes.

### Key Architectural Principles
- **Pull Model:** The receiver decides which pieces to request from which senders based on real-time availability; senders only fulfill valid requests.
- **Direct P2P Writing:** Pieces arriving from various senders in arbitrary order are written directly at their exact file offsets into pre-allocated `.part` files with zero post-download assembly overhead.
- **Transport Security:** Peer communication is encrypted with **TLS 1.2+** where the receiver **pins trust directly to the sender's certificate** (`verify_mode=CERT_REQUIRED`, `check_hostname=False`).
- **Mutual Join-Code Authentication:** An out-of-band shared join code is authenticated mutually at the application layer via Scrypt key derivation and constant-time HMAC-SHA256 challenge-response handshakes. The join code itself is never transmitted across the wire.
- **Device ID Sender Identity & Deduplication:** Senders are identified by their authenticated `device_id` (sent in the `CHALLENGE` handshake) rather than transient socket endpoints. If a sender is reached via both manual `--senders` and automatic UDP discovery, duplicate connections are automatically closed and all stats/bans are keyed by `device_id`.
- **Per-Sender Aggregate Rate Limiting:** The `--throttle-kbps N` flag enforces an aggregate upload ceiling in KiB/s (1024 B/s) across all concurrent peer connections on each sender using a **shared pacing schedule** (synchronized time-slot reservation scheduler), rather than a per-connection limiter or token bucket.
- **Automatic UDP Discovery:** Senders and receivers discover each other via UDP broadcast heartbeats on port 50000, with robust CLI fallbacks (`--senders`) for isolated subnets.
- **Real-Time Monitor & Clean URL Banner:** The receiver hosts a local, offline-first web dashboard. When bound to `0.0.0.0`, the receiver dynamically resolves loopback and active LAN interfaces, printing clickable URLs (`http://127.0.0.1:PORT and http://<LAN IP>:PORT`) and never printing `0.0.0.0`.
- **Post-Transfer Dashboard Persistence:** The receiver keeps the tracker and dashboard alive after transfer completion until `Ctrl+C` (printing `"Transfer complete. Dashboard still running; press Ctrl+C to quit"`), unless `--exit-when-done` is specified.

---

## 2. Requirements

- **Python 3.10+** (fully verified on Python 3.13)
- Supported Platforms: Linux (Ubuntu/Debian), macOS (Apple Silicon / Intel), Windows 10/11
- Virtual environment (`venv`) recommended
- Dependencies: `cryptography`, `flask`, `psutil`, `pytest`, `werkzeug` (see `requirements.txt`)

---

## 3. Installation & Setup

### Clone Repository & Create Virtual Environment

**Linux / macOS:**
```bash
git clone <repo-url> p2p_swarm
cd p2p_swarm
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

**Windows (Command Prompt / PowerShell):**
```cmd
git clone <repo-url> p2p_swarm
cd p2p_swarm
python -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Run Test Suite
```bash
pytest -v
# 148 passed in ~75s
```

---

## 4. Generating TLS Certificates

Senders require a TLS certificate (`cert.pem`) and private key (`key.pem`). The receiver **only requires the public certificate (`cert.pem`)** to pin trust.

```bash
# Generate self-signed certificate with IP SANs and CA:TRUE
python tools/gen_certs.py --out certs --ip 127.0.0.1 192.168.43.10 192.168.43.11
```
*Deployment rule:*
- Copy **`certs/cert.pem` AND `certs/key.pem`** to every sender machine.
- Copy **ONLY `certs/cert.pem`** to the receiver machine.

---

## 5. Running the Swarm

### A. Localhost Demo (Single Machine, 3 Terminals)

#### Step 1: Prepare Sample Data
```bash
python tools/make_test_data.py --out sample_data
```

#### Step 2: Set Shared Join Code
Use the `P2P_JOIN_CODE` environment variable across all terminals:
```bash
export P2P_JOIN_CODE="YOUR-SECRET-JOIN-CODE"
```
*(On Windows: `set P2P_JOIN_CODE=YOUR-SECRET-JOIN-CODE`)*

#### Step 3: Start Senders
**Terminal 1 (Sender A - throttled to 250 KB/s per-sender aggregate):**
```bash
python sender.py --path sample_data --port 6881 --name Sender-A --cert certs/cert.pem --key certs/key.pem --throttle-kbps 250
```

**Terminal 2 (Sender B - throttled to 250 KB/s per-sender aggregate):**
```bash
python sender.py --path sample_data --port 6882 --name Sender-B --cert certs/cert.pem --key certs/key.pem --throttle-kbps 250
```

#### Step 4: Start Receiver
**Terminal 3 (Receiver C):**
```bash
python receiver.py --out downloaded_data --cert certs/cert.pem --senders 127.0.0.1:6881 127.0.0.1:6882
```
Open `http://localhost:8080` in your browser to view the real-time SVG topology and chunk progress.

---

### B. Mobile Hotspot Demo (Multiple Physical Laptops)

1. Connect all laptops (e.g., Sender A, Sender B, Receiver C) to the same mobile hotspot (e.g. Android / iPhone Wi-Fi tethering).
2. Note each laptop's Wi-Fi IP address via `ip a` (Linux), `ifconfig` (macOS), or `ipconfig` (Windows).
3. Ensure certificates are generated with all LAN IPs:
   ```bash
   python tools/gen_certs.py --out certs --ip 192.168.43.10 192.168.43.11 192.168.43.12
   ```
4. Copy `certs/cert.pem` and `certs/key.pem` to Sender A and Sender B; copy only `certs/cert.pem` to Receiver C.
5. Launch senders with UDP auto-discovery enabled (default):
   - **Sender A:** `python sender.py --path sample_data --cert certs/cert.pem --key certs/key.pem`
   - **Sender B:** `python sender.py --path sample_data --cert certs/cert.pem --key certs/key.pem`
6. Launch receiver:
   - **Receiver C:** `python receiver.py --out downloaded_data --cert certs/cert.pem --min-senders 2`
   Receiver C will discover Sender A and B automatically over UDP broadcast, verify their certificates, perform mutual authentication, and download in parallel.

---

## 6. CLI Reference

### `sender.py`
```
usage: sender.py [-h] --path PATH [--port PORT] [--name NAME] --cert CERT --key KEY
                 [--code CODE] [--piece-size PIECE_SIZE] [--throttle-kbps THROTTLE_KBPS]
                 [--no-discovery] [--discovery-port DISCOVERY_PORT] [--tracker TRACKER]
```
- `--path PATH`: Path to file or folder to share.
- `--port PORT`: TCP port to listen on (default: 6881, 0 for auto).
- `--name NAME`: Human-readable device display name.
- `--cert CERT`: Path to TLS certificate (`cert.pem`).
- `--key KEY`: Path to TLS private key (`key.pem`).
- `--code CODE`: Join code (optional, defaults to `P2P_JOIN_CODE` env var).
- `--throttle-kbps N`: Throttles upload speed to `N` KiB/s across all peer connections via a shared pacing schedule (applied per sender as an aggregate outbound bandwidth limit; useful for demos).
- `--no-discovery`: Disables UDP discovery broadcasting.
- `--tracker HOST:PORT`: Tracker host and port for reporting telemetry.

### `receiver.py`
```
usage: receiver.py [-h] [--senders SENDERS [SENDERS ...]] --out OUT --cert CERT
                   [--code CODE] [--overwrite] [--name NAME] [--min-senders MIN_SENDERS]
                   [--discover-timeout DISCOVER_TIMEOUT] [--swarm SWARM]
                   [--web-port WEB_PORT] [--web-host WEB_HOST] [--web-pin WEB_PIN]
                   [--no-discovery] [--no-tracker] [--exit-when-done]
```
- `--senders HOST:PORT ...`: Manual list of initial senders (fallback).
- `--out OUT`: Directory where downloaded files will be saved.
- `--cert CERT`: Path to pinned TLS certificate (`cert.pem`).
- `--min-senders N`: Wait until `N` senders appear before beginning download.
- `--discover-timeout SEC`: Discovery timeout in seconds (default: 20.0).
- `--web-port PORT`: Dashboard HTTP port (default: 8080).
- `--web-pin PIN`: Optional PIN required to access the monitor dashboard.
- `--exit-when-done`: Exit immediately after transfer finishes instead of keeping the dashboard alive until Ctrl+C.
- `--overwrite`: Overwrite destination files if they exist.

---

## 7. Troubleshooting

### 1. Firewall & Port In Use
- **Error:** `Address already in use: 6881` or `8080`.
  - Fix: Specify a different port (`--port 6885` or `--web-port 8085`), or terminate the process holding the port using `lsof -i :<port>` or `netstat -ano`.
- **Firewall Rules:**
  - Linux: `sudo ufw allow 6881/tcp && sudo ufw allow 50000/udp`
  - macOS: Allow incoming connections when prompted by macOS Application Firewall.
  - Windows: Allow Python in Windows Defender Firewall for Private networks.

### 2. Wi-Fi Hotspot Client Isolation
- **Symptom:** Receiver does not discover senders automatically; `ping <sender-ip>` fails.
  - Cause: Many public or phone hotspots enable "Client Isolation" / "AP Isolation", blocking peer-to-peer packets between Wi-Fi clients.
  - Solution: Disable AP Isolation in your phone's hotspot configuration, or use manual `--senders <IP>:<PORT>` on the receiver CLI.

### 3. UDP Broadcast Blocked
- **Symptom:** Directed broadcast packets (`255.255.255.255`) are dropped by network switches.
  - Solution: Use the explicit `--senders <IP>:<PORT>` fallback flag on the receiver. The system will connect over TCP/TLS and bypass UDP discovery entirely.

### 4. Clock Skew on Signed Telemetry
- **Symptom:** `403 Invalid report timestamp (clock skew exceeds 30.0s)`.
  - Solution: Ensure system clocks are synchronized on all machines (NTP / date sync).

---

## 8. Documentation Index

- [Architecture & Protocol Design](docs/ARCHITECTURE.md)
- [Security Threat Model & Defenses](docs/SECURITY.md)
- [Spec Deviations & Security Audit Matrix](docs/DEVIATIONS.md)
- [Hotspot Environment Test Checklist](docs/HOTSPOT_TEST_CHECKLIST.md)
- [Project Report Notes & 15 Viva Questions](docs/REPORT_NOTES.md)
- [5-Minute Live Demo Script](docs/DEMO_SCRIPT.md)
