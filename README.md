# P2P Swarm

**A secure, torrent-style file sharing system for local networks.**
One receiver downloads different pieces of a file or folder from two or more senders at the same time, checks every piece, and rebuilds the files. All traffic is encrypted, only devices that know a secret join code can take part, and a live web dashboard shows what is happening.

**Course project:** Computer Networks (CN), Geethanjali College of Engineering and Technology
**Team:** Raj,Rahul,Rohit

> Educational project. Use it only on networks and devices you own or have permission to use.

---

## Table of contents

1. [What is it?](#what-is-it)
2. [Key features](#key-features)
3. [How it works](#how-it-works)
4. [Networking concepts used](#networking-concepts-used)
5. [Security](#security)
6. [Technology stack](#technology-stack)
7. [Repository structure](#repository-structure)
8. [Getting started](#getting-started)
9. [Command reference](#command-reference)
10. [Testing](#testing)
11. [Documentation](#documentation)
12. [Status and known limitations](#status-and-known-limitations)
13. [Future work](#future-work)
14. [Development notes](#development-notes)

---

## What is it?

Think of finishing a jigsaw puzzle with two friends: each friend hands you *different pieces* at the same time, so you finish faster than if one friend gave you the whole box slowly.

P2P Swarm works the same way for files:

- **Peer-to-peer (P2P):** devices talk directly to each other instead of asking one central server.
- **Torrent idea:** a file is cut into small numbered pieces, every piece has a fingerprint (a SHA-256 hash) so it can be checked, and pieces are downloaded from many sources at once.
- **Our addition:** encryption, a secret join code, automatic device discovery, and a live dashboard, all designed for a local network such as a phone hotspot.

## Key features

- **Multi-source download:** a receiver pulls pieces from two or more senders in parallel. Faster senders automatically do more of the work.
- **Integrity checking:** every piece is verified with SHA-256. A bad piece is thrown away and requested again, and a sender that sends three bad pieces is banned for the session.
- **Encrypted transfer:** TLS 1.2 or newer, with the receiver pinning the sender's certificate.
- **Join code authentication:** a shared secret that is never sent over the network. Each side proves it knows the secret (challenge and response), and repeated wrong tries are rate limited.
- **Automatic discovery:** senders announce themselves by UDP broadcast, so no one has to type IP addresses. A manual option exists for networks that block broadcasts.
- **Live dashboard:** a web page showing devices, who sends to whom, which sender supplied each piece, per-file progress, and an event log. It works offline and is read-only.
- **Multiple files and folders:** shared as one continuous stream of pieces, with the folder structure rebuilt on the receiver.
- **Fault tolerance:** if a sender stops or stalls, its unfinished pieces go back on the list and the other senders finish the job.
- **Tested:** 148 automated tests, including attack and failure cases.

## How it works

```
  Sender-A (TCP port 6881)        Sender-B (TCP port 6882)
  has the full file               has the same file
            \                            /
             \  pieces over TCP + TLS   /
              v                        v
        +--------------------------------------+
        |  Receiver                            |
        |   - downloader: shared to-do list,   |
        |     one worker thread per sender     |
        |   - dashboard (HTTP, port 8080)      |----> Browser (any device)
        +--------------------------------------+

  Senders also announce "I am here" by UDP broadcast (port 50000)
  so the receiver can find them automatically.
```

**A transfer, step by step**

1. **Prepare:** each sender glues its files into one long stream of bytes and cuts it into 64 KiB pieces. Every piece gets a SHA-256 fingerprint. The file list plus the fingerprints is the *metadata*, and a fingerprint of the metadata is the *swarm ID*.
2. **Listen:** each sender opens a TCP port and waits for requests.
3. **Discover:** senders broadcast a small "I am here" message every 2 seconds over UDP. The receiver keeps a table of devices and marks one offline after 8 silent seconds.
4. **Connect safely:** the receiver opens a TCP connection and starts TLS, accepting only the expected certificate.
5. **Authenticate:** sender and receiver prove to each other that they know the join code, without sending it.
6. **Get the metadata:** the receiver downloads the file list and fingerprints, recomputes the swarm ID itself, and checks that every sender has identical data. Unsafe file names are rejected.
7. **Take turns:** all piece numbers go on a shared list. One worker per sender takes the next number, requests that piece, and comes back for more. The receiver decides what to ask for; senders only answer.
8. **Verify:** each received piece is fingerprinted and compared with the metadata. A mismatch is discarded and retried.
9. **Write in place:** a good piece is written straight to its position in the file (piece number times piece size). Pieces may arrive in any order, so there is no separate joining step. Files are saved as `.part` and renamed once complete and verified.
10. **Recover:** a sender that disconnects or does not answer for 5 seconds is dropped, and its pieces are picked up by the others. If the same sender is reached twice (by hand and by discovery), the duplicate connection is closed.
11. **Watch:** senders send small signed status reports; the dashboard polls the receiver once per second and redraws.
12. **Finish:** a summary shows pieces per sender, bad pieces, and files completed. The dashboard keeps running until you press Ctrl+C.

## Networking concepts used

| Concept | Where it appears in the project |
| --- | --- |
| IP addresses and ports | Receiver connects to `IP:port` of each sender; ports 6881, 6882 (senders), 8080 (dashboard), 50000 (discovery) |
| Sockets | All connections use Python's `socket` module |
| TCP | Reliable, ordered transfer of pieces and metadata |
| UDP and broadcast | Automatic device discovery on the local network |
| Message framing | An 8-byte length prefix tells the receiver where each message ends |
| Packets vs pieces | Pieces (64 KiB) are our unit; packets (about 1,500 bytes) are created by TCP and IP |
| TLS and certificates | Encryption and sender identity (certificate pinning) |
| Hashing and HMAC | SHA-256 for integrity; HMAC for join-code proofs and signed status reports |
| Multithreading and queues | One worker per sender, a shared list of pieces, locks for safe file writes |
| HTTP and JSON | The dashboard and its `/api/state` data |
| Timeouts and rate limiting | Protection against silent connections and join-code guessing |
| Subnets, firewalls, NAT | Why the project targets a local network, and why Python must be allowed through firewalls |

## Security

| Threat | Defence |
| --- | --- |
| Someone spies on the traffic | TLS encryption |
| A fake sender | Certificate pinning plus the join code, checked in both directions |
| Guessing the join code | 5 wrong tries block an address for 60 seconds |
| Damaged or fake pieces | SHA-256 check, retry, ban after 3 bad pieces |
| Malicious file names such as `../../x` | Path validation; everything stays inside the download folder |
| Overload by huge or silent connections | Size limits, timeouts, connection and request limits |
| Fake devices or status reports | Devices stay "discovered" until verified; reports are signed, timed and numbered |
| Dashboard attacks | Read-only, device names shown as plain text, strict Content-Security-Policy |

The full threat model and known weaknesses are in [docs/SECURITY.md](docs/SECURITY.md).

## Technology stack

| Technology | Used for |
| --- | --- |
| Python 3.10+ | Main language (tested on 3.13) |
| `socket`, `ssl`, `threading`, `queue`, `hashlib`, `hmac`, `json`, `struct` | Networking, TLS, workers, hashing, message formats |
| Flask | Dashboard web server and API |
| psutil | Finding network interfaces for broadcast |
| cryptography | Creating the certificate and key |
| HTML, CSS, JavaScript | Offline dashboard (no external files) |
| pytest | Automated tests |
| Git and GitHub | Version control |

## Repository structure

```
p2p_swarm/
  README.md
  requirements.txt
  config.py            # constants: ports, timeouts, limits
  sender.py            # serves a file or folder
  receiver.py          # downloads and hosts the dashboard
  common/              # protocol, metadata, pieces, TLS, auth, discovery, reporting
  tracker/             # dashboard: state, Flask server, static page
  tools/               # certificate generator, test data, test-only evil sender
  tests/               # 148 automated tests
  docs/                # architecture, security, deviations, demo script, report notes
```

## Getting started

### Requirements

- Python 3.10 or newer (developed and tested on 3.13)
- macOS, Linux or Windows (tested so far on macOS; see [limitations](#status-and-known-limitations))

### 1. Install

```bash
git clone https://github.com/YOUR-USERNAME/p2p_swarm.git
cd p2p_swarm
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Run the tests

```bash
pytest -q
```

### 3. Create sample files and a certificate

```bash
python tools/make_test_data.py --out sample_data
python tools/gen_certs.py --out certs --ip 127.0.0.1
```

Senders need both `certs/cert.pem` and `certs/key.pem`. Receivers need only `certs/cert.pem`. **Never commit the `certs/` folder** (it is already in `.gitignore`), and never share `key.pem` through GitHub.

### 4. Run a demo on one computer (three terminals)

In **each** terminal, activate the environment and set the same join code. Choose your own long secret; do not reuse an example.

```bash
source .venv/bin/activate
export P2P_JOIN_CODE="YOUR-SECRET-JOIN-CODE"
# Windows cmd: set P2P_JOIN_CODE=YOUR-SECRET-JOIN-CODE
# Windows PowerShell: $env:P2P_JOIN_CODE="YOUR-SECRET-JOIN-CODE"
```

**Terminal 1, Sender-A**

```bash
python sender.py --path sample_data --port 6881 --name Sender-A --cert certs/cert.pem --key certs/key.pem --throttle-kbps 40
```

**Terminal 2, Sender-B**

```bash
python sender.py --path sample_data --port 6882 --name Sender-B --cert certs/cert.pem --key certs/key.pem --throttle-kbps 40
```

**Terminal 3, Receiver**

```bash
python receiver.py --out downloaded_data --cert certs/cert.pem --senders 127.0.0.1:6881 127.0.0.1:6882 --overwrite
```

`--throttle-kbps 40` limits each sender to 40 KiB per second so the transfer is slow enough to watch. Open the dashboard at **http://127.0.0.1:8080** while it runs.

### 5. Check the result

```bash
diff -r sample_data downloaded_data/sample_data
```

No output means every file is identical to the original.

### 6. Automatic discovery

Leave out `--senders` and let the receiver find the senders by itself:

```bash
python receiver.py --out downloaded_data --cert certs/cert.pem --min-senders 2 --overwrite
```

### 7. Several devices on one network (for example a phone hotspot)

1. Connect all devices to the same network and copy the project to each one.
2. Copy `certs/cert.pem` and `certs/key.pem` to the senders, and only `certs/cert.pem` to the receiver (USB or AirDrop, not GitHub).
3. Use the same `P2P_JOIN_CODE` on every device, and make sure the senders share identical files.
4. Start the senders, then the receiver without `--senders`, and open the dashboard address the receiver prints.
5. If devices do not appear, a firewall or a hotspot that blocks broadcasts may be the cause. Use `--senders IP:PORT` as a fallback. See [docs/HOTSPOT_TEST_CHECKLIST.md](docs/HOTSPOT_TEST_CHECKLIST.md).

## Command reference

Run `python sender.py --help` and `python receiver.py --help` for every option. The main ones:

| Script | Option | Meaning |
| --- | --- | --- |
| sender | `--path` | File or folder to share |
| sender | `--port` | TCP port to listen on (default 6881) |
| sender | `--name` | Friendly name shown on the dashboard |
| sender | `--cert`, `--key` | Certificate and private key |
| sender | `--throttle-kbps` | Upload limit in KiB per second, per sender (for demos) |
| sender | `--no-discovery` | Do not broadcast presence |
| sender | `--tracker HOST:PORT` | Report to a dashboard without waiting for its beacon |
| receiver | `--out` | Download folder |
| receiver | `--cert` | Certificate to trust |
| receiver | `--senders` | Sender addresses (`IP:PORT`), as a fallback to discovery |
| receiver | `--min-senders`, `--discover-timeout` | How many senders to wait for, and for how long |
| receiver | `--swarm` | Which swarm to join if several are found |
| receiver | `--web-port`, `--web-host`, `--web-pin` | Dashboard port, address, and optional PIN |
| receiver | `--exit-when-done` | Exit after the download instead of keeping the dashboard up |
| receiver | `--overwrite` | Replace existing files in the download folder |

The join code is read from the `P2P_JOIN_CODE` environment variable, or asked for interactively. Avoid putting it on the command line.

## Testing

```bash
pytest -q
```

The 148 tests cover message framing and size limits, metadata and path safety (including attack inputs), piece reading and writing with edge cases, TLS and join-code authentication, discovery rules and spoofed packets, signed reports and the dashboard API, and full transfers with failing senders and corrupted pieces.

## Documentation

- [Architecture and protocol](docs/ARCHITECTURE.md)
- [Security threat model and limitations](docs/SECURITY.md)
- [Spec deviations and security audit matrix](docs/DEVIATIONS.md)
- [Hotspot test checklist](docs/HOTSPOT_TEST_CHECKLIST.md)
- [Report notes and viva questions](docs/REPORT_NOTES.md)
- [Five-minute demo script](docs/DEMO_SCRIPT.md)

## Status and known limitations

- **Tested so far on a single computer** (macOS, Python 3.13) using several processes. Tests across real devices on a hotspot, and on Windows and Linux, are still to be done.
- **Local network only.** It does not cross the internet or home-router address translation (NAT).
- **Senders share one certificate and key.** Anyone who copies the key could pose as a sender, although they would also need the join code.
- **Self-asserted device IDs.** A device that knows the join code could claim another sender's ID.
- **The dashboard uses plain HTTP.** It is read-only and holds no secrets, but it is not encrypted.
- **Flooding is limited, not eliminated.** Timeouts and limits make it harder to keep a sender busy, but a determined attacker on the same network could still try.
- **One folder or file at a time.** An interrupted download starts again from the beginning.
- **Windows reserved file names** (such as `CON` or `AUX`) are rejected on every system.

## Future work

- A separate certificate for each sender
- Signed pieces, so one sender can prove another sent bad data
- Resume interrupted downloads, and download only chosen files
- Let a receiver become a sender after it finishes
- Peer discovery without broadcasts, and support across routers

## Development notes

The system was designed from a written specification and built in eight tested phases (protocol and pieces, basic transfer, multiple senders, TLS and join code, discovery, status reports, dashboard, hardening and documents). An AI coding assistant (Antigravity) helped write the code; the team reviewed and tested every phase.

## License

No license has been chosen yet. Until one is added, all rights are reserved by the authors.
