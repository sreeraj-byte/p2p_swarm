# P2P Swarm: Security Architecture & Threat Model

This document outlines the threat model, defensive controls, and architectural limitations of the **P2P Swarm** implementation per Section 14 and Section 20.

---

## 1. Threat Model & Defensive Controls

| Threat Vector | Attack Scenario | Defensive Control in P2P Swarm |
|---|---|---|
| **Eavesdropping / Sniffing** | Attacker on the local Wi-Fi captures packets to inspect transmitted files or credentials. | **TLS 1.2+ Encryption:** All peer data and metadata exchange occurs over TLS with strong ciphers. Plain TCP connections are actively refused. |
| **Man-in-the-Middle (MITM)** | Attacker intercepts connection and injects rogue certificate or proxy. | **Certificate Pinning:** The receiver pins trust exclusively to `cert.pem` (`verify_mode=CERT_REQUIRED`, `check_hostname=False`). Certificates not matching the pinned anchor are immediately dropped. |
| **Rogue / Unauthorized Peer** | A device on the LAN connects with a valid TLS cert but lacks authorization. | **Mutual Join-Code Challenge-Response:** Peers must prove possession of the out-of-band join code via Scrypt-derived keys and constant-time HMAC-SHA256 proofs (`HELLO` / `AUTH`). The join code is never transmitted. |
| **Corrupted / Poisoned Pieces** | Malicious sender sends garbage or altered bytes instead of legitimate file data. | **Piece SHA-256 Verification:** Receiver calculates SHA-256 over every downloaded piece before writing to disk. Mismatched pieces are discarded, retried via another peer, and the bad sender receives strikes leading to a permanent session ban. |
| **Spoofed Discovery Broadcasts** | Attacker injects fake UDP heartbeats claiming fake IP addresses or massive tables. | **Source-IP Enforcement & Table Caps:** Receiver takes the IP directly from the UDP packet source, caps device tables (`MAX_DEVICES=256`), limits distinct device IDs per IP (`MAX_DEVICES_PER_IP=8`), and marks devices as unverified until mutual TLS authentication succeeds. Real seeders cannot be evicted by spoofers. |
| **Duplicate Connections & Worker Flooding** | Multiple connection attempts initiated to the same sender via dual manual `--senders` and UDP discovery. | **Device ID Deduplication:** Senders are authenticated by unique `device_id`. If a connection arrives for an already connected `device_id`, the duplicate connection is closed immediately; workers, statistics, and bans are keyed strictly by `device_id`. |
| **Forged / Replayed Telemetry** | Attacker spams forged telemetry reports to corrupt the dashboard state. | **HMAC Signatures & Replay Protection:** POST `/api/report` requires an HMAC-SHA256 signature generated with `report_key`, enforces a 30s clock skew window, and requires strictly increasing per-device sequence numbers. |
| **Path Traversal & Symlink Attacks** | Malicious metadata contains `../../etc/passwd`, absolute paths, symlinks, or colons. | **Strict Path Canonicalization:** Paths must be relative POSIX paths; backslashes, colons, `..`, empty components, control characters, and Windows device names are strictly rejected. Paths are verified with `os.path.commonpath` to guarantee containment within destination directories, and symlinks are never followed when writing. |
| **Cross-Site Scripting (XSS)** | Attacker registers device named `<script>alert(1)</script>` to execute malicious code in monitor dashboard. | **100% Safe DOM Rendering & Strict CSP:** Frontend JavaScript strictly forbids `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, or dynamic `style`/`on*` attributes. All text is rendered using `textContent`. Enforces `Content-Security-Policy: default-src 'self'`. |
| **Resource Exhaustion / DoS** | Attacker floods connections, sends giant payloads, or holds sockets open (Slowloris). | **Pre-allocation Size Caps & Idle Timeouts:** Size headers are capped *before* allocating memory (`MAX_PAYLOAD_SIZE=2 MiB`). Sockets enforce a 10s handshake timeout (`HANDSHAKE_TIMEOUT=10.0s`), 30s idle timeout (`SOCKET_TIMEOUT=30.0s`), request rate limiting (`MAX_REQUESTS_PER_SEC=500`), and aggregate outbound bandwidth throttling (`--throttle-kbps` in KiB/s via a shared pacing schedule). |

---

## 2. Known Limitations & Architectural Trade-offs

The following design decisions represent conscious trade-offs appropriate for the local-network, educational scope of this project:

1. **Shared Certificate & Private Key across Senders:**
   - *Limitation:* All authorized senders share the same self-signed TLS certificate and private key.
   - *Risk:* A compromised sender has access to the private key used by other senders.
   - *Mitigation:* In local academic labs or classroom presentations, this simplifies credential distribution (1 cert + 1 key) compared to maintaining an internal PKI or CA.

2. **HTTP Monitor Dashboard:**
   - *Limitation:* The local web dashboard runs over plaintext HTTP (port 8080) rather than HTTPS.
   - *Risk:* Traffic between the local browser and the receiver's loopback interface could be inspected if bound to `0.0.0.0`.
   - *Mitigation:* The dashboard exposes purely transfer telemetry (speed, piece map, device status), never file contents, join codes, or private keys. The receiver never advertises `0.0.0.0`, printing only working URLs (`http://127.0.0.1:PORT and http://<LAN IP>:PORT`). An optional constant-time PIN (`--web-pin`) can restrict access. The dashboard persists post-transfer until Ctrl+C unless `--exit-when-done` is passed.

3. **LAN-Only Operation (No NAT Traversal):**
   - *Limitation:* Discovery and transport assume direct IP routability (flat LAN or Wi-Fi hotspot).
   - *Scope:* Does not implement STUN, TURN, or ICE hole-punching for wide-area Internet routing.

4. **No Per-Piece Digital Signatures:**
   - *Limitation:* Pieces are verified via SHA-256 hashes against trusted metadata, not asymmetric signatures signed by individual seeders.
   - *Mitigation:* Bad pieces are detected immediately, preventing corrupted data from entering the file, and bad peers are banned locally. However, signed non-repudiation across the entire swarm is deferred to stretch goals.

5. **Shared Report HMAC Key:**
   - *Limitation:* The report HMAC key (`report_key`) is derived from `auth_key`, which in turn is derived from the shared join code.
   - *Scope:* Any authenticated member of the swarm possesses the capability to construct valid report HMACs. Sequence number enforcement prevents report replay attacks.

6. **Connection and Heartbeat Flooding Limits:**
   - *Limitation:* While the device table caps total entries (`MAX_DEVICES=256`) and per-IP devices (`MAX_DEVICE_IDS_PER_IP=8`), a determined attacker flooding gigabits of UDP datagrams could cause CPU overhead on the listening thread.

7. **Rejection of Windows Reserved Names:**
   - *Limitation:* Filenames matching Windows device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`) are completely rejected by metadata validation across all platforms.
   - *Rationale:* Ensures cross-platform portability so that a swarm shared from macOS or Linux does not crash a Windows receiver.

8. **Unicode Filename Normalization across Operating Systems:**
   - *Limitation:* Filesystems handle Unicode normalization differently (macOS APFS/HFS+ defaults to NFD decomposed strings, while Linux and Windows use NFC composed strings).
   - *Mitigation:* P2P Swarm enforces canonical NFC normalization across all platforms during metadata generation, file scanning, and path comparison, preventing collision attacks or duplicate `.part` files.

9. **Self-Asserted Device IDs by Authenticated Peers:**
   - *Limitation:* The `device_id` is generated locally and self-asserted by authenticated senders during the handshake (`CHALLENGE` / `HELLO`), rather than being cryptographically bound to an asymmetric private key or individual X.509 certificate.
   - *Risk:* An authenticated sender holding the shared join code could potentially impersonate another legitimate sender's `device_id`.
   - *Impact:* An insider rogue peer could spoof a legitimate sender's `device_id` to cause the receiver to drop the legitimate peer's connection as a "duplicate", or could deliberately deliver corrupted pieces under that `device_id` to trigger session strikes and bans against the victim.
   - *Mitigation:* In academic lab and viva demonstration settings, peer membership is controlled by the secret join code and physical accountability. For hostile, open-internet swarms, each peer would require an individual asymmetric key pair with signed challenge proofs (Stretch Goal 5/6).
