# P2P Swarm: Project Report Notes & Viva Examination Guide

This document contains background material, related work analysis, limitations, future work, and **15 likely viva questions with code-referenced answers** for academic assessment.

---

## 1. Project Background & Related Work

Local-area file sharing has traditionally relied either on centralized client-server protocols (such as HTTP/FTP or local SMB shares) or single-peer ad-hoc transfer tools.

### How P2P Swarm Differs from Related Systems

1. **BitTorrent (BEP 3 & BEP 52):**
   - *BitTorrent:* Designed for global Internet distribution using central trackers or Kademlia Distributed Hash Tables (DHT). Clients operate as both seeders and leechers, exchanging piece bitfields and employing tit-for-tat choke algorithms.
   - *P2P Swarm:* Optimized specifically for zero-configuration local area networks and mobile hotspots. It uses a **pure pull-model downloader** that orchestrates parallel piece retrieval across dedicated seeders with zero tit-for-tat complexity. Transport is secured via **one-way pinned TLS 1.2+** with an application-layer Scrypt/HMAC join code, providing confidentiality and authentication without public Internet connectivity.

2. **BitTorrent Local Service Discovery (BEP 14):**
   - *BEP 14:* Uses multicast UDP on `239.192.152.143:6771` to discover local peers, sending plaintext HTTP-like announcement headers.
   - *P2P Swarm:* Employs directed IPv4 subnet broadcasts via `psutil` interface enumeration plus fallback to `255.255.255.255`. It mitigates multicast drops commonly encountered on mobile phone tethering and enforces strict 1 KiB packet bounds with untrusted input sanitization.

3. **LocalSend & Apple AirDrop:**
   - *LocalSend / AirDrop:* Designed for point-to-point (1-to-1) file pushing between devices. If multiple devices possess the same large dataset, a downloader cannot aggregate bandwidth across them.
   - *P2P Swarm:* Provides **multi-source swarm aggregation (N-to-1)**. A downloader concurrently fetches non-overlapping 64 KiB chunks from multiple seeders simultaneously, multiplying effective transfer speeds and providing instantaneous failover if a seeder drops.

4. **Peer Banning in Existing P2P Clients:**
   - *Traditional Clients:* Often ban peers only after an entire multi-megabyte piece or torrent fails, allowing malicious peers to waste substantial bandwidth.
   - *P2P Swarm:* Employs fine-grained 64 KiB piece verification, isolated strike counters (3 strikes = ban), and immediate re-queuing of missing chunks into the shared work queue.

---

## 2. Limitations & Future Work

### Current Limitations
- **One-Way Seeding:** The receiver downloads from seeders but does not immediately transition into a seeder for other peers during the transfer.
- **Shared Sender Credentials:** All seeders share the same TLS certificate and private key.
- **LAN Scope:** Assumes direct IP routability; does not perform NAT traversal (STUN/TURN/ICE).
- **No Per-Piece Digital Signatures:** Pieces are verified against trusted metadata hashes rather than individual sender digital signatures.

### Future Work & Extensions
1. **Tit-for-Tat Mesh Swarming:** Allow receivers to immediately seed completed pieces to other receivers in a mesh topology.
2. **Signed Pieces with Swarm-Wide Gossip Banning:** Senders sign delivered chunks; any receiver detecting a hash mismatch can broadcast the signed piece as cryptographic proof of malice, enabling the entire swarm to blacklist the rogue node.
3. **Pipelined Piece Requests:** Allow multiple outstanding piece requests per TCP connection to saturate high-latency links.
4. **Resumable Transfers:** Verify existing `.part` files on startup and download only missing pieces.
5. **Server-Sent Events (SSE) / WebSockets:** Push real-time telemetry to the dashboard instead of 1-second polling.

---

## 3. 15 Viva Examination Questions & Answers

### Q1: What is the fundamental difference between a network packet and a swarm piece?
**Answer:** A network packet (e.g., an IP/TCP packet) is a transport-layer unit of transmission (typically ~1500 bytes MTU) handled by the operating system kernel and network hardware. A **swarm piece** is an application-layer logical block (in our system, 64 KiB) defined in the swarm metadata, independently addressable by index and independently verified via a cryptographic SHA-256 hash. Multiple TCP packets combine to deliver a single swarm piece.

### Q2: Why does P2P Swarm use TCP instead of UDP for file piece transport?
**Answer:** TCP provides reliable, in-order byte stream delivery, congestion control, flow control, and transparent TLS framing. Since piece data integrity and reliable transmission are critical, building on TCP allows the application to focus on swarm orchestration and cryptographic piece hashing without reimplementing retransmissions or sliding window algorithms at the transport layer. (UDP is used strictly for discovery heartbeats where broadcast and low-overhead announcements are ideal).

### Q3: Why are cryptographic hashes (SHA-256) not considered encryption?
**Answer:** Encryption is a two-way function designed for **confidentiality**; given ciphertext and a secret key, the original plaintext can be recovered. A cryptographic hash is a one-way mathematical function designed for **integrity verification**; it compresses arbitrary data into a fixed-length digest (256 bits) from which the original input cannot be computed, and guarantees that any change to the input produces an entirely different digest with high probability (pre-image and collision resistance).

### Q4: Why does the receiver pull pieces rather than having senders push them?
**Answer:** A pull-based architecture gives the receiver complete control over bandwidth scheduling, work allocation, and load balancing across seeders. The receiver maintains a global shared queue of missing pieces, requests chunks according to seeder speed and availability, and immediately reassigns in-flight pieces if a seeder lags or disconnects. A push model would require complex distributed coordination to prevent multiple senders from sending duplicate pieces simultaneously.

### Q5: How does file reassembly work when pieces arrive out of order from different senders?
**Answer:** P2P Swarm treats multi-file directory shares as a single contiguous byte stream. At initialization, the receiver pre-allocates `.part` files on disk matching the target file sizes. When a 64 KiB piece arrives, `map_piece_to_slices()` determines the exact file index and byte offset for that chunk. The worker seeks directly to that offset and writes the slice. When all pieces for a file have arrived, the completed `.part` file is verified against its whole-file SHA-256 hash and atomically renamed via `os.replace()`. There is zero post-download reassembly overhead.

### Q6: What specific attack does TLS prevent in this architecture, and what does the join code protect?
**Answer:** 
- **TLS (with pinned certificate)** defends against **passive eavesdropping and network-level Man-in-the-Middle (MITM) attacks**. It encrypts the channel and ensures the receiver connects only to an entity presenting the trusted self-signed certificate.
- The **Join Code** acts as a **second-factor mutual authentication mechanism**. It defends against unauthorized or rogue peers that might possess the public certificate (or an identical certificate on the LAN) but do not know the classroom/lab secret passkey.

### Q7: Why is Scrypt used for key derivation instead of plain SHA-256 or MD5?
**Answer:** Join codes are human-memorable strings (e.g. passwords/passphrases). Fast hash functions like SHA-256 can be brute-forced at billions of hashes per second using GPUs or ASICs. **Scrypt** is a memory-hard password-based key derivation function (PBKDF) parameterized with CPU cost, memory cost, and block size, making dictionary and brute-force attacks computationally and economically infeasible.

### Q8: How does the join-code challenge-response prove knowledge of the secret without transmitting it?
**Answer:** The client and server exchange random nonces (`client_nonce`, `server_nonce`). Both derive a shared 256-bit `auth_key` from the join code using Scrypt. The server computes `server_proof = HMAC-SHA256(auth_key, "SERVER" || transcript)` and the client verifies it. The client then computes `client_proof = HMAC-SHA256(auth_key, "CLIENT" || transcript)` and the server verifies it. Because HMAC is a one-way MAC function, each party proves possession of `auth_key` without exposing the key or join code on the network.

### Q9: Why is `hmac.compare_digest` used for verification instead of standard `==` string comparison?
**Answer:** Standard string/byte comparison (`==`) terminates at the first differing character, leaking the position of the mismatch through execution time (**timing attack**). An attacker measuring microsecond-level response times can incrementally deduce valid proof tokens. `hmac.compare_digest` runs in **constant time**, comparing all bytes regardless of where differences occur, completely eliminating timing side-channels.

### Q10: How does the receiver defend against a malicious sender injecting corrupted pieces?
**Answer:** Every piece downloaded from a peer is checked against the authoritative SHA-256 hash list in the canonical metadata before being written to disk. If the hash does not match:
1. The piece data is discarded immediately.
2. The piece index is re-inserted into the shared work queue for retrieval from another sender.
3. The offending sender receives a strike (incrementing `failures`).
4. Upon reaching 3 strikes, the sender is permanently banned for the session and its connection is severed.

### Q11: How does the system defend against UDP discovery spoofing and device table exhaustion?
**Answer:** 
1. The receiver ignores any IP claimed inside the payload and strictly takes the candidate IP from `sock.recvfrom()` packet source metadata.
2. The device table is hard-capped at 256 entries (`MAX_DEVICES`).
3. Each source IP is restricted to a maximum of 8 distinct device IDs (`MAX_DEVICES_PER_IP`).
4. An established real seeder cannot be evicted by incoming spoofed heartbeats.
5. Discovered devices remain untrusted (`discovered`) and are only upgraded to `verified` after completing the TLS handshake and mutual join-code challenge.

### Q12: Why does the web dashboard strictly avoid `innerHTML`?
**Answer:** Setting `innerHTML` with untrusted data received from the network (such as device names or file paths in `/api/state`) creates a critical **Cross-Site Scripting (XSS)** vulnerability. If an attacker injects `<script>alert(1)</script>` into a device name, the browser would execute it. P2P Swarm strictly renders all network text using `document.createElement()` and `element.textContent`, ensuring that HTML tags are treated purely as inert plaintext strings.

### Q13: What is the purpose of the Content-Security-Policy (CSP) header in the embedded monitor?
**Answer:** The server returns `Content-Security-Policy: default-src 'self'`. This header instructs the browser to refuse execution of any inline `<script>` tags, any inline `<style>` attributes, any `eval()` calls, and any external resources loaded from third-party domains or CDNs. Even if an attacker found a way to inject script tags into the DOM, the browser's CSP engine would block execution.

### Q14: How does the receiver ensure path traversal safety across operating systems?
**Answer:** In `common/metadata.py`, all relative file paths are validated against strict security rules:
- Paths must use POSIX forward slashes.
- Backslashes, colons (drive letters), `..`, empty segments, and control characters are rejected.
- Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`) are rejected.
- Paths are normalized to Unicode NFC and checked for case-insensitive collisions.
- Before writing, `os.path.commonpath([out_dir, resolved_target])` verifies that the target resides strictly inside the destination folder. Symlinks are never followed when writing.

### Q15: Why does P2P Swarm work offline without Internet access or a central coordinator?
**Answer:** All core mechanisms are completely decentralized and localized:
1. **Certificates:** Self-signed with custom IP Subject Alternative Names; verified via direct certificate pinning rather than an external Certificate Authority (CA).
2. **Discovery:** Operates via local IPv4 UDP broadcast; does not rely on DNS or external STUN/DHT servers.
3. **Metadata:** Canonical metadata is retrieved directly from the first connected seeder.
4. **Dashboard:** Built entirely with offline static vanilla HTML, CSS, and JS; zero external CDNs, fonts, or libraries.
The entire swarm functions flawlessly on an isolated, air-gapped router or mobile phone hotspot.
