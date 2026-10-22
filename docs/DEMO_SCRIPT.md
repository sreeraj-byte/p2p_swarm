# P2P Swarm: 5-Minute Live Demonstration Script

This script provides an exact, step-by-step walkthrough for presenting **P2P Swarm** during a 5-minute technical review or viva examination.

---

## Demo Schedule & Time Allocation

| Time | Phase | Focus / What to Demonstrate |
|---|---|---|
| **0:00 – 1:00** | **Setup & Swarm Initiation** | Generate certs, generate test data, launch Senders A & B (throttled to 250 KB/s). |
| **1:00 – 2:00** | **Multi-Sender Transfer & Live Dashboard** | Launch Receiver C; observe A/B piece split (50%/50%), dynamic SVG curve thickness, and piece map. |
| **2:00 – 3:00** | **Fault Tolerance & Seeder Kill** | Abruptly kill Sender A; observe seamless failover to Sender B without corruption. |
| **3:00 – 4:00** | **Security: Rogue Join Code & XSS Test** | Attempt connection with wrong join code; register malicious device `<script>alert(1)</script>`. |
| **4:00 – 5:00** | **Packet Capture & Wrap-up** | Inspect TLS 1.3 encrypted packets in Wireshark/tcpdump; summarize architecture. |

---

## Step-by-Step Commands & Speaking Notes

### 0:00 – 1:00: Setup & Swarm Initiation

1. **Open 4 Terminal Windows** (Terminals 1, 2, 3, 4).
2. **Terminal 1 — Generate Certificates & Test Files:**
   ```bash
   cd p2p_swarm
   source .venv/bin/activate
   # Generate pinned certificate with localhost SAN
   python tools/gen_certs.py --out certs --ip 127.0.0.1
   # Generate multi-file test dataset (3 files, ~500 KB, 8 pieces)
   python tools/make_test_data.py --out sample_data
   # Export shared join code
   export P2P_JOIN_CODE="YOUR-SECRET-JOIN-CODE"
   ```

3. **Terminal 1 — Start Sender A (throttled):**
   ```bash
   python sender.py --path sample_data --port 6881 --name Laptop-A --cert certs/cert.pem --key certs/key.pem --throttle-kbps 250
   ```
   *Expected Output:*
   ```
   P2P Swarm Sender | name=Laptop-A | 0.0.0.0:6881 | TLS on
   Sharing: sample_data/ (3 files, 0.5 MB, 8 pieces of 64 KiB)  swarm=a3b9f10c
   Ready for receiver connections...
   ```

4. **Terminal 2 — Start Sender B (throttled):**
   ```bash
   cd p2p_swarm
   source .venv/bin/activate
   export P2P_JOIN_CODE="YOUR-SECRET-JOIN-CODE"
   python sender.py --path sample_data --port 6882 --name Laptop-B --cert certs/cert.pem --key certs/key.pem --throttle-kbps 250
   ```
   *Expected Output:*
   ```
   P2P Swarm Sender | name=Laptop-B | 0.0.0.0:6882 | TLS on
   Sharing: sample_data/ (3 files, 0.5 MB, 8 pieces of 64 KiB)  swarm=a3b9f10c
   Ready for receiver connections...
   ```

---

### 1:00 – 2:00: Multi-Sender Transfer & Live Dashboard

1. **Terminal 3 — Start Receiver C:**
   ```bash
   cd p2p_swarm
   source .venv/bin/activate
   export P2P_JOIN_CODE="YOUR-SECRET-JOIN-CODE"
   python receiver.py --out downloads --cert certs/cert.pem --senders 127.0.0.1:6881 127.0.0.1:6882
   ```

2. **Open Browser at `http://localhost:8080`:**
   - **Point Out to Examiner:**
     - **Header Badges:** `TLS ON` (green) and `AUTH ON` (blue) confirming transport encryption and mutual HMAC authentication.
     - **Live Transfer Map (Inline SVG):** Notice the two curved streams converging from Laptop-A and Laptop-B to Receiver-C. Line thicknesses are equal because each sender is contributing 50% of the pieces.
     - **Piece Map:** Color-blind-safe matrix showing pieces alternating in Sky Blue (`#38bdf8`) for Laptop-A and Orange (`#fb923c`) for Laptop-B.
     - **Per-File Stacked Bars:** Showing chunk boundaries across file1, file2, and file3 with dual-colored contributor bars.

---

### 2:00 – 3:00: Fault Tolerance & Killing a Sender Mid-Transfer

1. While the download is running (~40% progress), **switch to Terminal 1 (Laptop-A) and press `Ctrl+C`**.
2. **Observe Terminal 3 (Receiver):**
   - Receiver logs: `Connection to Laptop-A lost. Re-queuing in-flight pieces.`
   - Receiver does not crash; instead, all remaining pieces are automatically fulfilled by **Laptop-B**.
3. **Observe Web Dashboard:**
   - On the SVG map, Laptop-A's link turns gray and dims to 25% opacity with an `OFFLINE` tag.
   - Laptop-B's line thickness grows to 100% of the active throughput.
   - Transfer successfully finishes: `Summary: 8 pieces | A: 3 (38%) | B: 5 (63%) | bad pieces: 0 | files: 3/3`.

---

### 3:00 – 4:00: Security Defense: Wrong Join Code & XSS Demonstration

1. **Terminal 4 — Attempt Rogue Connection with Wrong Join Code:**
   ```bash
   # Attacker has the legitimate cert.pem, but guesses wrong code
   export P2P_JOIN_CODE="wrong-stolen-code"
   python sender.py --path sample_data --port 6889 --name Rogue --cert certs/cert.pem --key certs/key.pem
   ```
2. In another terminal, simulate receiver attempting connection to rogue sender:
   ```bash
   export P2P_JOIN_CODE="YOUR-SECRET-JOIN-CODE"
   python receiver.py --out test_rogue --cert certs/cert.pem --senders 127.0.0.1:6889 --no-tracker
   ```
   *Expected Result:*
   `Authentication failed with 127.0.0.1:6889: Server proof verification failed.`
   *Speaking Point:* "Even with valid TLS certificates, an attacker without the classroom join code cannot decrypt or request any pieces."

3. **Demonstrate XSS Immunity in Dashboard:**
   - Show unit test `test_xss_protection_device_name_rendered_as_plain_text`:
     ```bash
     pytest tests/test_tracker.py -k test_xss
     ```
   - *Speaking Point:* "Notice the test passes. When a device name `<script>alert(1)</script>` enters the tracker, our frontend renders strictly via `textContent`. Zero `innerHTML`, zero inline script or styles, backed by a strict `Content-Security-Policy: default-src 'self'`."

---

### 4:00 – 5:00: Packet Capture (Wireshark / tcpdump) & Conclusion

1. **Inspect Traffic on Wire:**
   ```bash
   sudo tcpdump -i lo0 -nn -X -c 10 "port 6881 or port 6882"
   ```
   *Point Out:* All packets display encrypted TLS 1.3 records (`TLSv1.3 Application Data`, opaque hexadecimal payloads). Zero plaintext strings, zero join codes, and zero file contents leak onto the wire.
2. **Conclude Demo:**
   - Summarize that the swarm fulfills high-speed parallel retrieval, direct-to-disk sparse writes, cryptographic piece verification, automatic discovery, and real-time visualization entirely offline.
