# Mobile Hotspot Test Checklist & Evaluation Procedure

This document provides a step-by-step testing checklist for deploying and evaluating **P2P Swarm** over mobile Wi-Fi hotspots and academic campus subnets.

---

## 1. Network Environment Pre-Flight Checks

Before starting a multi-laptop test, verify the network conditions of the tethering environment:

- [ ] **Hotspot Type:** Android Wi-Fi Hotspot, iOS Personal Hotspot, or portable travel router.
- [ ] **Wi-Fi Band:** 5 GHz preferred for high throughput; 2.4 GHz acceptable for range.
- [ ] **Subnet & IP Assignment:**
  - Verify all participating devices receive valid IP addresses in the same subnet (e.g., `192.168.43.0/24` on Android or `172.20.10.0/28` on iOS).
  - Run `ip a` (Linux), `ifconfig` (macOS), or `ipconfig` (Windows) on each device.
- [ ] **AP / Client Isolation Check:**
  - *Test:* From Laptop A, run `ping <IP_OF_LAPTOP_B>`.
  - *Result:* If pings fail with `Request timed out` or `Host is down`, **AP Isolation is enabled** by the hotspot/carrier.
  - *Remedy:* Disable AP Isolation in phone hotspot advanced settings, use an Android device with tethering isolation disabled, or use a hardware travel router.
- [ ] **UDP Broadcast Support:**
  - Verify that directed broadcasts (`255.255.255.255` or subnet broadcast `192.168.43.255`) reach peers on port 50000.
  - If broadcast packets are dropped by the mobile OS, use the `--senders <IP>:<PORT>` CLI fallback.

---

## 2. Multi-Device Setup Checklist

### Device Roles
- **Node 1 (Sender A):** Seeder holding shared directory `sample_data/`.
- **Node 2 (Sender B):** Seeder holding shared directory `sample_data/`.
- **Node 3 (Receiver C):** Downloader retrieving files to `downloaded_data/`.

### Pre-Deployment Preparation
- [ ] **Certificates:** Generate certificate with all LAN IP addresses:
  ```bash
  python tools/gen_certs.py --out certs --ip 127.0.0.1 <IP_NODE_1> <IP_NODE_2> <IP_NODE_3>
  ```
- [ ] **Credential Distribution:**
  - Copy `certs/cert.pem` and `certs/key.pem` to Node 1 and Node 2.
  - Copy **only** `certs/cert.pem` to Node 3.
  - Set restrictive permissions on private key: `chmod 600 certs/key.pem`.
- [ ] **Shared Join Code:** Configure the exact same `P2P_JOIN_CODE` environment variable on all three laptops.
- [ ] **Sample Dataset:** Generate sample dataset on Node 1 and Node 2:
  ```bash
  python tools/make_test_data.py --out sample_data
  ```

---

## 3. Step-by-Step Test Procedure

### Test 1: Baseline Multi-Sender Swarm Transfer
1. **Start Senders:**
   - On Node 1: `python sender.py --path sample_data --name Laptop-A --cert certs/cert.pem --key certs/key.pem --throttle-kbps 250`
   - On Node 2: `python sender.py --path sample_data --name Laptop-B --cert certs/cert.pem --key certs/key.pem --throttle-kbps 250`
2. **Start Receiver:**
   - On Node 3: `python receiver.py --out downloads --cert certs/cert.pem --min-senders 2`
3. **Verify:**
   - [ ] Both senders discovered via UDP broadcast on port 50000.
   - [ ] Receiver outputs `Verified Laptop-A OK` and `Verified Laptop-B OK`.
   - [ ] Terminal progress bar updates smoothly in real time.
   - [ ] Final summary displays proportional piece distribution across A and B (approx 50%/50% split).
   - [ ] File checksums match original source files: `shasum -a 256 downloads/*`.

### Test 2: Sender Failover & Disconnection Handling
1. Start transfer with Node 1 and Node 2.
2. At 40% progress, abruptly terminate Node 1 (`Ctrl+C` or pull power/close lid).
3. **Verify:**
   - [ ] Receiver detects socket disconnection on Node 1.
   - [ ] In-flight piece assigned to Node 1 is returned to the shared work queue.
   - [ ] Node 2 automatically picks up all remaining pieces.
   - [ ] Download successfully completes to 100% without hang or data corruption.

### Test 3: Unauthorized Peer & Wrong Join Code Rejection
1. Launch rogue sender with valid certificate but incorrect join code:
   `P2P_JOIN_CODE="wrong-code" python sender.py --path sample_data --name Rogue --port 6889 --cert certs/cert.pem --key certs/key.pem`
2. Attempt connection from Receiver:
   `python receiver.py --out test_rogue --cert certs/cert.pem --senders <ROGUE_IP>:6889`
3. **Verify:**
   - [ ] Receiver rejects server proof; no metadata or piece data requested.
   - [ ] Sender logs authentication failure and increments rate-limiting failure counter.

### Test 4: Real-Time Web Dashboard Inspection
1. Open `http://<RECEIVER_IP>:8080` on Node 3 or from a smartphone connected to the same hotspot.
2. **Verify:**
   - [ ] `TLS ON` and `AUTH ON` green badges displayed.
   - [ ] Inline SVG topology map renders real-time curved connections to both senders.
   - [ ] Line stroke thickness reflects each sender's data contribution.
   - [ ] Downsampled piece matrix colors cells by sender using color-blind-safe swatches.
   - [ ] Event log records events in chronological order.

---

## 4. Latency & Jitter Diagnostic Metrics

When recording test results for your project report or viva presentation, document the following network metrics:

| Metric | Hotspot Condition | Measurement Method | Typical Target |
|---|---|---|---|
| **Ping Latency (RTT)** | Idle Wi-Fi Link | `ping <sender_ip>` | 2 – 15 ms |
| **Ping Latency (Loaded)** | Active Transfer | `ping <sender_ip>` during download | 15 – 45 ms |
| **Jitter / StdDev** | Active Transfer | `ping -c 50 <sender_ip>` | < 10 ms |
| **Aggregated Throughput** | Multi-Sender Pull | Receiver summary throughput | 5 – 25 MB/s (Wi-Fi 5/6) |
| **Verification Overhead** | Per-Piece Hash | SHA-256 over 64 KiB chunk | < 0.2 ms per piece |
