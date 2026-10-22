"""Run a live throttled transfer with two senders and an embedded tracker for browser verification."""

import json
import logging
from pathlib import Path
import shutil
import sys
import threading
import time
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent.resolve()))

from common.auth import get_join_code
from tools.gen_certs import generate_self_signed_cert
from sender import SenderServer
from receiver import SwarmReceiver

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("demo")


def main():
    base_dir = Path("demo_run").resolve()
    if base_dir.exists():
        shutil.rmtree(base_dir)
    base_dir.mkdir(parents=True, exist_ok=True)

    cert_dir = base_dir / "certs"
    cert_path, key_path = generate_self_signed_cert(out_dir=cert_dir)

    # Multi-file source directory
    shared_dir = base_dir / "shared"
    shared_dir.mkdir()
    (shared_dir / "lecture1.pdf").write_bytes(b"LectureNotesPDFPayload..." * 4000)   # ~100 KB
    (shared_dir / "solver.py").write_bytes(b"print('Solving matrix equations...')\n" * 2500) # ~85 KB
    (shared_dir / "dataset.bin").write_bytes(b"BinarySimulationDatasetBytes..." * 4500) # ~140 KB
    # Total ~325 KB -> 5 pieces of 64 KB

    join_code = "demo-swarm-join-code-2026"
    dest_dir = base_dir / "downloads"
    dest_dir.mkdir()

    # Sender 1: Laptop-A, throttled at 25 KB/s
    sender_a = SenderServer(
        source_path=shared_dir,
        port=0,
        name="Laptop-A",
        cert_path=cert_path,
        key_path=key_path,
        join_code=join_code,
        piece_size=65536,
        throttle_kbps=25,
        enable_discovery=False,
    )
    sender_a.start(blocking=False)

    # Sender 2: Laptop-B, throttled at 25 KB/s
    sender_b = SenderServer(
        source_path=shared_dir,
        port=0,
        name="Laptop-B",
        cert_path=cert_path,
        key_path=key_path,
        join_code=join_code,
        piece_size=65536,
        throttle_kbps=25,
        enable_discovery=False,
    )
    sender_b.start(blocking=False)

    time.sleep(0.1)

    web_port = 8080
    receiver = SwarmReceiver(
        senders=[f"127.0.0.1:{sender_a.port}", f"127.0.0.1:{sender_b.port}"],
        out_dir=dest_dir,
        cert_path=cert_path,
        join_code=join_code,
        name="Receiver-C",
        verbose=True,
        enable_discovery=False,
        enable_tracker=True,
        web_port=web_port,
        web_host="127.0.0.1",
        keep_tracker_alive=True,
    )

    t = threading.Thread(target=receiver.download, daemon=True)
    t.start()

    logger.info("Demo swarm running! Dashboard at http://127.0.0.1:%d", web_port)
    logger.info("Sender A at port %d, Sender B at port %d", sender_a.port, sender_b.port)

    # Keep alive for 120 seconds for browser verification
    try:
        for _ in range(120):
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        sender_a.stop()
        sender_b.stop()
        if receiver.tracker_server:
            receiver.tracker_server.stop()
        logger.info("Demo swarm stopped.")


if __name__ == "__main__":
    main()
