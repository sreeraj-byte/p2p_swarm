"""Live terminal device table viewer for P2P Swarm.

Listens to UDP discovery heartbeats and beacons on DISCOVERY_PORT (50000)
and displays a live, formatted terminal table of all discovered devices.
"""

import argparse
import os
from pathlib import Path
import sys
import time

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from common.discovery import DeviceTable, DiscoveryListener
import config


def format_table(table: DeviceTable) -> str:
    """Generate a clean ASCII formatted table from the device table."""
    devices = table.get_devices(only_online=False)
    now = time.time()

    lines = []
    lines.append("=" * 105)
    lines.append(
        f"{'Device ID':<18} {'Name':<18} {'IP:Port':<22} {'Role':<10} {'Swarm ID':<10} {'Status':<9} {'Trust':<11} {'Last Seen'}"
    )
    lines.append("-" * 105)

    if not devices:
        lines.append("No devices discovered yet. Listening on LAN...")
    else:
        for dev in devices:
            dev_id_short = dev.device_id[:16] + "..." if len(dev.device_id) > 16 else dev.device_id
            addr_str = f"{dev.ip}:{dev.tcp_port}" if dev.role == "sender" else (f"{dev.ip}:{dev.web_port}" if dev.web_port else dev.ip)
            swarm_str = dev.swarm_id_short[:8] if dev.swarm_id_short else "-"
            silence = max(0.0, now - dev.last_seen)
            silence_str = f"{silence:.1f}s ago" if silence < 60 else f"{int(silence // 60)}m ago"

            status_marker = dev.status.upper()
            trust_marker = dev.trust

            lines.append(
                f"{dev_id_short:<18} {dev.name:<18} {addr_str:<22} {dev.role:<10} {swarm_str:<10} "
                f"{status_marker:<9} {trust_marker:<11} {silence_str}"
            )

    lines.append("=" * 105)
    online_count = sum(1 for d in devices if d.is_online())
    lines.append(f"Total: {len(devices)} devices ({online_count} online) | Press Ctrl+C to exit")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="P2P Swarm Live Terminal Device Table")
    parser.add_argument(
        "--port",
        type=int,
        default=config.DISCOVERY_PORT,
        help=f"UDP discovery port to listen on (default: {config.DISCOVERY_PORT})",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Print the table once and exit (waits briefly for announcements)",
    )
    parser.add_argument(
        "--wait",
        type=float,
        default=2.5,
        help="Seconds to listen when --once is specified (default: 2.5)",
    )

    args = parser.parse_args()

    device_table = DeviceTable()
    listener = DiscoveryListener(
        own_device_id="monitor_tool_" + os.urandom(4).hex(),
        device_table=device_table,
        port=args.port,
    )

    listener.start()

    try:
        if args.once:
            time.sleep(args.wait)
            print(format_table(device_table))
            return

        while True:
            # Clear screen (POSIX or Windows)
            os.system("clear" if os.name == "posix" else "cls")
            print(f"P2P Swarm Discovery Monitor | UDP Port {args.port}\n")
            print(format_table(device_table))
            time.sleep(1.0)

    except KeyboardInterrupt:
        print("\nDiscovery monitor stopped.")
    finally:
        listener.stop()


if __name__ == "__main__":
    main()
