"""Automatic UDP Discovery for P2P Swarm.

Implements Section 11 and Section 14.4:
- Periodic UDP broadcasts on DISCOVERY_PORT (50000) for HEARTBEAT and BEACON.
- Directed broadcasts to every IPv4 interface discovered via psutil plus 255.255.255.255 and 127.0.0.1.
- Sockets use SO_REUSEADDR and SO_REUSEPORT so multiple processes can run on one machine.
- Device identity is based on random device_id; IP is strictly taken from the UDP packet source.
- Name sanitization (max 32 chars, printable characters only, stripped control chars).
- 1 KiB maximum packet cap: oversized and malformed packets are dropped before processing.
- Thread-safe DeviceTable capped at MAX_DEVICES (256) with offline and expiry pruning rules.
- Untrusted discovery data: devices start as 'discovered' and become 'verified' only after TLS + auth handshake.
"""

from dataclasses import asdict, dataclass
import ipaddress
import json
import logging
from pathlib import Path
import select
import socket
import sys
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import psutil

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import config

logger = logging.getLogger("p2p_swarm.discovery")


def sanitize_device_name(name: Any) -> str:
    """Sanitize device name: max 32 characters, printable only, no control chars.

    Args:
        name: Raw name from input or network.

    Returns:
        Sanitized printable string up to 32 characters, defaulting to 'Anonymous'.
    """
    if not isinstance(name, str):
        name = str(name) if name is not None else "Anonymous"

    # Filter to printable characters (excluding control characters and non-printable bytes)
    cleaned = "".join(c for c in name if c.isprintable() and ord(c) >= 32)
    cleaned = cleaned.strip()

    if not cleaned:
        return "Anonymous"

    return cleaned[:32]


def get_broadcast_addresses() -> List[str]:
    """Discover all IPv4 broadcast destinations across all active network interfaces.

    Returns:
        Sorted list of unique broadcast IPv4 strings, including:
        - 255.255.255.255 (global broadcast)
        - Subnet directed broadcast addresses from psutil (e.g. 192.168.1.255)
        - 127.0.0.1 (loopback unicast fallback for single-machine multi-process testing)
    """
    destinations: Set[str] = {"255.255.255.255", "127.0.0.1"}

    try:
        net_if_addrs = psutil.net_if_addrs()
        net_if_stats = psutil.net_if_stats()
    except Exception as err:
        logger.debug("psutil interface enumeration failed: %s", err)
        return sorted(destinations)

    for iface_name, addrs in net_if_addrs.items():
        stats = net_if_stats.get(iface_name)
        if stats and not stats.isup:
            continue

        for addr in addrs:
            if addr.family == socket.AF_INET:
                # 1. Use explicit broadcast address provided by OS if available
                if addr.broadcast:
                    destinations.add(addr.broadcast)
                # 2. Derive broadcast address from IP and netmask
                elif addr.address and addr.netmask and addr.address != "127.0.0.1":
                    try:
                        net = ipaddress.IPv4Network(f"{addr.address}/{addr.netmask}", strict=False)
                        destinations.add(str(net.broadcast_address))
                    except Exception:
                        pass

    return sorted(destinations)


def get_lan_ip() -> Optional[str]:
    """Return the primary LAN IPv4 address of this host, or None if unavailable."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and not ip.startswith("127."):
            return ip
    except Exception:
        pass

    try:
        net_if_addrs = psutil.net_if_addrs()
        net_if_stats = psutil.net_if_stats()
        for iface_name, addrs in net_if_addrs.items():
            stats = net_if_stats.get(iface_name)
            if stats and not stats.isup:
                continue
            for addr in addrs:
                if addr.family == socket.AF_INET and addr.address:
                    if not addr.address.startswith("127.") and not addr.address.startswith("169.254."):
                        return addr.address
    except Exception:
        pass

    return None


def format_dashboard_urls(host: Optional[str], port: int) -> str:
    """Format dashboard URL string, never printing 0.0.0.0.

    When bound to 0.0.0.0, empty string, or None, prints:
    http://127.0.0.1:PORT and http://<LAN IP>:PORT
    (or http://127.0.0.1:PORT if LAN IP is unavailable).
    """
    if host in ("0.0.0.0", "", "::", None):
        lan = get_lan_ip()
        if lan and lan != "127.0.0.1":
            return f"http://127.0.0.1:{port} and http://{lan}:{port}"
        return f"http://127.0.0.1:{port}"
    return f"http://{host}:{port}"


def make_heartbeat(
    device_id: str,
    name: str,
    role: str = "sender",
    tcp_port: int = config.DEFAULT_TCP_PORT,
    swarm_name: Optional[str] = None,
    swarm_id_short: Optional[str] = None,
    files: int = 0,
    total_bytes: int = 0,
) -> bytes:
    """Build a JSON-encoded HEARTBEAT datagram payload (Section 11)."""
    payload = {
        "v": config.PROTOCOL_VERSION,
        "type": "HEARTBEAT",
        "device_id": str(device_id),
        "name": sanitize_device_name(name),
        "role": role,
        "tcp_port": int(tcp_port),
        "swarm_name": str(swarm_name or ""),
        "swarm_id_short": str(swarm_id_short or ""),
        "files": int(files),
        "total_bytes": int(total_bytes),
    }
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def make_beacon(
    device_id: str,
    web_port: int = config.DEFAULT_WEB_PORT,
) -> bytes:
    """Build a JSON-encoded BEACON datagram payload (Section 11)."""
    payload = {
        "v": config.PROTOCOL_VERSION,
        "type": "BEACON",
        "device_id": str(device_id),
        "web_port": int(web_port),
    }
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


@dataclass
class DeviceEntry:
    """Represents a discovered network peer in the device table."""

    device_id: str
    name: str
    ip: str  # Packet source IP, never from JSON body
    tcp_port: int
    role: str  # "sender", "receiver", "tracker"
    swarm_name: str = ""
    swarm_id_short: str = ""
    files: int = 0
    total_bytes: int = 0
    web_port: Optional[int] = None
    first_seen: float = 0.0
    last_seen: float = 0.0
    status: str = "online"  # "online", "offline"
    trust: str = "discovered"  # "discovered", "verified", "banned"

    def is_online(self) -> bool:
        """Return True if device status is online."""
        return self.status == "online"

    def to_dict(self) -> Dict[str, Any]:
        """Convert entry to dictionary representation."""
        return asdict(self)


class DeviceTable:
    """Thread-safe table tracking discovered devices with capping and pruning rules."""

    def __init__(
        self,
        max_devices: int = config.MAX_DEVICES,
        offline_after: float = config.OFFLINE_AFTER,
        expiry_after: float = config.DEVICE_EXPIRY_AFTER,
        max_device_ids_per_ip: int = config.MAX_DEVICE_IDS_PER_IP,
    ) -> None:
        self.max_devices = max_devices
        self.offline_after = offline_after
        self.expiry_after = expiry_after
        self.max_device_ids_per_ip = max_device_ids_per_ip
        self._devices: Dict[str, DeviceEntry] = {}
        self._lock = threading.Lock()

    def update_from_heartbeat(self, msg: Dict[str, Any], source_ip: str, now: Optional[float] = None) -> Optional[DeviceEntry]:
        """Insert or update a device entry from an authenticated or discovered heartbeat.

        Args:
            msg: Parsed and validated JSON payload.
            source_ip: Source IP extracted directly from recvfrom().
            now: Optional current timestamp (defaults to time.time()).

        Returns:
            The updated or newly created DeviceEntry, or None if dropped.
        """
        device_id = msg.get("device_id")
        if not device_id or not isinstance(device_id, str):
            return None

        current_time = now if now is not None else time.time()
        name = sanitize_device_name(msg.get("name", "Anonymous"))
        role = str(msg.get("role", "sender"))
        tcp_port = int(msg.get("tcp_port", config.DEFAULT_TCP_PORT))
        swarm_name = str(msg.get("swarm_name", ""))
        swarm_id_short = str(msg.get("swarm_id_short", ""))
        files = int(msg.get("files", 0))
        total_bytes = int(msg.get("total_bytes", 0))

        with self._lock:
            # 1. Update existing entry
            if device_id in self._devices:
                entry = self._devices[device_id]
                entry.name = name
                entry.ip = source_ip  # Always bind to observed packet source
                entry.tcp_port = tcp_port
                entry.role = role
                entry.swarm_name = swarm_name
                entry.swarm_id_short = swarm_id_short
                entry.files = files
                entry.total_bytes = total_bytes
                entry.last_seen = current_time
                entry.status = "online"
                return entry

            # 2. Check per-source-IP cap on distinct device IDs
            ids_for_ip = sum(1 for dev in self._devices.values() if dev.ip == source_ip)
            if ids_for_ip >= self.max_device_ids_per_ip:
                logger.debug(
                    "Source IP %s reached max device IDs cap (%d). Dropping new device %s",
                    source_ip,
                    self.max_device_ids_per_ip,
                    device_id,
                )
                return None

            # 3. Prune expired entries before admitting new device
            if len(self._devices) >= self.max_devices:
                self._prune_locked(current_time)

            # 4. If table is still full, do not evict existing devices to admit new ones
            if len(self._devices) >= self.max_devices:
                logger.warning(
                    "DeviceTable is at MAX_DEVICES (%d). Rejecting new device %s",
                    self.max_devices,
                    device_id,
                )
                return None

            # 5. Insert new device entry
            new_entry = DeviceEntry(
                device_id=device_id,
                name=name,
                ip=source_ip,
                tcp_port=tcp_port,
                role=role,
                swarm_name=swarm_name,
                swarm_id_short=swarm_id_short,
                files=files,
                total_bytes=total_bytes,
                first_seen=current_time,
                last_seen=current_time,
                status="online",
                trust="discovered",
            )
            self._devices[device_id] = new_entry
            return new_entry

    def update_from_beacon(self, msg: Dict[str, Any], source_ip: str, now: Optional[float] = None) -> Optional[DeviceEntry]:
        """Update tracker entry from a BEACON message."""
        device_id = msg.get("device_id")
        if not device_id or not isinstance(device_id, str):
            return None

        current_time = now if now is not None else time.time()
        web_port = int(msg.get("web_port", config.DEFAULT_WEB_PORT))

        with self._lock:
            if device_id in self._devices:
                entry = self._devices[device_id]
                entry.ip = source_ip
                entry.web_port = web_port
                entry.last_seen = current_time
                entry.status = "online"
                return entry

            # Check per-source-IP cap
            ids_for_ip = sum(1 for dev in self._devices.values() if dev.ip == source_ip)
            if ids_for_ip >= self.max_device_ids_per_ip:
                return None

            if len(self._devices) >= self.max_devices:
                self._prune_locked(current_time)

            if len(self._devices) >= self.max_devices:
                return None

            new_entry = DeviceEntry(
                device_id=device_id,
                name="Tracker",
                ip=source_ip,
                tcp_port=0,
                role="tracker",
                web_port=web_port,
                first_seen=current_time,
                last_seen=current_time,
                status="online",
                trust="discovered",
            )
            self._devices[device_id] = new_entry
            return new_entry

        return None

    def mark_verified(self, device_id: str) -> bool:
        """Mark a device as verified after successful TLS and join-code handshake."""
        with self._lock:
            if device_id in self._devices:
                self._devices[device_id].trust = "verified"
                return True
            # Also support matching by IP:port or label if device_id is formatted
            for dev in self._devices.values():
                if f"{dev.ip}:{dev.tcp_port}" == device_id or dev.name == device_id:
                    dev.trust = "verified"
                    return True
        return False

    def mark_banned(self, device_id: str) -> bool:
        """Mark a device as banned (e.g. after HASH_STRIKES_TO_BAN strikes)."""
        with self._lock:
            if device_id in self._devices:
                self._devices[device_id].trust = "banned"
                return True
            for dev in self._devices.values():
                if f"{dev.ip}:{dev.tcp_port}" == device_id or dev.name == device_id:
                    dev.trust = "banned"
                    return True
        return False

    def prune(self, now: Optional[float] = None) -> None:
        """Prune devices exceeding offline and expiry thresholds."""
        current_time = now if now is not None else time.time()
        with self._lock:
            self._prune_locked(current_time)

    def _prune_locked(self, current_time: float) -> None:
        """Internal prune implementation holding _lock."""
        expired_ids = []
        for dev_id, dev in self._devices.items():
            silence = current_time - dev.last_seen
            if silence > self.expiry_after:
                expired_ids.append(dev_id)
            elif silence > self.offline_after:
                dev.status = "offline"

        for dev_id in expired_ids:
            del self._devices[dev_id]

    def get_devices(
        self,
        role: Optional[str] = None,
        swarm_id_short: Optional[str] = None,
        only_online: bool = False,
        now: Optional[float] = None,
    ) -> List[DeviceEntry]:
        """Return snapshot of devices matching criteria."""
        self.prune(now)
        with self._lock:
            results = []
            for dev in self._devices.values():
                if only_online and not dev.is_online():
                    continue
                if role and dev.role != role:
                    continue
                if swarm_id_short and dev.swarm_id_short != swarm_id_short:
                    continue
                results.append(dev)
            return sorted(results, key=lambda d: d.name)

    def get_device(self, device_id: str) -> Optional[DeviceEntry]:
        """Retrieve a device entry by device_id."""
        with self._lock:
            return self._devices.get(device_id)

    def get_senders_by_swarm(
        self,
        only_online: bool = True,
        now: Optional[float] = None,
    ) -> Dict[str, List[DeviceEntry]]:
        """Group candidate senders by swarm_id_short (Section 9.1 Step 3)."""
        self.prune(now)
        grouped: Dict[str, List[DeviceEntry]] = {}
        with self._lock:
            for dev in self._devices.values():
                if dev.role != "sender":
                    continue
                if only_online and not dev.is_online():
                    continue
                if not dev.swarm_id_short:
                    continue
                grouped.setdefault(dev.swarm_id_short, []).append(dev)
        return grouped

    def clear(self) -> None:
        """Clear all entries (test fixture helper)."""
        with self._lock:
            self._devices.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._devices)


class DiscoveryBroadcaster:
    """Sends periodic UDP broadcast datagrams on DISCOVERY_PORT."""

    def __init__(
        self,
        payload_factory: Callable[[], bytes],
        port: int = config.DISCOVERY_PORT,
        interval: float = config.HEARTBEAT_INTERVAL,
    ) -> None:
        self.payload_factory = payload_factory
        self.port = port
        self.interval = interval
        self._sock: Optional[socket.socket] = None
        self._is_running = False
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start broadcaster background thread."""
        if self._is_running:
            return

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self._is_running = True

        self._thread = threading.Thread(target=self._broadcast_loop, daemon=True)
        self._thread.start()

    def broadcast_once(self) -> None:
        """Send a single broadcast datagram to all discovered IPv4 destinations."""
        if not self._sock:
            return

        try:
            payload = self.payload_factory()
        except Exception as err:
            logger.debug("Failed building discovery payload: %s", err)
            return

        destinations = get_broadcast_addresses()
        for dest_ip in destinations:
            try:
                self._sock.sendto(payload, (dest_ip, self.port))
            except OSError:
                # Ignore unreachable subnets or disabled virtual interfaces without crashing
                pass

    def _broadcast_loop(self) -> None:
        """Periodic broadcast execution loop."""
        # Send immediate initial announcement
        self.broadcast_once()

        while self._is_running:
            time.sleep(self.interval)
            if self._is_running:
                self.broadcast_once()

    def stop(self) -> None:
        """Stop broadcaster background thread and close socket."""
        self._is_running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None


class DiscoveryListener:
    """Listens on UDP DISCOVERY_PORT with SO_REUSEADDR and SO_REUSEPORT."""

    def __init__(
        self,
        own_device_id: str,
        device_table: DeviceTable,
        port: int = config.DISCOVERY_PORT,
        on_sender_discovered: Optional[Callable[[DeviceEntry], None]] = None,
        on_tracker_discovered: Optional[Callable[[DeviceEntry], None]] = None,
    ) -> None:
        self.own_device_id = str(own_device_id)
        self.device_table = device_table
        self.port = port
        self.on_sender_discovered = on_sender_discovered
        self.on_tracker_discovered = on_tracker_discovered

        self._sock: Optional[socket.socket] = None
        self._is_running = False
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Bind socket and start listener background thread."""
        if self._is_running:
            return

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Enable SO_REUSEADDR and SO_REUSEPORT so multiple local processes can bind to DISCOVERY_PORT
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                pass
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        # Bind to all IPv4 interfaces
        self._sock.bind(("", self.port))
        self._sock.settimeout(0.5)

        self._is_running = True
        self._thread = threading.Thread(target=self._listen_loop, daemon=True)
        self._thread.start()

    def _listen_loop(self) -> None:
        """Listen for UDP discovery datagrams and update device table."""
        while self._is_running and self._sock:
            try:
                raw_data, addr = self._sock.recvfrom(config.MAX_DISCOVERY_PACKET_BYTES + 64)
            except (TimeoutError, socket.timeout):
                continue
            except OSError:
                break

            # 1. Cap enforcement: drop datagrams larger than MAX_DISCOVERY_PACKET_BYTES (1 KiB)
            if len(raw_data) > config.MAX_DISCOVERY_PACKET_BYTES:
                logger.debug("Dropped oversized discovery packet (%d bytes) from %s", len(raw_data), addr)
                continue

            # 2. JSON validation
            try:
                msg = json.loads(raw_data.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue

            if not isinstance(msg, dict):
                continue

            # 3. Protocol version and message validation
            if msg.get("v") != config.PROTOCOL_VERSION:
                continue

            msg_type = msg.get("type")
            sender_device_id = msg.get("device_id")

            # 4. Own-heartbeat filtering: ignore datagrams originating from this process
            if sender_device_id == self.own_device_id:
                continue

            source_ip = addr[0]  # Take source IP directly from packet, NEVER from body!

            if msg_type == "HEARTBEAT":
                entry = self.device_table.update_from_heartbeat(msg, source_ip=source_ip)
                if entry and self.on_sender_discovered and entry.role == "sender":
                    try:
                        self.on_sender_discovered(entry)
                    except Exception as err:
                        logger.debug("on_sender_discovered callback error: %s", err)

            elif msg_type == "BEACON":
                entry = self.device_table.update_from_beacon(msg, source_ip=source_ip)
                if entry and self.on_tracker_discovered and entry.role == "tracker":
                    try:
                        self.on_tracker_discovered(entry)
                    except Exception as err:
                        logger.debug("on_tracker_discovered callback error: %s", err)

    def stop(self) -> None:
        """Stop listener thread and close socket."""
        self._is_running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None


class DiscoveryService:
    """Unified service coordinating discovery broadcasting, listening, and device state."""

    def __init__(
        self,
        device_id: str,
        name: str,
        role: str = "sender",
        tcp_port: int = config.DEFAULT_TCP_PORT,
        swarm_name: Optional[str] = None,
        swarm_id_short: Optional[str] = None,
        files: int = 0,
        total_bytes: int = 0,
        discovery_port: int = config.DISCOVERY_PORT,
        on_sender_discovered: Optional[Callable[[DeviceEntry], None]] = None,
        device_table: Optional[DeviceTable] = None,
    ) -> None:
        self.device_id = device_id
        self.name = name
        self.role = role
        self.tcp_port = tcp_port
        self.swarm_name = swarm_name
        self.swarm_id_short = swarm_id_short
        self.files = files
        self.total_bytes = total_bytes
        self.discovery_port = discovery_port

        self.device_table = device_table or DeviceTable()

        # Broadcaster
        def payload_factory() -> bytes:
            return make_heartbeat(
                device_id=self.device_id,
                name=self.name,
                role=self.role,
                tcp_port=self.tcp_port,
                swarm_name=self.swarm_name,
                swarm_id_short=self.swarm_id_short,
                files=self.files,
                total_bytes=self.total_bytes,
            )

        self.broadcaster = DiscoveryBroadcaster(
            payload_factory=payload_factory,
            port=self.discovery_port,
        )

        # Listener
        self.listener = DiscoveryListener(
            own_device_id=self.device_id,
            device_table=self.device_table,
            port=self.discovery_port,
            on_sender_discovered=on_sender_discovered,
        )

    def start(self) -> None:
        """Start both listener and broadcaster."""
        self.listener.start()
        self.broadcaster.start()

    def stop(self) -> None:
        """Stop both broadcaster and listener."""
        self.broadcaster.stop()
        self.listener.stop()
