"""Configuration constants for P2P Swarm.

This module centralizes all system-wide parameters, protocol definitions,
timeouts, and security limits. All values follow Section 5 of PROJECT_SPEC.md.
"""

from typing import Final

# Wire Protocol Version
PROTOCOL_VERSION: Final[int] = 1

# Piece Size Parameters (bytes)
# 64 KiB default strikes a good balance between network packet overhead and memory usage on LAN.
DEFAULT_PIECE_SIZE: Final[int] = 65536  # 64 KiB
MIN_PIECE_SIZE: Final[int] = 16384       # 16 KiB
MAX_PIECE_SIZE: Final[int] = 4194304     # 4 MiB

# Maximum pieces per swarm. If a dataset exceeds this with the default piece size,
# the sender chooses a larger power-of-two piece size up to MAX_PIECE_SIZE.
MAX_PIECES: Final[int] = 100000

# Network Ports
DEFAULT_TCP_PORT: Final[int] = 6881     # Peer-to-peer data transfer port
DISCOVERY_PORT: Final[int] = 50000      # UDP broadcast port for heartbeats and beacons
DEFAULT_WEB_PORT: Final[int] = 8080     # HTTP port for the receiver's monitor dashboard

# Discovery and Heartbeat Timing (seconds)
HEARTBEAT_INTERVAL: Final[float] = 2.0  # Periodic announce frequency
OFFLINE_AFTER: Final[float] = 8.0       # Threshold to consider an absent peer offline
DEVICE_EXPIRY_AFTER: Final[float] = 60.0  # Prune offline device after 60 seconds
DEFAULT_MIN_SENDERS: Final[int] = 2     # Minimum discovered senders required to start download
DEFAULT_DISCOVER_TIMEOUT: Final[float] = 20.0  # Timeout waiting for min senders in seconds
MAX_DEVICE_IDS_PER_IP: Final[int] = 8     # Cap on distinct device IDs accepted per source IP
MAX_CONCURRENT_CONNECT_ATTEMPTS: Final[int] = 4  # Limit concurrent connection attempts to candidates

# Message Size Limits (defense against allocation exhaustion attacks)
MAX_DISCOVERY_PACKET_BYTES: Final[int] = 1024        # 1 KiB max UDP packet size
MAX_HEADER_BYTES: Final[int] = 65536             # 64 KiB max JSON header
MAX_PIECE_PAYLOAD: Final[int] = MAX_PIECE_SIZE   # Max binary payload for a PIECE message
MAX_METADATA_BYTES: Final[int] = 16777216        # 16 MiB max JSON payload for METADATA

# Peer Connection Timeouts & Limits
HANDSHAKE_TIMEOUT: Final[float] = 10.0  # TLS handshake and authentication timeout in seconds
SOCKET_TIMEOUT: Final[float] = 30.0     # Idle socket read/write timeout in seconds
REQUEST_TIMEOUT: Final[float] = 5.0    # Per-request response timeout in seconds
MAX_FILES: Final[int] = 10000           # Cap on number of files in a swarm
MAX_TOTAL_BYTES: Final[int] = 50 * 1024 * 1024 * 1024  # 50 GiB max swarm payload

# Concurrency & Rate Limiting
MAX_CONNECTIONS_PER_SENDER: Final[int] = 8  # Maximum simultaneous peer connections
MAX_REQUESTS_PER_SEC: Final[int] = 500      # Max piece requests per second per connection

# Security & Authentication Limits
AUTH_MAX_FAILURES: Final[int] = 5       # Max failed handshakes from an IP before temporary block
AUTH_BLOCK_SECONDS: Final[float] = 60.0 # Duration of temporary IP block after auth failures
HASH_STRIKES_TO_BAN: Final[int] = 3     # Corrupted piece deliveries before banning a sender

# Reliability & Retries
MAX_PIECE_ATTEMPTS: Final[int] = 6      # Max download attempts for a piece before failing transfer
CONNECT_RETRIES: Final[int] = 3         # Reconnect attempts per sender (backoff: 1, 2, 4 seconds)

# Telemetry and Reporting
REPORT_INTERVAL: Final[float] = 0.5     # Interval between sender telemetry reports to the tracker
REPORT_CLOCK_SKEW: Final[float] = 30.0  # Maximum tolerated timestamp skew in seconds
MAX_REPORT_BYTES: Final[int] = 65536    # 64 KiB maximum body size for POST /api/report

# Tracker & Monitor Limits
MAX_DEVICES: Final[int] = 256           # Device table entry cap
MAX_EVENTS: Final[int] = 200            # Size of in-memory circular event buffer
PIECE_MAP_MAX_CELLS: Final[int] = 400   # Maximum grid cells displayed on dashboard
