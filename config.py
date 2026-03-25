"""
config.py — System-wide configuration constants.

Keep all magic numbers and tunables here so every module imports
from a single source of truth.
"""

# ── Network ──────────────────────────────────────────────────────────────────
BROKER_HOST: str = "127.0.0.1"
BROKER_PORT: int = 9999
SOCKET_TIMEOUT: float = 10.0          # seconds before a recv/send gives up
MAX_MESSAGE_BYTES: int = 65_536       # 64 KB max envelope size

# ── Cryptography ──────────────────────────────────────────────────────────────
RSA_KEY_BITS: int = 2048              # RSA key size (min recommended)
RSA_PUBLIC_EXPONENT: int = 65537

# ── Anomaly Detection ─────────────────────────────────────────────────────────
ANOMALY_CONTAMINATION: float = 0.05   # Expected fraction of anomalous txns
ANOMALY_MIN_SAMPLES: int = 20         # Minimum history before model trains

# ── RBAC ─────────────────────────────────────────────────────────────────────
class Role:
    TRADER  = "TRADER"
    MONITOR = "MONITOR"
    ADMIN   = "ADMIN"

# ── Message Types ─────────────────────────────────────────────────────────────
class MsgType:
    REGISTER   = "REGISTER"    # Agent → Broker: announce identity + public key
    TRADE      = "TRADE"       # Trader → Broker: submit an order
    BROADCAST  = "BROADCAST"   # Broker → Monitor: forward verified trade
    ACK        = "ACK"         # Broker → Trader: trade accepted
    REJECT     = "REJECT"      # Broker → Trader: trade rejected
    ANOMALY    = "ANOMALY"     # Monitor → Broker: flag suspicious trade
    STATUS     = "STATUS"      # Any agent: heartbeat / status query
