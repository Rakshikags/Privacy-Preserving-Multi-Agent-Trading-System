# Privacy-Preserving Multi-Agent Trading System

## Architecture

```
trading_system/
├── README.md
├── requirements.txt
├── config.py                  # System-wide constants & config
├── crypto/
│   ├── __init__.py
│   ├── encryption.py          # Fernet/AES symmetric encryption
│   └── signatures.py          # RSA key generation & digital signatures
├── rbac/
│   ├── __init__.py
│   └── access_control.py      # Role-Based Access Control
├── network/
│   ├── __init__.py
│   ├── protocol.py            # Secure message envelope (serialize/deserialize)
│   └── server.py              # Central broker server (socket-based)
├── agents/
│   ├── __init__.py
│   ├── base_agent.py          # Abstract base agent
│   ├── trader_agent.py        # Executes buy/sell orders
│   └── monitor_agent.py       # Verifies transactions & detects anomalies
├── anomaly/
│   ├── __init__.py
│   └── detector.py            # Isolation Forest anomaly detection
├── ledger/
│   ├── __init__.py
│   └── transaction_log.py     # Append-only verified transaction ledger
└── main.py                    # Entry point — launches broker + agents
```

## Quick Start

```bash
pip install -r requirements.txt
python main.py
```

## Security Model

| Layer | Mechanism |
|---|---|
| Transport confidentiality | Fernet (AES-128-CBC + HMAC-SHA256) |
| Agent identity | RSA-2048 key pairs |
| Message integrity | RSA-PSS digital signatures |
| Authorization | Role-Based Access Control (RBAC) |
| Fraud detection | Isolation Forest (scikit-learn) |
| Audit trail | Append-only SHA-256 chained ledger |

## Roles

- **TRADER** — can submit buy/sell orders
- **MONITOR** — can read all transactions, flag anomalies
- **ADMIN** — can manage agents and view system state
