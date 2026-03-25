"""
main.py — Entry point for the Privacy-Preserving Multi-Agent Trading System.

Launch sequence
---------------
1. Start the broker in a background daemon thread.
2. Allow 0.5 s for the broker to bind its socket.
3. Connect one MonitorAgent (observes all trades, flags anomalies).
4. Connect two TraderAgents and submit a series of trades.
   - Most trades are "normal" (small quantity, mid-range price).
   - Two trades are outliers designed to trigger the anomaly detector once
     enough history has been collected.
5. Wait for all messages to settle, then verify ledger integrity.
"""

import logging
import random
import time
import threading

# ── Logging — configure before importing any module that uses logging ─────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("main")

from network.server import Broker
from agents.trader_agent import TraderAgent
from agents.monitor_agent import MonitorAgent


# ── Helpers ───────────────────────────────────────────────────────────────────

def start_broker() -> Broker:
    """Instantiate and start the broker in a background daemon thread."""
    broker = Broker()
    t = threading.Thread(target=broker.start, name="broker", daemon=True)
    t.start()
    return broker


def connect_agents(
    monitor: MonitorAgent,
    traders: list[TraderAgent],
    startup_delay: float = 0.5,
) -> None:
    """
    Wait for the broker to start, then connect all agents.

    The monitor connects first so it is registered before any trades arrive.
    """
    time.sleep(startup_delay)
    monitor.connect()
    time.sleep(0.1)          # small gap — ensures monitor is registered first
    for trader in traders:
        trader.connect()
        time.sleep(0.05)


def run_normal_trades(trader: TraderAgent, n: int = 25) -> None:
    """Submit *n* normal trades to build up the detector's history."""
    symbols = ["BTC/USD", "ETH/USD", "SOL/USD", "AAPL", "TSLA"]
    for i in range(n):
        symbol   = random.choice(symbols)
        side     = random.choice(["buy", "sell"])
        quantity = round(random.uniform(0.1, 5.0), 4)
        price    = round(random.uniform(100.0, 500.0), 2)
        trader.submit_trade(symbol, side, quantity, price)
        time.sleep(0.05)     # pace the messages


def run_anomalous_trades(trader: TraderAgent) -> None:
    """Submit a few extreme trades that the Isolation Forest should flag."""
    log.info("── Submitting anomalous trades ──────────────────────────────")
    # Massively outsized quantity
    trader.submit_trade("BTC/USD", "buy", quantity=99_999.0, price=0.0001)
    time.sleep(0.1)
    # Price far outside normal range
    trader.submit_trade("ETH/USD", "sell", quantity=0.0001, price=9_999_999.0)
    time.sleep(0.1)


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    log.info("═" * 60)
    log.info("  Privacy-Preserving Multi-Agent Trading System")
    log.info("═" * 60)

    # 1. Broker
    broker = start_broker()

    # 2. Agents
    monitor  = MonitorAgent("monitor-1")
    trader_a = TraderAgent("trader-alice")
    trader_b = TraderAgent("trader-bob")

    connect_agents(monitor, [trader_a, trader_b])

    # 3. Normal trade history (fills detector window)
    log.info("── Building normal trade history ────────────────────────────")
    run_normal_trades(trader_a, n=15)
    run_normal_trades(trader_b, n=10)

    # 4. Anomalous trades (should trigger ANOMALY messages once ≥20 samples)
    run_anomalous_trades(trader_a)

    # 5. A few more normal trades after the anomalies
    run_normal_trades(trader_b, n=5)

    # 6. Allow all in-flight messages to settle
    time.sleep(1.5)

    # 7. Ledger integrity check
    log.info("── Ledger integrity verification ────────────────────────────")
    # Access the broker's ledger via its internal reference for the demo;
    # in production this would be a separate admin RPC call.
    ok = broker._ledger.verify_integrity()
    log.info("Ledger integrity: %s", "✓ PASS" if ok else "✗ FAIL")
    log.info("Total recorded transactions: %d", broker._ledger.size())
    log.info("Monitor anomaly alerts raised: %d", monitor.anomaly_count)

    log.info("═" * 60)
    log.info("  Demo complete.  Press Ctrl-C to exit.")
    log.info("═" * 60)

    # Keep main thread alive so daemon threads can finish logging
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log.info("Shutting down.")
        broker.stop()
        trader_a.disconnect()
        trader_b.disconnect()
        monitor.disconnect()


if __name__ == "__main__":
    main()
