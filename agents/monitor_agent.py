"""
agents/monitor_agent.py — Monitor agent: verifies transactions and flags anomalies.

The monitor receives every BROADCAST message from the broker (i.e. every
verified trade), feeds it to the Isolation Forest detector, and sends an
ANOMALY message back to the broker when suspicious activity is detected.
"""

import logging
from config import MsgType, Role
from agents.base_agent import BaseAgent
from anomaly.detector import AnomalyDetector

log = logging.getLogger("monitor")


class MonitorAgent(BaseAgent):
    """
    Passively observes all trades and raises anomaly alerts.

    The agent accumulates a rolling window of recent transactions and retrains
    the Isolation Forest model periodically (delegated to AnomalyDetector).
    """

    def __init__(self, agent_id: str) -> None:
        super().__init__(agent_id=agent_id, role=Role.MONITOR)
        self._detector = AnomalyDetector()
        self.anomaly_count = 0

    # ── Incoming message handler ───────────────────────────────────────────────

    def on_message(self, msg_type: str, payload: dict) -> None:
        if msg_type == MsgType.BROADCAST:
            self._handle_broadcast(payload)
        elif msg_type == MsgType.ACK:
            # ACK for our own ANOMALY report — nothing to do
            pass
        else:
            log.debug("[%s] Unhandled msg_type '%s'", self.agent_id, msg_type)

    # ── Broadcast processing ──────────────────────────────────────────────────

    def _handle_broadcast(self, payload: dict) -> None:
        """Feed trade to detector; raise ANOMALY if suspicious."""
        txn_id   = payload.get("txn_id", "?")
        symbol   = payload.get("symbol", "UNKNOWN")
        quantity = float(payload.get("quantity", 0))
        price    = float(payload.get("price", 0))

        log.info("[%s] Received trade #%s — %s qty=%.4f price=%.4f",
                 self.agent_id, txn_id, symbol, quantity, price)

        is_anomaly = self._detector.record_and_predict(quantity, price)

        if is_anomaly:
            self.anomaly_count += 1
            alert = {
                "txn_id":   txn_id,
                "symbol":   symbol,
                "quantity": quantity,
                "price":    price,
                "reason":   "Isolation Forest: statistical outlier",
            }
            log.warning("[%s] ⚠ Anomaly detected for txn #%s — flagging broker", self.agent_id, txn_id)
            self.send(MsgType.ANOMALY, alert)
