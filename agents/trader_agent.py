"""
agents/trader_agent.py — Trader agent: submits buy/sell orders to the broker.

Usage
-----
    trader = TraderAgent("trader-1")
    trader.connect()
    trader.submit_trade("BTC/USD", "buy", quantity=0.5, price=62000.0)
"""

import logging
from config import MsgType, Role
from agents.base_agent import BaseAgent

log = logging.getLogger("trader")


class TraderAgent(BaseAgent):
    """
    Sends TRADE messages and listens for ACK / REJECT replies.

    The agent is intentionally simple: it trusts the broker's ACK and logs
    the assigned transaction ID.
    """

    def __init__(self, agent_id: str) -> None:
        super().__init__(agent_id=agent_id, role=Role.TRADER)
        # Track pending trade results: txn_id → status
        self.trade_results: dict[str, str] = {}

    # ── Public API ────────────────────────────────────────────────────────────

    def submit_trade(
        self,
        symbol: str,
        side: str,
        quantity: float,
        price: float,
    ) -> None:
        """
        Submit a trade order to the broker.

        Parameters
        ----------
        symbol   : str   Instrument ticker, e.g. "BTC/USD"
        side     : str   "buy" or "sell"
        quantity : float Number of units
        price    : float Limit price per unit
        """
        if side not in ("buy", "sell"):
            raise ValueError(f"Invalid side '{side}' — must be 'buy' or 'sell'")
        if quantity <= 0 or price <= 0:
            raise ValueError("quantity and price must be positive")

        payload = {
            "symbol":   symbol,
            "side":     side,
            "quantity": quantity,
            "price":    price,
        }
        log.info("[%s] Submitting trade: %s %s x%.4f @ %.4f",
                 self.agent_id, side.upper(), symbol, quantity, price)
        self.send(MsgType.TRADE, payload)

    # ── Incoming message handler ───────────────────────────────────────────────

    def on_message(self, msg_type: str, payload: dict) -> None:
        if msg_type == MsgType.ACK:
            txn_id = payload.get("txn_id", "?")
            self.trade_results[txn_id] = "accepted"
            log.info("[%s] ✓ Trade accepted — txn_id=%s", self.agent_id, txn_id)

        elif msg_type == MsgType.REJECT:
            detail = payload.get("detail", "no detail")
            log.warning("[%s] ✗ Trade rejected: %s", self.agent_id, detail)

        else:
            log.debug("[%s] Unhandled msg_type '%s'", self.agent_id, msg_type)
