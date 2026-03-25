"""
network/server.py — Central broker server.

Responsibilities
----------------
• Accept TCP connections from agents.
• Handle REGISTER handshakes (exchange public keys + session key).
• Route and validate all subsequent messages through RBAC.
• Forward verified trades to MONITOR agents.
• Append accepted trades to the ledger.

Threading model: one thread per connected client (simple, clear).
For production scale, replace with asyncio or a thread pool.
"""

import json
import socket
import threading
import logging
from typing import Callable

from config import BROKER_HOST, BROKER_PORT, SOCKET_TIMEOUT, MAX_MESSAGE_BYTES, MsgType, Role
from crypto.encryption import EncryptionManager
from crypto.signatures import SignatureManager
from network.protocol import parse_envelope, open_envelope, build_envelope, ProtocolError
from rbac.access_control import AccessController, AccessDeniedError
from ledger.transaction_log import TransactionLedger

log = logging.getLogger("broker")


# ── Internal data structures ──────────────────────────────────────────────────

class AgentSession:
    """Holds per-connection state for a connected agent."""

    def __init__(
        self,
        agent_id: str,
        role: str,
        pub_key_pem: bytes,
        enc_manager: EncryptionManager,
        conn: socket.socket,
    ) -> None:
        self.agent_id    = agent_id
        self.role        = role
        self.pub_key_pem = pub_key_pem
        self.enc_manager = enc_manager  # shared session key
        self.conn        = conn


# ── Broker ────────────────────────────────────────────────────────────────────

class Broker:
    """
    Central message broker.

    Parameters
    ----------
    anomaly_callback : Callable[[dict], None] | None
        Optional hook called with the raw payload whenever an ANOMALY message
        arrives.  Useful for tests / dashboards.
    """

    def __init__(self, anomaly_callback: Callable[[dict], None] | None = None) -> None:
        self._ac       = AccessController()
        self._ledger   = TransactionLedger()
        self._sessions: dict[str, AgentSession] = {}   # agent_id → session
        self._lock     = threading.Lock()
        self._anomaly_cb = anomaly_callback

        # Broker's own key pair — used to sign ACK/REJECT replies
        priv, pub = SignatureManager.generate_key_pair()
        self._sig_manager = SignatureManager(priv, pub)
        self._pub_key_pem = pub

        self._server_sock: socket.socket | None = None

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Bind the server socket and start accepting connections (blocking)."""
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((BROKER_HOST, BROKER_PORT))
        self._server_sock.listen(16)
        log.info("Broker listening on %s:%d", BROKER_HOST, BROKER_PORT)

        while True:
            try:
                conn, addr = self._server_sock.accept()
                conn.settimeout(SOCKET_TIMEOUT)
                log.debug("New connection from %s", addr)
                t = threading.Thread(target=self._handle_client, args=(conn,), daemon=True)
                t.start()
            except OSError:
                break   # server socket closed

    def stop(self) -> None:
        if self._server_sock:
            self._server_sock.close()

    # ── Connection handler ────────────────────────────────────────────────────

    def _handle_client(self, conn: socket.socket) -> None:
        """Entry point for each client thread."""
        session: AgentSession | None = None
        try:
            # Step 1: expect REGISTER as the first message (plaintext JSON)
            session = self._handle_register(conn)
            if session is None:
                return

            # Step 2: message loop
            while True:
                raw = _recv(conn)
                if raw is None:
                    break
                self._dispatch(session, raw)

        except (ConnectionResetError, TimeoutError, OSError):
            agent_id = session.agent_id if session else "<unknown>"
            log.info("Agent '%s' disconnected", agent_id)
        finally:
            if session:
                with self._lock:
                    self._sessions.pop(session.agent_id, None)
                    self._ac.deregister(session.agent_id)
            conn.close()

    # ── REGISTER handshake ────────────────────────────────────────────────────

    def _handle_register(self, conn: socket.socket) -> AgentSession | None:
        """
        REGISTER handshake (plaintext — no session key yet).

        Agent sends:
            { "msg_type": "REGISTER", "agent_id": ..., "role": ...,
              "pub_key_pem": "<base64>" }

        Broker replies:
            { "status": "OK", "session_key": "<base64 Fernet key>",
              "broker_pub_key": "<base64 PEM>" }
        """
        raw = _recv(conn)
        if raw is None:
            return None

        try:
            data = json.loads(raw.decode())
            assert data.get("msg_type") == MsgType.REGISTER
            agent_id    = data["agent_id"]
            role        = data["role"]
            pub_key_pem = data["pub_key_pem"].encode()
        except (KeyError, AssertionError, json.JSONDecodeError) as exc:
            log.warning("Bad REGISTER message: %s", exc)
            _send(conn, json.dumps({"status": "ERROR", "detail": str(exc)}).encode())
            return None

        # Generate a per-session symmetric key and create the session
        session_key = EncryptionManager.generate_key()
        enc_manager = EncryptionManager(session_key)

        session = AgentSession(
            agent_id=agent_id,
            role=role,
            pub_key_pem=pub_key_pem,
            enc_manager=enc_manager,
            conn=conn,
        )

        with self._lock:
            self._sessions[agent_id] = session
            self._ac.register(agent_id, role)

        # Reply with session key (in production this would be encrypted with
        # the agent's public key; simplified here for clarity)
        reply = {
            "status": "OK",
            "session_key": session_key.decode(),
            "broker_pub_key": self._pub_key_pem.decode(),
        }
        _send(conn, json.dumps(reply).encode())
        log.info("Agent '%s' registered as %s", agent_id, role)
        return session

    # ── Message dispatcher ────────────────────────────────────────────────────

    def _dispatch(self, session: AgentSession, raw: bytes) -> None:
        """Parse, authenticate, authorise, and route one message."""
        try:
            envelope = parse_envelope(raw)
            payload  = open_envelope(envelope, session.enc_manager, session.pub_key_pem)
            self._ac.require_for_message(session.agent_id, envelope.msg_type)

        except (ProtocolError, AccessDeniedError) as exc:
            log.warning("Message rejected from '%s': %s", session.agent_id, exc)
            self._reply(session, MsgType.REJECT, {"detail": str(exc)})
            return

        if envelope.msg_type == MsgType.TRADE:
            self._process_trade(session, payload)
        elif envelope.msg_type == MsgType.ANOMALY:
            self._process_anomaly(session, payload)
        elif envelope.msg_type == MsgType.STATUS:
            self._reply(session, MsgType.ACK, {"ledger_size": self._ledger.size()})
        else:
            log.debug("Unhandled msg_type '%s' from '%s'", envelope.msg_type, session.agent_id)

    # ── Trade processing ──────────────────────────────────────────────────────

    def _process_trade(self, session: AgentSession, payload: dict) -> None:
        """Validate, record, and broadcast a trade."""
        required_fields = {"symbol", "side", "quantity", "price"}
        missing = required_fields - payload.keys()
        if missing:
            self._reply(session, MsgType.REJECT, {"detail": f"Missing fields: {missing}"})
            return

        # Basic sanity checks
        try:
            qty   = float(payload["quantity"])
            price = float(payload["price"])
            assert qty > 0 and price > 0
        except (ValueError, AssertionError):
            self._reply(session, MsgType.REJECT, {"detail": "quantity and price must be positive numbers"})
            return

        # Record to ledger
        txn = {**payload, "trader_id": session.agent_id}
        txn_id = self._ledger.append(txn)
        log.info("Trade #%s accepted: %s %s x%.2f @ %.4f",
                 txn_id, payload["side"], payload["symbol"], qty, price)

        # ACK the trader
        self._reply(session, MsgType.ACK, {"txn_id": txn_id})

        # Broadcast to all MONITOR agents
        self._broadcast_to_monitors(txn_id, txn)

    def _broadcast_to_monitors(self, txn_id: str, txn: dict) -> None:
        """Forward a verified trade to every connected MONITOR agent."""
        with self._lock:
            monitors = [
                s for s in self._sessions.values()
                if s.role in (Role.MONITOR, Role.ADMIN)
            ]
        for monitor in monitors:
            self._reply(monitor, MsgType.BROADCAST, {"txn_id": txn_id, **txn})

    # ── Anomaly processing ────────────────────────────────────────────────────

    def _process_anomaly(self, session: AgentSession, payload: dict) -> None:
        log.warning("⚠ ANOMALY flagged by '%s': %s", session.agent_id, payload)
        if self._anomaly_cb:
            self._anomaly_cb(payload)

    # ── Reply helper ──────────────────────────────────────────────────────────

    def _reply(self, session: AgentSession, msg_type: str, payload: dict) -> None:
        """Send an encrypted, signed reply to *session*."""
        try:
            raw = build_envelope(
                msg_type=msg_type,
                sender_id="broker",
                plaintext_payload=payload,
                enc_manager=session.enc_manager,
                sig_manager=self._sig_manager,
            )
            _send(session.conn, raw)
        except OSError as exc:
            log.debug("Could not reply to '%s': %s", session.agent_id, exc)


# ── Socket I/O helpers ────────────────────────────────────────────────────────

def _send(conn: socket.socket, data: bytes) -> None:
    """Length-prefix frame: 4-byte big-endian length + payload."""
    length = len(data).to_bytes(4, "big")
    conn.sendall(length + data)


def _recv(conn: socket.socket) -> bytes | None:
    """Read one length-prefixed frame.  Returns None on clean close."""
    header = _recv_exact(conn, 4)
    if header is None:
        return None
    length = int.from_bytes(header, "big")
    if length > MAX_MESSAGE_BYTES:
        raise ProtocolError(f"Message too large: {length} bytes")
    return _recv_exact(conn, length)


def _recv_exact(conn: socket.socket, n: int) -> bytes | None:
    """Read exactly *n* bytes or return None on EOF."""
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)
