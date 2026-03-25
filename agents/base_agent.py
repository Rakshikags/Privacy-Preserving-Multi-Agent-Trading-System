"""
agents/base_agent.py — Abstract base class for all trading agents.

Handles:
  • TCP connection to the broker
  • REGISTER handshake (sends public key, receives session key)
  • Encrypted, signed message sending
  • Encrypted message receiving and decrypting in a background thread
  • Subclass hook :meth:`on_message` for type-specific logic
"""

import json
import socket
import threading
import logging
from abc import ABC, abstractmethod

from config import BROKER_HOST, BROKER_PORT, SOCKET_TIMEOUT, MsgType
from crypto.encryption import EncryptionManager
from crypto.signatures import SignatureManager
from network.protocol import build_envelope, parse_envelope, open_envelope, ProtocolError

log = logging.getLogger("agent")


class BaseAgent(ABC):
    """
    Abstract agent that speaks the broker protocol.

    Subclasses must implement :meth:`on_message` to handle incoming messages,
    and call :meth:`send` to transmit messages.
    """

    def __init__(self, agent_id: str, role: str) -> None:
        self.agent_id = agent_id
        self.role     = role

        # Generate this agent's identity key pair
        priv, pub = SignatureManager.generate_key_pair()
        self._sig_manager = SignatureManager(priv, pub)
        self._pub_key_pem = pub

        self._enc_manager: EncryptionManager | None = None
        self._broker_pub_key: bytes | None          = None
        self._conn: socket.socket | None            = None
        self._running = False

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def connect(self) -> None:
        """Open a TCP connection to the broker and complete the REGISTER handshake."""
        self._conn = socket.create_connection((BROKER_HOST, BROKER_PORT), timeout=SOCKET_TIMEOUT)
        log.info("[%s] Connected to broker", self.agent_id)
        self._register()
        self._running = True
        # Start background receive loop
        t = threading.Thread(target=self._recv_loop, daemon=True)
        t.start()

    def disconnect(self) -> None:
        self._running = False
        if self._conn:
            try:
                self._conn.close()
            except OSError:
                pass

    # ── REGISTER handshake ────────────────────────────────────────────────────

    def _register(self) -> None:
        """Send REGISTER and receive the session key from the broker."""
        msg = json.dumps({
            "msg_type":    MsgType.REGISTER,
            "agent_id":    self.agent_id,
            "role":        self.role,
            "pub_key_pem": self._pub_key_pem.decode(),
        }).encode()
        _send(self._conn, msg)

        raw = _recv(self._conn)
        if raw is None:
            raise ConnectionError("Broker closed connection during handshake")

        reply = json.loads(raw.decode())
        if reply.get("status") != "OK":
            raise ConnectionError(f"Registration rejected: {reply}")

        session_key          = reply["session_key"].encode()
        self._enc_manager    = EncryptionManager(session_key)
        self._broker_pub_key = reply["broker_pub_key"].encode()
        log.info("[%s] Registered with role=%s", self.agent_id, self.role)

    # ── Send ──────────────────────────────────────────────────────────────────

    def send(self, msg_type: str, payload: dict) -> None:
        """
        Build a signed, encrypted envelope and send it to the broker.

        Parameters
        ----------
        msg_type : str
            One of :class:`config.MsgType`.
        payload : dict
            Application-level data.
        """
        if self._enc_manager is None:
            raise RuntimeError("Agent not connected — call connect() first")
        raw = build_envelope(
            msg_type=msg_type,
            sender_id=self.agent_id,
            plaintext_payload=payload,
            enc_manager=self._enc_manager,
            sig_manager=self._sig_manager,
        )
        _send(self._conn, raw)

    # ── Receive loop ──────────────────────────────────────────────────────────

    def _recv_loop(self) -> None:
        """Background thread: receive and dispatch incoming messages."""
        while self._running:
            try:
                raw = _recv(self._conn)
                if raw is None:
                    break
                envelope = parse_envelope(raw)
                payload  = open_envelope(envelope, self._enc_manager, self._broker_pub_key)
                self.on_message(envelope.msg_type, payload)
            except (ProtocolError, OSError) as exc:
                if self._running:
                    log.warning("[%s] Receive error: %s", self.agent_id, exc)
                break
        log.info("[%s] Receive loop ended", self.agent_id)

    # ── Hook for subclasses ───────────────────────────────────────────────────

    @abstractmethod
    def on_message(self, msg_type: str, payload: dict) -> None:
        """
        Called by the receive loop for every incoming message.

        Parameters
        ----------
        msg_type : str
            The envelope's msg_type field.
        payload : dict
            Decrypted, verified payload.
        """


# ── Socket I/O (mirrors server.py helpers) ────────────────────────────────────

def _send(conn: socket.socket, data: bytes) -> None:
    length = len(data).to_bytes(4, "big")
    conn.sendall(length + data)


def _recv(conn: socket.socket) -> bytes | None:
    header = _recv_exact(conn, 4)
    if header is None:
        return None
    length = int.from_bytes(header, "big")
    return _recv_exact(conn, length)


def _recv_exact(conn: socket.socket, n: int) -> bytes | None:
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)
