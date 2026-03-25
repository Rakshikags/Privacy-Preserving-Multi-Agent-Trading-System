"""
network/protocol.py — Secure message envelope.

Every message transmitted between agents and the broker is wrapped in a
SecureEnvelope.  The envelope guarantees:

  1. Authenticity  — sender_id + RSA signature over the plaintext payload
  2. Confidentiality — payload encrypted with the shared Fernet session key
  3. Integrity     — Fernet's built-in HMAC; signature over plaintext

Wire format (JSON → UTF-8 bytes, length-prefixed by server):

    {
      "msg_type":  "TRADE",
      "sender_id": "trader-1",
      "payload":   "<base64 Fernet token>",
      "signature": "<base64 RSA-PSS signature over raw plaintext payload>"
    }

The *signature* is computed over the raw (unencrypted) payload bytes so
that the broker can verify identity before decrypting — a common pattern
in secure protocols (sign-then-encrypt or encrypt-then-sign; here we use
sign-plaintext, encrypt-separately).
"""

import json
import base64
from dataclasses import dataclass, asdict

from crypto.encryption import EncryptionManager
from crypto.signatures import SignatureManager, SignatureError


class ProtocolError(Exception):
    """Raised on malformed or unauthenticated envelopes."""


@dataclass
class SecureEnvelope:
    """Immutable wire message.  All fields are strings for JSON serialisation."""
    msg_type:  str   # one of config.MsgType
    sender_id: str   # agent identifier
    payload:   str   # base64-encoded Fernet ciphertext
    signature: str   # base64-encoded RSA-PSS signature over raw plaintext


# ── Serialisation helpers ─────────────────────────────────────────────────────

def build_envelope(
    msg_type: str,
    sender_id: str,
    plaintext_payload: dict,
    enc_manager: EncryptionManager,
    sig_manager: SignatureManager,
) -> bytes:
    """
    Construct, sign, encrypt, and serialise a :class:`SecureEnvelope` to JSON bytes.

    Parameters
    ----------
    plaintext_payload : dict
        The application-level message (will be JSON-encoded before signing).
    enc_manager : EncryptionManager
        Shared session key used to encrypt the payload.
    sig_manager : SignatureManager
        Sender's private-key manager used to produce the signature.

    Returns
    -------
    bytes
        UTF-8 JSON bytes ready to be written to a socket.
    """
    # 1. Serialise payload to bytes (sign the canonical form)
    raw_payload: bytes = json.dumps(plaintext_payload, sort_keys=True).encode()

    # 2. Sign the raw plaintext
    print("✍️ Signing message...")
    signature: bytes = sig_manager.sign(raw_payload)

    # 3. Encrypt the payload
    print("🔒 Encrypting message...")
    ciphertext: bytes = enc_manager.encrypt(raw_payload)

    # 4. Pack everything into an envelope
    envelope = SecureEnvelope(
        msg_type=msg_type,
        sender_id=sender_id,
        payload=base64.b64encode(ciphertext).decode(),
        signature=base64.b64encode(signature).decode(),
    )
    return json.dumps(asdict(envelope)).encode()


def parse_envelope(raw: bytes) -> SecureEnvelope:
    """
    Deserialise JSON bytes into a :class:`SecureEnvelope`.

    Raises
    ------
    ProtocolError
        If the bytes are not valid JSON or lack required fields.
    """
    try:
        data = json.loads(raw.decode())
        return SecureEnvelope(
            msg_type=data["msg_type"],
            sender_id=data["sender_id"],
            payload=data["payload"],
            signature=data["signature"],
        )
    except (KeyError, json.JSONDecodeError) as exc:
        raise ProtocolError(f"Malformed envelope: {exc}") from exc


def open_envelope(
    envelope: SecureEnvelope,
    enc_manager: EncryptionManager,
    sender_pub_key_pem: bytes,
) -> dict:
    """
    Decrypt and verify a :class:`SecureEnvelope`.

    Steps
    -----
    1. Decrypt ciphertext → raw plaintext bytes.
    2. Verify RSA-PSS signature over plaintext.
    3. Deserialise plaintext to dict and return.

    Raises
    ------
    ProtocolError
        On decryption failure or invalid signature.
    """
    try:
        ciphertext = base64.b64decode(envelope.payload)
        signature  = base64.b64decode(envelope.signature)
    except Exception as exc:
        raise ProtocolError(f"Base64 decode error: {exc}") from exc

    # Decrypt
    from crypto.encryption import EncryptionError
    try:
        print("🔓 Decrypting message...")
        plaintext = enc_manager.decrypt(ciphertext)
    except EncryptionError as exc:
        raise ProtocolError(f"Decryption failed: {exc}") from exc

    # Verify signature over the decrypted plaintext
    try:
        print("✔️ Verifying signature...")
        SignatureManager.verify(sender_pub_key_pem, plaintext, signature)
    except SignatureError as exc:
        raise ProtocolError(f"Signature invalid for sender '{envelope.sender_id}': {exc}") from exc

    return json.loads(plaintext.decode())
