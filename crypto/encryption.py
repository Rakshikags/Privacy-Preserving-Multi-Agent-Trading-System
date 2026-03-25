"""
crypto/encryption.py — Symmetric encryption using Fernet (AES-128-CBC + HMAC).

Fernet guarantees:
  • Confidentiality  — AES-128 in CBC mode
  • Integrity       — HMAC-SHA256 authentication tag
  • Freshness       — embedded timestamp (replay window configurable)

Usage
-----
    key = EncryptionManager.generate_key()
    em  = EncryptionManager(key)
    token = em.encrypt(b"hello")
    plain = em.decrypt(token)
"""

from cryptography.fernet import Fernet, InvalidToken


class EncryptionError(Exception):
    """Raised when decryption or key operations fail."""


class EncryptionManager:
    """Wraps Fernet to provide a clean encrypt/decrypt interface."""

    def __init__(self, key: bytes) -> None:
        """
        Parameters
        ----------
        key : bytes
            A URL-safe base64-encoded 32-byte Fernet key.
            Generate one with :meth:`generate_key`.
        """
        self._fernet = Fernet(key)

    # ── Key Management ────────────────────────────────────────────────────────

    @staticmethod
    def generate_key() -> bytes:
        """Return a fresh, cryptographically secure Fernet key."""
        return Fernet.generate_key()

    # ── Encrypt / Decrypt ─────────────────────────────────────────────────────

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt *plaintext* and return an opaque Fernet token (bytes).

        The token includes a timestamp; use :meth:`decrypt_with_ttl` to
        enforce message freshness.
        """
        return self._fernet.encrypt(plaintext)

    def decrypt(self, token: bytes) -> bytes:
        """
        Decrypt *token* and return the original plaintext.

        Raises
        ------
        EncryptionError
            If the token is malformed, tampered with, or encrypted with a
            different key.
        """
        try:
            return self._fernet.decrypt(token)
        except InvalidToken as exc:
            raise EncryptionError("Decryption failed — invalid token or wrong key") from exc

    def decrypt_with_ttl(self, token: bytes, ttl_seconds: int) -> bytes:
        """
        Decrypt *token* and reject messages older than *ttl_seconds*.

        This provides replay-attack protection: a captured ciphertext
        cannot be replayed after the TTL window expires.

        Raises
        ------
        EncryptionError
            If the token is invalid or has expired.
        """
        try:
            return self._fernet.decrypt(token, ttl=ttl_seconds)
        except InvalidToken as exc:
            raise EncryptionError(
                f"Decryption failed — token invalid or older than {ttl_seconds}s"
            ) from exc
