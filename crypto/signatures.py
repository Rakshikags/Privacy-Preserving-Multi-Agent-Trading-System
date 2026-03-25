"""
crypto/signatures.py — RSA-2048 key generation and PSS digital signatures.

Design choices
--------------
• RSA-PSS (probabilistic) over PKCS#1 v1.5 — PSS is provably secure and
  the recommended padding scheme for new systems.
• SHA-256 as the hash algorithm — well-understood, widely deployed.
• Keys serialised to PEM for easy storage / transmission.

Usage
-----
    priv, pub = SignatureManager.generate_key_pair()
    sm  = SignatureManager(priv, pub)

    sig = sm.sign(b"my message")
    ok  = SignatureManager.verify(pub_pem=pub, message=b"my message", signature=sig)
"""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.exceptions import InvalidSignature

from config import RSA_KEY_BITS, RSA_PUBLIC_EXPONENT


class SignatureError(Exception):
    """Raised when signature verification fails."""


class SignatureManager:
    """Generates RSA key pairs and produces / verifies PSS signatures."""

    def __init__(self, private_key_pem: bytes, public_key_pem: bytes) -> None:
        self._private_key: RSAPrivateKey = serialization.load_pem_private_key(
            private_key_pem, password=None
        )
        self._public_key: RSAPublicKey = serialization.load_pem_public_key(public_key_pem)

    # ── Key Generation ────────────────────────────────────────────────────────

    @staticmethod
    def generate_key_pair() -> tuple[bytes, bytes]:
        """
        Generate a fresh RSA-2048 key pair.

        Returns
        -------
        (private_key_pem, public_key_pem) : tuple[bytes, bytes]
            Both keys in PEM-encoded bytes.  Keep the private key secret;
            share the public key freely.
        """
        private_key = rsa.generate_private_key(
            public_exponent=RSA_PUBLIC_EXPONENT,
            key_size=RSA_KEY_BITS,
        )
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),  # caller controls storage
        )
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return private_pem, public_pem

    # ── Sign ──────────────────────────────────────────────────────────────────

    def sign(self, message: bytes) -> bytes:
        """
        Sign *message* with the agent's private key using RSA-PSS + SHA-256.

        Returns
        -------
        bytes
            Raw signature bytes (256 bytes for RSA-2048).
        """
        return self._private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

    # ── Verify ────────────────────────────────────────────────────────────────

    @staticmethod
    def verify(pub_key_pem: bytes, message: bytes, signature: bytes) -> bool:
        """
        Verify *signature* over *message* using *pub_key_pem*.

        Returns
        -------
        bool
            ``True`` if valid.

        Raises
        ------
        SignatureError
            If the signature is invalid or the key cannot be loaded.
        """
        try:
            public_key: RSAPublicKey = serialization.load_pem_public_key(pub_key_pem)
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except InvalidSignature as exc:
            raise SignatureError("Signature verification failed") from exc
        except Exception as exc:
            raise SignatureError(f"Key or signature error: {exc}") from exc
