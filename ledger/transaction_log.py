"""
ledger/transaction_log.py — Append-only SHA-256 chained transaction ledger.

Each entry hashes (previous_hash + entry_data) to form a tamper-evident
chain — the same principle used in blockchain systems.  Tampering with any
historical record invalidates all subsequent hashes.

Usage
-----
    ledger = TransactionLedger()
    txn_id = ledger.append({"symbol": "BTC/USD", "side": "buy", ...})
    entries = ledger.all()
    ok = ledger.verify_integrity()
"""

import hashlib
import json
import threading
import time
import uuid
import logging

log = logging.getLogger("ledger")

# Sentinel hash for the genesis block (no previous entry)
GENESIS_HASH = "0" * 64


class LedgerEntry:
    """One immutable record in the ledger."""

    __slots__ = ("txn_id", "timestamp", "data", "prev_hash", "entry_hash")

    def __init__(
        self,
        txn_id:     str,
        timestamp:  float,
        data:       dict,
        prev_hash:  str,
        entry_hash: str,
    ) -> None:
        self.txn_id     = txn_id
        self.timestamp  = timestamp
        self.data       = data
        self.prev_hash  = prev_hash
        self.entry_hash = entry_hash

    def to_dict(self) -> dict:
        return {
            "txn_id":     self.txn_id,
            "timestamp":  self.timestamp,
            "data":       self.data,
            "prev_hash":  self.prev_hash,
            "entry_hash": self.entry_hash,
        }


class TransactionLedger:
    """
    Thread-safe, append-only ledger with SHA-256 hash chaining.

    The ledger lives in memory only.  For persistence, extend :meth:`append`
    to write each entry to a file or database before returning.
    """

    def __init__(self) -> None:
        self._entries: list[LedgerEntry] = []
        self._lock = threading.Lock()

    # ── Write ─────────────────────────────────────────────────────────────────

    def append(self, data: dict) -> str:
        """
        Append a new transaction record and return its ``txn_id``.

        Parameters
        ----------
        data : dict
            Arbitrary transaction data (must be JSON-serialisable).

        Returns
        -------
        str
            Unique transaction ID (UUID4).
        """
        with self._lock:
            txn_id    = str(uuid.uuid4())
            timestamp = time.time()
            prev_hash = self._entries[-1].entry_hash if self._entries else GENESIS_HASH

            # Compute hash over canonical representation of this entry
            raw = json.dumps(
                {"txn_id": txn_id, "timestamp": timestamp, "data": data, "prev_hash": prev_hash},
                sort_keys=True,
            ).encode()
            entry_hash = hashlib.sha256(raw).hexdigest()

            entry = LedgerEntry(
                txn_id=txn_id,
                timestamp=timestamp,
                data=data,
                prev_hash=prev_hash,
                entry_hash=entry_hash,
            )
            self._entries.append(entry)
            log.debug("Ledger: appended txn_id=%s hash=%s…", txn_id, entry_hash[:12])
            return txn_id

    # ── Read ──────────────────────────────────────────────────────────────────

    def all(self) -> list[dict]:
        """Return all ledger entries as a list of dicts (snapshot)."""
        with self._lock:
            return [e.to_dict() for e in self._entries]

    def get(self, txn_id: str) -> dict | None:
        """Return the entry with *txn_id*, or ``None`` if not found."""
        with self._lock:
            for entry in self._entries:
                if entry.txn_id == txn_id:
                    return entry.to_dict()
        return None

    def size(self) -> int:
        """Return the number of recorded transactions."""
        with self._lock:
            return len(self._entries)

    # ── Integrity ─────────────────────────────────────────────────────────────

    def verify_integrity(self) -> bool:
        """
        Re-compute every hash in the chain and confirm the chain is unbroken.

        Returns
        -------
        bool
            ``True`` if every entry's stored hash matches the recomputed hash
            AND every ``prev_hash`` links correctly to the preceding entry.
        """
        with self._lock:
            prev_hash = GENESIS_HASH
            for i, entry in enumerate(self._entries):
                # Verify linkage
                if entry.prev_hash != prev_hash:
                    log.error(
                        "Ledger integrity FAIL at index %d: prev_hash mismatch "
                        "(expected %s…, got %s…)",
                        i, prev_hash[:12], entry.prev_hash[:12],
                    )
                    return False

                # Recompute hash
                raw = json.dumps(
                    {
                        "txn_id":    entry.txn_id,
                        "timestamp": entry.timestamp,
                        "data":      entry.data,
                        "prev_hash": entry.prev_hash,
                    },
                    sort_keys=True,
                ).encode()
                expected_hash = hashlib.sha256(raw).hexdigest()

                if entry.entry_hash != expected_hash:
                    log.error(
                        "Ledger integrity FAIL at index %d txn_id=%s: hash mismatch",
                        i, entry.txn_id,
                    )
                    return False

                prev_hash = entry.entry_hash

            log.info("Ledger integrity OK — %d entries verified", len(self._entries))
            return True
