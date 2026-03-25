"""
anomaly/detector.py — Isolation Forest–based anomaly detection.

Design
------
• Features: [quantity, price] for each transaction.
• The model is retrained incrementally every time a new sample arrives
  once the minimum sample threshold is met (avoids cold-start false positives).
• IsolationForest is unsupervised — no labelled data required.
• contamination sets the expected proportion of anomalies in training data.

For production: consider replacing the retraining strategy with an online
update scheme (e.g. half-space trees) to reduce CPU cost.
"""

import logging
import numpy as np
from sklearn.ensemble import IsolationForest

from config import ANOMALY_CONTAMINATION, ANOMALY_MIN_SAMPLES

log = logging.getLogger("anomaly")


class AnomalyDetector:
    """
    Rolling Isolation Forest detector over (quantity, price) feature pairs.

    Parameters
    ----------
    contamination : float
        Expected fraction of anomalies; controls the decision threshold.
    min_samples : int
        Minimum number of observations before the model begins predicting.
    """

    def __init__(
        self,
        contamination: float = ANOMALY_CONTAMINATION,
        min_samples:   int   = ANOMALY_MIN_SAMPLES,
    ) -> None:
        self._contamination = contamination
        self._min_samples   = min_samples
        self._history: list[list[float]] = []   # [[qty, price], ...]
        self._model: IsolationForest | None = None

    # ── Public interface ──────────────────────────────────────────────────────

    def record_and_predict(self, quantity: float, price: float) -> bool:
        """
        Record a new observation and return whether it is anomalous.

        Parameters
        ----------
        quantity : float   Trade quantity
        price    : float   Trade price

        Returns
        -------
        bool
            ``True`` if the observation is classified as an anomaly.
            Always returns ``False`` until :attr:`min_samples` are accumulated.
        """
        self._history.append([quantity, price])

        if len(self._history) < self._min_samples:
            log.debug(
                "Detector warming up (%d/%d samples)",
                len(self._history), self._min_samples,
            )
            return False

        # Retrain on full history (cheap for small windows; swap for incremental if needed)
        self._fit()
        return self._predict(quantity, price)

    def reset(self) -> None:
        """Clear history and model (useful for testing)."""
        self._history.clear()
        self._model = None

    @property
    def sample_count(self) -> int:
        return len(self._history)

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _fit(self) -> None:
        """Fit the Isolation Forest on the accumulated history."""
        X = np.array(self._history, dtype=float)
        self._model = IsolationForest(
            contamination=self._contamination,
            random_state=42,
            n_estimators=100,
        )
        self._model.fit(X)

    def _predict(self, quantity: float, price: float) -> bool:
        """
        Predict whether the given sample is an anomaly.

        IsolationForest returns -1 for anomalies and +1 for inliers.
        """
        if self._model is None:
            return False
        sample = np.array([[quantity, price]])
        prediction = self._model.predict(sample)
        is_anomaly = prediction[0] == -1
        if is_anomaly:
            score = self._model.score_samples(sample)[0]
            log.debug("Anomaly score=%.4f for qty=%.4f price=%.4f", score, quantity, price)
        return bool(is_anomaly)
