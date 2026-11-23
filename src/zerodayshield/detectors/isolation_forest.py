import numpy as np
from sklearn.ensemble import IsolationForest

from .base import AnomalyDetector


class IsolationForestDetector(AnomalyDetector):
    """Isolation Forest wrapper with a consistent high-is-anomalous score."""

    def __init__(
        self,
        n_estimators: int = 300,
        max_samples: str | int | float = "auto",
        random_state: int = 17,
    ) -> None:
        self.model = IsolationForest(
            n_estimators=n_estimators,
            max_samples=max_samples,
            contamination="auto",
            random_state=random_state,
            n_jobs=-1,
        )

    def fit(self, X: np.ndarray) -> "IsolationForestDetector":
        self.model.fit(X)
        return self

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        # sklearn's score_samples is lower for more anomalous observations.
        return -self.model.score_samples(X)
