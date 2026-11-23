from abc import ABC, abstractmethod

import numpy as np


class AnomalyDetector(ABC):
    """Common interface: higher scores must indicate more anomalous traffic."""

    @abstractmethod
    def fit(self, X: np.ndarray) -> "AnomalyDetector":
        """Fit using normal training examples only."""

    @abstractmethod
    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """Return one anomaly score per row; larger means more anomalous."""
