import numpy as np
from sklearn.decomposition import PCA

from .base import AnomalyDetector


class PCAReconstructionDetector(AnomalyDetector):
    """PCA reconstruction error detector; higher MSE means more anomalous."""

    def __init__(self, n_components: int | float = 0.95, random_state: int = 17) -> None:
        self.model = PCA(n_components=n_components, svd_solver="full", random_state=random_state)

    def fit(self, X: np.ndarray) -> "PCAReconstructionDetector":
        self.model.fit(X)
        return self

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        reconstructed = self.model.inverse_transform(self.model.transform(X))
        return np.mean(np.square(X - reconstructed), axis=1)
