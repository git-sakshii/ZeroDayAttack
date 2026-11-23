"""Small CPU-friendly PyTorch reconstruction detector."""

import numpy as np

from .base import AnomalyDetector


class AutoencoderDetector(AnomalyDetector):
    """Dense autoencoder trained only on benign rows; anomaly score is MSE."""

    def __init__(
        self,
        hidden_dim: int = 32,
        bottleneck_dim: int = 8,
        epochs: int = 30,
        batch_size: int = 512,
        learning_rate: float = 1e-3,
        random_state: int = 17,
    ) -> None:
        self.hidden_dim = hidden_dim
        self.bottleneck_dim = bottleneck_dim
        self.epochs = epochs
        self.batch_size = batch_size
        self.learning_rate = learning_rate
        self.random_state = random_state
        self.model = None

    def _torch(self):
        try:
            import torch
            from torch import nn
        except ImportError as exc:
            raise ImportError(
                "Autoencoder requires the optional CPU PyTorch dependency. Install with: "
                "python -m pip install -r requirements-ml.txt"
            ) from exc
        return torch, nn

    def fit(self, X: np.ndarray) -> "AutoencoderDetector":
        torch, nn = self._torch()
        if X.ndim != 2 or len(X) == 0:
            raise ValueError("Autoencoder expects a non-empty 2D training matrix")
        torch.manual_seed(self.random_state)
        torch.set_num_threads(max(1, min(4, torch.get_num_threads())))
        input_dim = X.shape[1]
        hidden_dim = max(2, min(self.hidden_dim, input_dim * 2))
        bottleneck_dim = max(1, min(self.bottleneck_dim, hidden_dim - 1))
        self.model = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, bottleneck_dim),
            nn.ReLU(),
            nn.Linear(bottleneck_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, input_dim),
        )
        optimizer = torch.optim.Adam(self.model.parameters(), lr=self.learning_rate)
        loss_fn = nn.MSELoss()
        values = torch.as_tensor(np.asarray(X, dtype=np.float32))
        generator = torch.Generator().manual_seed(self.random_state)
        self.model.train()
        for _ in range(self.epochs):
            # Tensor indexing avoids DataLoader worker/dispatch overhead on Windows CPU.
            order = torch.randperm(len(values), generator=generator)
            for indices in order.split(self.batch_size):
                batch = values[indices]
                optimizer.zero_grad(set_to_none=True)
                loss = loss_fn(self.model(batch), batch)
                loss.backward()
                optimizer.step()
        self.model.eval()
        return self

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        if self.model is None:
            raise RuntimeError("Call fit before score_samples")
        torch, _ = self._torch()
        values = torch.as_tensor(np.asarray(X, dtype=np.float32))
        batches = []
        self.model.eval()
        with torch.no_grad():
            for start in range(0, len(values), self.batch_size):
                batch = values[start : start + self.batch_size]
                errors = torch.mean(torch.square(self.model(batch) - batch), dim=1)
                batches.append(errors.cpu().numpy())
        return np.concatenate(batches) if batches else np.empty(0, dtype=float)
