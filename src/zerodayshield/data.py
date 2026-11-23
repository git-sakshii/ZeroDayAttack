from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler


@dataclass
class PreparedData:
    X_train: np.ndarray
    X_calibration: np.ndarray
    X_test: np.ndarray
    y_test: np.ndarray
    families_test: np.ndarray
    feature_names: list[str]
    train_indexes: np.ndarray
    calibration_indexes: np.ndarray
    test_indexes: np.ndarray


def load_and_split(
    frame: pd.DataFrame,
    label_column: str,
    family_column: str | None = None,
    benign_label: str = "BENIGN",
    test_family: str | None = None,
    calibration_fraction: float = 0.2,
    random_state: int = 17,
) -> PreparedData:
    """Create a deterministic benign-only train/calibration split and family test.

    This starter makes the designated family the test family. Other attack rows
    are excluded from fitting and calibration. Preprocessing is fit on the
    benign training partition only.
    """
    if label_column not in frame.columns:
        raise ValueError(f"Missing label column: {label_column}")
    if family_column and family_column not in frame.columns:
        raise ValueError(f"Missing family column: {family_column}")

    labels = frame[label_column].astype(str).str.strip()
    benign_mask = labels.str.casefold() == benign_label.casefold()
    if family_column:
        families = frame[family_column].fillna("unknown").astype(str).str.strip()
    else:
        families = labels.where(~benign_mask, "BENIGN")
    families = families.where(~benign_mask, "BENIGN")

    attack_families = sorted(families[~benign_mask].unique().tolist())
    if not attack_families:
        raise ValueError("Input must contain benign rows and at least one attack family")
    if test_family is None:
        test_family = attack_families[-1]
    if test_family not in attack_families:
        raise ValueError(f"Unknown test family {test_family!r}; available: {attack_families}")

    # Remove label/family and non-numeric columns; prevent target leakage.
    excluded = {label_column}
    if family_column:
        excluded.add(family_column)
    # CIC-style files may contain identifiers as strings (or parse as numeric);
    # exclude common flow identity columns regardless of dtype.
    excluded.update({"Flow ID", "Source IP", "Destination IP", "Timestamp", "SimillarHTTP"})
    feature_columns = [column for column in frame.columns if column not in excluded]
    candidate = frame.loc[:, feature_columns].copy()
    numeric = candidate.apply(pd.to_numeric, errors="coerce")
    numeric = numeric.replace([np.inf, -np.inf], np.nan)
    numeric = numeric.dropna(axis=1, how="all")
    if numeric.shape[1] == 0:
        raise ValueError("No usable numeric feature columns found after removing labels and identifiers")

    benign_indexes = frame.index[benign_mask].to_numpy()
    if len(benign_indexes) < 3:
        raise ValueError("At least three benign rows are required for train/calibration splitting")
    rng = np.random.default_rng(random_state)
    shuffled = rng.permutation(benign_indexes)
    if not 0 < calibration_fraction < 0.5:
        raise ValueError("calibration_fraction must be between 0 and 0.5")
    n_calibration = max(1, int(round(len(shuffled) * calibration_fraction)))
    n_calibration = min(n_calibration, len(shuffled) - 2)
    calibration_indexes = shuffled[:n_calibration]

    # Reserve a disjoint benign test partition so FPR can be measured alongside
    # recall. Only the designated held-out family appears as an attack in test.
    remaining_benign = shuffled[n_calibration:]
    n_test_benign = max(1, int(round(len(shuffled) * calibration_fraction)))
    n_test_benign = min(n_test_benign, max(1, len(remaining_benign) // 3))
    test_benign_indexes = remaining_benign[:n_test_benign]
    train_indexes = remaining_benign[n_test_benign:]
    if len(train_indexes) == 0:
        raise ValueError("Not enough benign rows for disjoint train, calibration, and test partitions")

    test_attack_mask = (~benign_mask) & (families == test_family)
    test_attack_indexes = frame.index[test_attack_mask].to_numpy()
    test_indexes = np.concatenate([test_benign_indexes, test_attack_indexes])
    test_labels = np.concatenate([
        np.zeros(len(test_benign_indexes), dtype=int),
        np.ones(len(test_attack_indexes), dtype=int),
    ])
    if len(test_attack_indexes) == 0:
        raise ValueError(f"No test rows found for family {test_family!r}")

    imputer = SimpleImputer(strategy="median")
    scaler = StandardScaler()
    X_train = scaler.fit_transform(imputer.fit_transform(numeric.loc[train_indexes]))
    X_calibration = scaler.transform(imputer.transform(numeric.loc[calibration_indexes]))
    X_test = scaler.transform(imputer.transform(numeric.loc[test_indexes]))

    return PreparedData(
        X_train=X_train,
        X_calibration=X_calibration,
        X_test=X_test,
        y_test=test_labels,
        families_test=families.loc[test_indexes].to_numpy(),
        feature_names=numeric.columns.tolist(),
        train_indexes=train_indexes,
        calibration_indexes=calibration_indexes,
        test_indexes=test_indexes,
    )
