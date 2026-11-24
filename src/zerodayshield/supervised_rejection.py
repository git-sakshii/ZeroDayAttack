"""LOFO reference: supervised known-family classifier with unknown rejection."""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.preprocessing import StandardScaler


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def anomaly_score(classifier, X: np.ndarray) -> np.ndarray:
    """Combine known-attack probability with low-confidence unknown rejection.

    A flow is unusual if the classifier assigns mass to a known attack class or
    if it cannot confidently match any learned class. The final cutoff is still
    calibrated only on benign calibration rows.
    """
    probabilities = classifier.predict_proba(X)
    benign_index = list(classifier.classes_).index("benign")
    known_attack_score = 1.0 - probabilities[:, benign_index]
    unknown_rejection_score = 1.0 - probabilities.max(axis=1)
    return np.maximum(known_attack_score, unknown_rejection_score)


def threshold_for_budget(scores: np.ndarray, budget: float) -> tuple[float, bool, float]:
    allowed = int(np.floor(len(scores) * budget))
    threshold = float(np.sort(scores)[-allowed - 1])
    inclusive = int((scores == threshold).sum()) + int((scores > threshold).sum()) <= allowed
    observed = float((scores >= threshold).mean() if inclusive else (scores > threshold).mean())
    return threshold, inclusive, observed


def run(args: argparse.Namespace) -> dict:
    input_path = Path(args.input)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    frame = pd.read_parquet(input_path) if input_path.suffix.casefold() == ".parquet" else pd.read_csv(input_path, low_memory=False)
    families = frame[args.family_column].fillna("unknown").astype(str).str.strip().str.casefold()
    if args.label_column in frame:
        labels = frame[args.label_column].fillna("unknown").astype(str).str.strip().str.casefold()
        if not np.array_equal(labels.eq(args.benign_label.casefold()).to_numpy(), families.eq("benign").to_numpy()):
            raise ValueError("The configured benign label and family column disagree")
    else:
        raise ValueError(f"Missing label column {args.label_column!r}")

    excluded = {args.label_column, args.family_column, "label_raw", "Flow ID", "Source IP", "Destination IP", "Timestamp", "SimillarHTTP"}
    feature_columns = [c for c in frame.columns if c not in excluded]
    numeric = frame.loc[:, feature_columns].apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan)
    numeric = numeric.dropna(axis=1, how="all")
    family_values = families.to_numpy()
    all_families = sorted(set(family_values) - {"benign"})
    if not all_families:
        raise ValueError("No attack families were found")
    benign_indexes = np.flatnonzero(family_values == "benign")
    records = []
    seeds = args.seeds
    budgets = [0.001, 0.01]
    fold_records = []

    for seed in seeds:
        rng = np.random.default_rng(seed)
        shuffled = rng.permutation(benign_indexes)
        n_cal = int(round(len(shuffled) * 0.20))
        n_test = int(round(len(shuffled) * 0.20))
        cal_idx = shuffled[:n_cal]
        benign_test_idx = shuffled[n_cal:n_cal + n_test]
        benign_train_idx = shuffled[n_cal + n_test:]

        for held_family in all_families:
            train_indexes = [
                rng.choice(benign_train_idx, size=min(args.max_per_class, len(benign_train_idx)), replace=False)
            ]
            training_labels = [np.repeat("benign", len(train_indexes[0]))]
            family_sizes = {"benign": len(train_indexes[0])}
            for known_family in all_families:
                if known_family == held_family:
                    continue
                family_idx = np.flatnonzero(family_values == known_family)
                chosen = rng.choice(family_idx, size=min(args.max_per_class, len(family_idx)), replace=False)
                train_indexes.append(chosen)
                training_labels.append(np.repeat(known_family, len(chosen)))
                family_sizes[known_family] = len(chosen)
            model_idx = np.concatenate(train_indexes)
            y_train = np.concatenate(training_labels)

            imputer = SimpleImputer(strategy="median")
            scaler = StandardScaler()
            X_train = scaler.fit_transform(imputer.fit_transform(numeric.iloc[model_idx])).astype(np.float32, copy=False)
            X_cal = scaler.transform(imputer.transform(numeric.iloc[cal_idx])).astype(np.float32, copy=False)

            classifier = HistGradientBoostingClassifier(
                learning_rate=0.1,
                max_iter=args.max_iter,
                max_leaf_nodes=31,
                l2_regularization=1.0,
                class_weight="balanced",
                random_state=seed,
            )
            fit_started = time.perf_counter()
            classifier.fit(X_train, y_train)
            fit_seconds = time.perf_counter() - fit_started
            calibration_scores = anomaly_score(classifier, X_cal)

            attack_idx = np.flatnonzero(family_values == held_family)
            test_idx = np.concatenate([benign_test_idx, attack_idx])
            y_test = np.concatenate([np.zeros(len(benign_test_idx), dtype=int), np.ones(len(attack_idx), dtype=int)])
            score_parts = []
            score_started = time.perf_counter()
            for start in range(0, len(test_idx), 25_000):
                indices = test_idx[start:start + 25_000]
                X = scaler.transform(imputer.transform(numeric.iloc[indices])).astype(np.float32, copy=False)
                score_parts.append(anomaly_score(classifier, X))
            test_scores = np.concatenate(score_parts)
            score_seconds = time.perf_counter() - score_started

            for budget in budgets:
                threshold, inclusive, cal_fpr = threshold_for_budget(calibration_scores, budget)
                predicted = test_scores >= threshold if inclusive else test_scores > threshold
                benign = y_test == 0
                attack = y_test == 1
                records.append({
                    "dataset": "CICIDS2017_Kaggle_derivative",
                    "seed": seed,
                    "held_out_family": held_family,
                    "model": "HistGradientBoosting_known_attack_with_rejection",
                    "target_fpr": budget,
                    "threshold": threshold,
                    "threshold_inclusive": inclusive,
                    "calibration_fpr_observed": cal_fpr,
                    "test_fpr": float(predicted[benign].mean()),
                    "recall": float(predicted[attack].mean()),
                    "auroc": float(roc_auc_score(y_test, test_scores)),
                    "aupr": float(average_precision_score(y_test, test_scores)),
                    "benign_train_rows": len(benign_train_idx),
                    "benign_calibration_rows": len(cal_idx),
                    "benign_test_rows": int(benign.sum()),
                    "attack_test_rows": int(attack.sum()),
                    "supervised_train_rows": int(len(model_idx)),
                    "fit_seconds": fit_seconds,
                    "score_latency_ms_per_row": 1000 * score_seconds / max(1, len(test_scores)),
                })
            fold_records.append({"seed": seed, "held_out_family": held_family,
                                 "supervised_class_rows": family_sizes, "fit_seconds": fit_seconds,
                                 "test_attack_rows": len(attack_idx)})

    results = pd.DataFrame(records)
    results.to_csv(output_dir / "lofo_metrics.csv", index=False)
    results.to_parquet(output_dir / "lofo_metrics.parquet", index=False)
    summary = (results.groupby(["model", "target_fpr"], as_index=False)
               .agg(macro_family_recall=("recall", "mean"), worst_family_recall=("recall", "min"),
                    mean_observed_benign_fpr=("test_fpr", "mean"), mean_auroc=("auroc", "mean"),
                    mean_aupr=("aupr", "mean"), mean_fit_seconds=("fit_seconds", "mean"),
                    family_count=("held_out_family", "nunique"), seed_count=("seed", "nunique")))
    summary.to_csv(output_dir / "summary.csv", index=False)
    protocol = {
        "protocol_version": "supervised-known-rejection-1.0",
        "dataset": "CICIDS2017 Kaggle cleaned/preprocessed derivative",
        "strategy": "For each fold, fit a multiclass HistGradientBoosting classifier on benign training rows and sampled known-family attack rows; exclude the held-out attack family from every fitting and calibration step.",
        "unknown_score": "max(1 - P(benign), 1 - max_class_probability); high known-attack probability catches known classes and low maximum confidence contributes an unknown-rejection score.",
        "threshold_selection": "benign-only calibration rows; test labels never set thresholds",
        "seeds": seeds,
        "target_fpr_budgets": budgets,
        "max_rows_per_training_class": args.max_per_class,
        "classifier": {"max_iter": args.max_iter, "max_leaf_nodes": 31, "learning_rate": 0.1, "l2_regularization": 1.0, "class_weight": "balanced"},
        "limitations": [
            "This supervised baseline is a reference strategy and is not part of the benign-only detector family.",
            "Known attack categories are supervised training labels; the held-out family is excluded from fitting and cutoff calibration.",
            "Anomaly threshold remains calibrated on benign data only; classifier probabilities are not asserted to be calibrated attack probabilities.",
            "Results apply only to the broad families and features in the Kaggle-prepared derivative.",
        ],
    }
    (output_dir / "protocol.json").write_text(json.dumps(protocol, indent=2), encoding="utf-8")
    metadata = {"input": str(input_path.resolve()), "input_sha256": sha256_file(input_path),
                "models": ["HistGradientBoosting_known_attack_with_rejection"],
                "seeds": seeds, "budgets": budgets, "folds": fold_records, "protocol": protocol,
                "rows": len(records)}
    (output_dir / "run.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return metadata


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a supervised known-attack plus unknown-rejection LOFO reference")
    parser.add_argument("--input", default="data/processed/cicids2017_cleaned.parquet")
    parser.add_argument("--label-column", default="Label")
    parser.add_argument("--family-column", default="attack_family")
    parser.add_argument("--benign-label", default="benign")
    parser.add_argument("--output-dir", default="results/supervised_rejection")
    parser.add_argument("--max-per-class", type=int, default=10_000)
    parser.add_argument("--max-iter", type=int, default=100)
    parser.add_argument("--seeds", type=int, nargs="+", default=[17, 29, 43])
    args = parser.parse_args()
    if args.max_per_class < 100 or args.max_iter < 1:
        parser.error("--max-per-class must be at least 100 and --max-iter must be positive")
    if not args.seeds or len(set(args.seeds)) != len(args.seeds):
        parser.error("--seeds must contain distinct integer seeds")
    metadata = run(args)
    print(json.dumps({"rows": metadata["rows"], "folds": len(metadata["folds"])}, indent=2))


if __name__ == "__main__":
    main()
