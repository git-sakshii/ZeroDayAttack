"""Reverse transfer: fit on UNSW benign training rows, evaluate on CIC and UNSW test.

UNSW attack labels are used only to select normal rows for fitting/calibration
and to score the withheld evaluation. CIC labels are evaluation-only.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler

from .cross_dataset import (
    CIC_FEATURES,
    FEATURE_NAMES,
    UNSW_FEATURES,
    map_cic_features,
    map_unsw_features,
    normalize_family,
    row_metrics,
    sha256_file,
    threshold_for_budget,
)
from .detectors import IsolationForestDetector, PCAReconstructionDetector
from .experiment import percentile_scores


def family_ranking_metrics(scores, family_names, benign_mask, family_values):
    """Compute threshold-independent AUROC/AUPR once per family and model."""
    result = {}
    for family in family_names:
        attack = family_values == family
        mask = benign_mask | attack
        labels = attack[mask].astype(int)
        metrics = row_metrics(scores[mask], labels, float("inf"), True)
        result[family] = (metrics["auroc"], metrics["aupr"])
    return result


def family_threshold_metrics(domain, family_names, benign_mask, family_values, scores,
                             threshold, inclusive, base, ranking):
    rows = []
    for family in family_names:
        attack = family_values == family
        mask = benign_mask | attack
        labels = attack[mask].astype(int)
        predicted = scores[mask] >= threshold if inclusive else scores[mask] > threshold
        benign = labels == 0
        attack_rows = labels == 1
        rows.append({
            **base,
            "domain": domain,
            "attack_family": family,
            "recall": float(predicted[attack_rows].mean()) if attack_rows.any() else float("nan"),
            "benign_fpr": float(predicted[benign].mean()) if benign.any() else float("nan"),
            "alert_rate": float(predicted.mean()),
            "attack_rows": int(attack_rows.sum()),
            "benign_rows": int(benign.sum()),
            "auroc": ranking[family][0],
            "aupr": ranking[family][1],
        })
    return rows


def run(args: argparse.Namespace) -> dict:
    cic_path = Path(args.cic_input)
    unsw_train_path = Path(args.unsw_train)
    unsw_test_path = Path(args.unsw_test)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    expected = {
        "unsw_train": "bec7dd5ec88dc2a0ccc7a07879d338395ed7421750f675fd0339e07dfe0648fa",
        "unsw_test": "734fe6642edf758f7c94d7d9149426b49d202fe8e7bf0bef47392489c3c0a559",
    }
    train_hash, test_hash = sha256_file(unsw_train_path), sha256_file(unsw_test_path)
    if train_hash != expected["unsw_train"] or test_hash != expected["unsw_test"]:
        raise ValueError("UNSW inputs do not match the pinned mirror files recorded in DATASETS.md")

    unsw_train = pd.read_csv(unsw_train_path, low_memory=False)
    unsw_test = pd.read_csv(unsw_test_path, low_memory=False)
    if len(unsw_train) != 175_341 or len(unsw_test) != 82_332:
        raise ValueError("UNSW row counts differ from the documented fixed partition profile")
    if int((unsw_train["label"] == 0).sum()) != 56_000 or int((unsw_test["label"] == 0).sum()) != 37_000:
        raise ValueError("UNSW normal counts differ from the expected fixed partition profile")

    cic_raw = pd.read_parquet(cic_path, columns=CIC_FEATURES + ["attack_family"])
    cic_families = normalize_family(cic_raw["attack_family"]).to_numpy()
    cic_attacks = sorted(set(cic_families) - {"benign"})
    cic_X = map_cic_features(cic_raw)

    unsw_train_X = map_unsw_features(unsw_train)
    unsw_test_X = map_unsw_features(unsw_test)
    unsw_test_families = normalize_family(unsw_test["attack_cat"]).to_numpy()
    unsw_test_labels = pd.to_numeric(unsw_test["label"], errors="raise").to_numpy(dtype=int)
    if not np.array_equal(unsw_test_labels == 0, unsw_test_families == "normal"):
        raise ValueError("UNSW binary and family labels disagree on normal rows")
    unsw_attacks = sorted(set(unsw_test_families) - {"normal"})
    unsw_train_labels = pd.to_numeric(unsw_train["label"], errors="raise").to_numpy(dtype=int)
    unsw_train_benign = np.flatnonzero(unsw_train_labels == 0)
    if len(unsw_train_benign) < 3:
        raise ValueError("UNSW training partition has too few benign rows")

    rows: list[dict] = []
    run_records = []
    seeds = [17, 29, 43]
    budgets = [0.001, 0.01]

    for seed in seeds:
        rng = np.random.default_rng(seed)
        shuffled = rng.permutation(unsw_train_benign)
        n_train = int(0.60 * len(shuffled))
        n_cal = int(0.20 * len(shuffled))
        train_idx = shuffled[:n_train]
        cal_idx = shuffled[n_train:n_train + n_cal]

        imputer = SimpleImputer(strategy="median")
        scaler = StandardScaler()
        X_train = scaler.fit_transform(imputer.fit_transform(unsw_train_X.iloc[train_idx]))
        X_cal = scaler.transform(imputer.transform(unsw_train_X.iloc[cal_idx]))
        X_unsw_test = scaler.transform(imputer.transform(unsw_test_X))

        models = {
            "IsolationForest": IsolationForestDetector(n_estimators=150, random_state=seed),
            "PCAReconstruction": PCAReconstructionDetector(n_components=0.95, random_state=seed),
        }
        fit_seconds = {}
        cal_scores = {}
        unsw_scores = {}
        for name, model in models.items():
            started = time.perf_counter()
            model.fit(X_train)
            fit_seconds[name] = time.perf_counter() - started
            cal_scores[name] = model.score_samples(X_cal)
            unsw_scores[name] = model.score_samples(X_unsw_test)

        cic_scores_by_model = {name: np.empty(len(cic_X), dtype=np.float64) for name in models}
        for start in range(0, len(cic_X), 100_000):
            stop = min(len(cic_X), start + 100_000)
            X_chunk = scaler.transform(imputer.transform(cic_X.iloc[start:stop]))
            for name, model in models.items():
                cic_scores_by_model[name][start:stop] = model.score_samples(X_chunk)

        score_sets = {
            "IsolationForest": (cal_scores["IsolationForest"], unsw_scores["IsolationForest"], cic_scores_by_model["IsolationForest"]),
            "PCAReconstruction": (cal_scores["PCAReconstruction"], unsw_scores["PCAReconstruction"], cic_scores_by_model["PCAReconstruction"]),
            "RankFusion(IF+PCA)": (
                (percentile_scores(cal_scores["IsolationForest"], cal_scores["IsolationForest"])
                 + percentile_scores(cal_scores["PCAReconstruction"], cal_scores["PCAReconstruction"])) / 2,
                (percentile_scores(cal_scores["IsolationForest"], unsw_scores["IsolationForest"])
                 + percentile_scores(cal_scores["PCAReconstruction"], unsw_scores["PCAReconstruction"])) / 2,
                (percentile_scores(cal_scores["IsolationForest"], cic_scores_by_model["IsolationForest"])
                 + percentile_scores(cal_scores["PCAReconstruction"], cic_scores_by_model["PCAReconstruction"])) / 2,
            ),
        }

        for model_name, (cal, unsw_score, cic_score) in score_sets.items():
            ranking_unsw = family_ranking_metrics(
                unsw_score, unsw_attacks, unsw_test_labels == 0, unsw_test_families)
            ranking_cic = family_ranking_metrics(
                cic_score, cic_attacks, cic_families == "benign", cic_families)
            for budget in budgets:
                threshold, inclusive, calibration_fpr = threshold_for_budget(cal, budget)
                base = {"model": model_name, "seed": seed, "target_fpr": budget,
                        "threshold": threshold, "threshold_inclusive": inclusive,
                        "calibration_fpr_observed": calibration_fpr,
                        "fit_seconds": sum(fit_seconds.values()) if model_name == "RankFusion(IF+PCA)" else fit_seconds[model_name]}
                rows.extend(family_threshold_metrics(
                    "UNSW_NB15_same_dataset", unsw_attacks, unsw_test_labels == 0,
                    unsw_test_families, unsw_score, threshold, inclusive, base, ranking_unsw,
                ))
                # Every CIC row is evaluation-only for this reverse direction.
                rows.extend(family_threshold_metrics(
                    "CICIDS2017_cross_dataset", cic_attacks, cic_families == "benign",
                    cic_families, cic_score, threshold, inclusive, base, ranking_cic,
                ))

        run_records.append({
            "seed": seed,
            "unsw_benign_train_rows": len(train_idx),
            "unsw_benign_calibration_rows": len(cal_idx),
            "unsw_test_rows": len(unsw_test),
            "cic_evaluation_rows": len(cic_raw),
            "fit_seconds": fit_seconds,
        })

    per_family = pd.DataFrame(rows)
    per_family.to_csv(output_dir / "cross_dataset_reverse_family_metrics.csv", index=False)
    mean_metrics = (
        per_family.groupby(["domain", "model", "target_fpr", "attack_family"], as_index=False)
        .agg(recall=("recall", "mean"), benign_fpr=("benign_fpr", "mean"),
             alert_rate=("alert_rate", "mean"), auroc=("auroc", "mean"), aupr=("aupr", "mean"),
             attack_rows=("attack_rows", "first"), benign_rows=("benign_rows", "first"))
    )
    summaries = []
    for (domain, model, budget), group in mean_metrics.groupby(["domain", "model", "target_fpr"]):
        families = group[group["attack_family"] != "normal"]
        summaries.append({
            "domain": domain, "model": model, "target_fpr": budget,
            "macro_family_recall": float(families["recall"].mean()),
            "worst_family_recall": float(families["recall"].min()),
            "mean_family_auroc": float(families["auroc"].mean()),
            "mean_family_aupr": float(families["aupr"].mean()),
            "mean_observed_benign_fpr": float(group["benign_fpr"].mean()),
            "family_count": int(len(families)), "seed_count": len(seeds),
        })
    summary = pd.DataFrame(summaries)
    summary.to_csv(output_dir / "cross_dataset_reverse_summary.csv", index=False)
    mean_metrics.to_csv(output_dir / "cross_dataset_reverse_family_means.csv", index=False)

    protocol = {
        "protocol_version": "cross-dataset-reverse-1.0",
        "source_dataset": "UNSW-NB15 documented training partition mirror",
        "target_dataset": "CICIDS2017 Kaggle-prepared derivative and UNSW-NB15 fixed test partition mirror",
        "transfer_direction": "UNSW benign-only fit and benign calibration -> CIC evaluation",
        "models": ["IsolationForest", "PCAReconstruction", "RankFusion(IF+PCA)"],
        "seeds": seeds,
        "target_fpr_budgets": budgets,
        "features": FEATURE_NAMES,
        "source_columns": UNSW_FEATURES,
        "target_columns": CIC_FEATURES,
        "threshold_selection": "UNSW training-partition benign calibration rows only; CIC labels are evaluation-only",
        "preprocessing_fit": "UNSW training-partition benign training rows only",
        "limitations": [
            "This is one reverse transfer direction between public benchmark testbeds, not independent real-network validation.",
            "Nine feature measurements are semantic approximations across Argus/Bro and CICFlowMeter.",
            "UNSW mirror SHA-256 hashes pin local copies; the provider does not publish corresponding checksums.",
            "The UNSW held-out test and CIC derivative are both benchmark datasets; macro family recall is descriptive because taxonomies differ.",
        ],
    }
    (output_dir / "cross_dataset_reverse_protocol.json").write_text(json.dumps(protocol, indent=2), encoding="utf-8")
    metadata = {
        "inputs": {
            "cicids2017_parquet": str(cic_path.resolve()),
            "cicids2017_sha256": sha256_file(cic_path),
            "unsw_training_csv": str(unsw_train_path.resolve()), "unsw_training_sha256": train_hash,
            "unsw_test_csv": str(unsw_test_path.resolve()), "unsw_test_sha256": test_hash,
        },
        "cic_rows": len(cic_raw), "cic_benign_rows": int((cic_families == "benign").sum()),
        "unsw_train_rows": len(unsw_train), "unsw_train_benign_rows": len(unsw_train_benign),
        "unsw_test_rows": len(unsw_test), "unsw_test_benign_rows": int((unsw_test_labels == 0).sum()),
        "runs": run_records, "protocol": protocol,
        "note": "Reverse-direction benchmark transfer only; no result establishes independent real-network performance.",
    }
    (output_dir / "cross_dataset_reverse_run.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return metadata


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate reverse UNSW-NB15-to-CICIDS2017 transfer")
    parser.add_argument("--cic-input", default="data/processed/cicids2017_cleaned.parquet")
    parser.add_argument("--unsw-train", default="data/raw/unsw-nb15/UNSW_NB15_training-set.csv")
    parser.add_argument("--unsw-test", default="data/raw/unsw-nb15/UNSW_NB15_testing-set.csv")
    parser.add_argument("--output-dir", default="results/cross_dataset_reverse")
    metadata = run(parser.parse_args())
    print(json.dumps({"cic_rows": metadata["cic_rows"], "unsw_test_rows": metadata["unsw_test_rows"]}, indent=2))


if __name__ == "__main__":
    main()
