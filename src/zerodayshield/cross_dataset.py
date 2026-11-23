"""Cross-dataset transfer from CICIDS2017 to the official UNSW-NB15 test split.

Only a small, explicitly documented set of semantically corresponding flow
features is used. Preprocessing and alert thresholds are learned from CIC benign
training/calibration rows; no UNSW labels participate in fitting or calibration.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.impute import SimpleImputer
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.preprocessing import StandardScaler

from . import __version__
from .detectors import IsolationForestDetector, PCAReconstructionDetector
from .experiment import percentile_scores


CIC_FEATURES = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Length of Fwd Packets",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "Flow Bytes/s",
    "Bwd Packets/s",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
]
UNSW_FEATURES = [
    "dur",
    "spkts",
    "sbytes",
    "smean",
    "dmean",
    "(sbytes + dbytes) / dur",
    "dpkts",
    "swin",
    "dwin",
]
FEATURE_NAMES = [
    "duration_seconds",
    "source_packet_count",
    "source_bytes",
    "source_mean_packet_bytes",
    "destination_mean_packet_bytes",
    "total_flow_bytes_per_second",
    "destination_packet_count",
    "source_initial_tcp_window",
    "destination_initial_tcp_window",
]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def normalize_family(values: pd.Series) -> pd.Series:
    return values.fillna("unknown").astype(str).str.strip().str.casefold()


def map_cic_features(frame: pd.DataFrame) -> pd.DataFrame:
    duration_s = pd.to_numeric(frame["Flow Duration"], errors="coerce") / 1_000_000.0
    flow_bytes_s = pd.to_numeric(frame["Flow Bytes/s"], errors="coerce")
    out = pd.DataFrame(index=frame.index)
    out[FEATURE_NAMES[0]] = duration_s
    out[FEATURE_NAMES[1]] = pd.to_numeric(frame["Total Fwd Packets"], errors="coerce")
    out[FEATURE_NAMES[2]] = pd.to_numeric(frame["Total Length of Fwd Packets"], errors="coerce")
    out[FEATURE_NAMES[3]] = pd.to_numeric(frame["Fwd Packet Length Mean"], errors="coerce")
    out[FEATURE_NAMES[4]] = pd.to_numeric(frame["Bwd Packet Length Mean"], errors="coerce")
    out[FEATURE_NAMES[5]] = flow_bytes_s
    # CICFlowMeter reports packet rate in packets/second; multiply by seconds.
    out[FEATURE_NAMES[6]] = pd.to_numeric(frame["Bwd Packets/s"], errors="coerce") * duration_s
    out[FEATURE_NAMES[7]] = pd.to_numeric(frame["Init_Win_bytes_forward"], errors="coerce")
    out[FEATURE_NAMES[8]] = pd.to_numeric(frame["Init_Win_bytes_backward"], errors="coerce")
    return out.replace([np.inf, -np.inf], np.nan)


def map_unsw_features(frame: pd.DataFrame) -> pd.DataFrame:
    out = pd.DataFrame(index=frame.index)
    out[FEATURE_NAMES[0]] = pd.to_numeric(frame["dur"], errors="coerce")
    out[FEATURE_NAMES[1]] = pd.to_numeric(frame["spkts"], errors="coerce")
    out[FEATURE_NAMES[2]] = pd.to_numeric(frame["sbytes"], errors="coerce")
    out[FEATURE_NAMES[3]] = pd.to_numeric(frame["smean"], errors="coerce")
    out[FEATURE_NAMES[4]] = pd.to_numeric(frame["dmean"], errors="coerce")
    duration = pd.to_numeric(frame["dur"], errors="coerce")
    total_bytes = pd.to_numeric(frame["sbytes"], errors="coerce") + pd.to_numeric(frame["dbytes"], errors="coerce")
    out[FEATURE_NAMES[5]] = total_bytes / duration.replace(0, np.nan)
    out[FEATURE_NAMES[6]] = pd.to_numeric(frame["dpkts"], errors="coerce")
    out[FEATURE_NAMES[7]] = pd.to_numeric(frame["swin"], errors="coerce")
    out[FEATURE_NAMES[8]] = pd.to_numeric(frame["dwin"], errors="coerce")
    return out.replace([np.inf, -np.inf], np.nan)


def threshold_for_budget(scores: np.ndarray, budget: float) -> tuple[float, bool, float]:
    if not 0 < budget < 1:
        raise ValueError(f"FPR budget must be in (0, 1), got {budget}")
    allowed = int(np.floor(len(scores) * budget))
    threshold = float(np.sort(scores)[-allowed - 1])
    inclusive = int((scores == threshold).sum()) + int((scores > threshold).sum()) <= allowed
    rate = float((scores >= threshold).mean() if inclusive else (scores > threshold).mean())
    return threshold, inclusive, rate


def row_metrics(scores: np.ndarray, labels: np.ndarray, threshold: float, inclusive: bool) -> dict:
    predicted = scores >= threshold if inclusive else scores > threshold
    benign = labels == 0
    attack = labels == 1
    return {
        "recall": float(predicted[attack].mean()) if attack.any() else float("nan"),
        "benign_fpr": float(predicted[benign].mean()) if benign.any() else float("nan"),
        "alert_rate": float(predicted.mean()),
        "attack_rows": int(attack.sum()),
        "benign_rows": int(benign.sum()),
        "auroc": float(roc_auc_score(labels, scores)) if len(np.unique(labels)) == 2 else float("nan"),
        "aupr": float(average_precision_score(labels, scores)) if attack.any() else float("nan"),
    }


def score_domain(
    domain: str,
    family_names: list[str],
    benign_mask: np.ndarray,
    family_values: np.ndarray,
    scores: np.ndarray,
    threshold: float,
    inclusive: bool,
    base: dict,
) -> list[dict]:
    rows = []
    for family in family_names:
        attack = family_values == family
        mask = benign_mask | attack
        labels = attack[mask].astype(int)
        metrics = row_metrics(scores[mask], labels, threshold, inclusive)
        rows.append({**base, "domain": domain, "attack_family": family, **metrics})
    return rows


def run(args: argparse.Namespace) -> dict:
    cic_path = Path(args.cic_input)
    unsw_train_path = Path(args.unsw_train)
    unsw_test_path = Path(args.unsw_test)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    expected_hashes = {
        "unsw_train": "bec7dd5ec88dc2a0ccc7a07879d338395ed7421750f675fd0339e07dfe0648fa",
        "unsw_test": "734fe6642edf758f7c94d7d9149426b49d202fe8e7bf0bef47392489c3c0a559",
    }
    actual_train_hash = sha256_file(unsw_train_path)
    actual_test_hash = sha256_file(unsw_test_path)
    if actual_train_hash != expected_hashes["unsw_train"] or actual_test_hash != expected_hashes["unsw_test"]:
        raise ValueError("UNSW files do not match the verified official partition checksums")

    cic_columns = CIC_FEATURES + ["attack_family"]
    cic_raw = pd.read_parquet(cic_path, columns=cic_columns)
    cic_families = normalize_family(cic_raw["attack_family"]).to_numpy()
    cic_X_df = map_cic_features(cic_raw)
    cic_benign = cic_families == "benign"
    cic_attacks = sorted(set(cic_families) - {"benign"})
    if not cic_attacks:
        raise ValueError("CIC input has no attack-family labels")

    unsw_train = pd.read_csv(unsw_train_path, low_memory=False)
    unsw_test = pd.read_csv(unsw_test_path, low_memory=False)
    if len(unsw_train) != 175_341 or len(unsw_test) != 82_332:
        raise ValueError("UNSW partition row counts do not match the official UNSW-NB15 release")
    if int((unsw_train["label"] == 0).sum()) != 56_000 or int((unsw_test["label"] == 0).sum()) != 37_000:
        raise ValueError("UNSW normal-row counts do not match the official partition signatures")

    unsw_X_df = map_unsw_features(unsw_test)
    unsw_families = normalize_family(unsw_test["attack_cat"]).to_numpy()
    unsw_labels = pd.to_numeric(unsw_test["label"], errors="raise").to_numpy(dtype=int)
    if not np.array_equal(unsw_labels == 0, unsw_families == "normal"):
        raise ValueError("UNSW binary and family labels disagree on benign rows")
    unsw_attacks = sorted(set(unsw_families) - {"normal"})

    # A conservative common-row policy: impute from CIC training rows, and keep
    # the original row counts while the imputer handles missing derived features.
    all_raw_features = pd.concat([cic_X_df, unsw_X_df], axis=0, ignore_index=True)
    all_raw_features = all_raw_features.replace([np.inf, -np.inf], np.nan)
    n_cic = len(cic_X_df)
    cic_X_df = all_raw_features.iloc[:n_cic].reset_index(drop=True)
    unsw_X_df = all_raw_features.iloc[n_cic:].reset_index(drop=True)
    cic_families = np.asarray(cic_families)

    rows: list[dict] = []
    run_records: list[dict] = []
    seeds = [17, 29, 43]
    budgets = [0.001, 0.01]
    for seed in seeds:
        rng = np.random.default_rng(seed)
        benign_idx = np.flatnonzero(cic_benign)
        shuffled = rng.permutation(benign_idx)
        n_train = int(0.60 * len(shuffled))
        n_cal = int(0.20 * len(shuffled))
        train_idx = shuffled[:n_train]
        calibration_idx = shuffled[n_train : n_train + n_cal]
        benign_test_idx = shuffled[n_train + n_cal :]

        imputer = SimpleImputer(strategy="median")
        scaler = StandardScaler()
        X_train = scaler.fit_transform(imputer.fit_transform(cic_X_df.iloc[train_idx]))
        X_cal = scaler.transform(imputer.transform(cic_X_df.iloc[calibration_idx]))
        X_cic_benign_test = scaler.transform(imputer.transform(cic_X_df.iloc[benign_test_idx]))
        X_unsw_test = scaler.transform(imputer.transform(unsw_X_df))

        models = {
            "IsolationForest": IsolationForestDetector(n_estimators=150, random_state=seed),
            "PCAReconstruction": PCAReconstructionDetector(n_components=0.95, random_state=seed),
        }
        raw_cal: dict[str, np.ndarray] = {}
        raw_cic: dict[str, np.ndarray] = {}
        raw_unsw: dict[str, np.ndarray] = {}
        fit_times: dict[str, float] = {}
        for name, model in models.items():
            started = time.perf_counter()
            model.fit(X_train)
            fit_times[name] = time.perf_counter() - started
            raw_cal[name] = model.score_samples(X_cal)
            raw_cic[name] = model.score_samples(X_cic_benign_test)
            raw_unsw[name] = model.score_samples(X_unsw_test)

        score_sets = {
            "IsolationForest": (raw_cal["IsolationForest"], raw_cic["IsolationForest"], raw_unsw["IsolationForest"]),
            "PCAReconstruction": (raw_cal["PCAReconstruction"], raw_cic["PCAReconstruction"], raw_unsw["PCAReconstruction"]),
            "RankFusion(IF+PCA)": (
                (percentile_scores(raw_cal["IsolationForest"], raw_cal["IsolationForest"]) + percentile_scores(raw_cal["PCAReconstruction"], raw_cal["PCAReconstruction"])) / 2,
                (percentile_scores(raw_cal["IsolationForest"], raw_cic["IsolationForest"]) + percentile_scores(raw_cal["PCAReconstruction"], raw_cic["PCAReconstruction"])) / 2,
                (percentile_scores(raw_cal["IsolationForest"], raw_unsw["IsolationForest"]) + percentile_scores(raw_cal["PCAReconstruction"], raw_unsw["PCAReconstruction"])) / 2,
            ),
        }

        for model_name, (scores_cal, scores_cic_benign, scores_unsw) in score_sets.items():
            for budget in budgets:
                threshold, inclusive, cal_fpr = threshold_for_budget(scores_cal, budget)
                seed_budget = {"model": model_name, "seed": seed, "target_fpr": budget}
                cic_score_full = np.empty(len(cic_X_df), dtype=np.float64)
                cic_score_full[benign_test_idx] = scores_cic_benign
                # Attack test rows are scored in bounded batches to limit peak memory.
                attack_idx = np.flatnonzero(~cic_benign)
                attack_scores = []
                for start in range(0, len(attack_idx), 100_000):
                    chunk_idx = attack_idx[start : start + 100_000]
                    x_chunk = scaler.transform(imputer.transform(cic_X_df.iloc[chunk_idx]))
                    if model_name == "IsolationForest":
                        chunk_scores = models["IsolationForest"].score_samples(x_chunk)
                    elif model_name == "PCAReconstruction":
                        chunk_scores = models["PCAReconstruction"].score_samples(x_chunk)
                    else:
                        if_scores = models["IsolationForest"].score_samples(x_chunk)
                        pca_scores = models["PCAReconstruction"].score_samples(x_chunk)
                        chunk_scores = (
                            percentile_scores(raw_cal["IsolationForest"], if_scores)
                            + percentile_scores(raw_cal["PCAReconstruction"], pca_scores)
                        ) / 2
                    attack_scores.append(chunk_scores)
                cic_score_full[attack_idx] = np.concatenate(attack_scores)
                cic_family_values = cic_families
                cic_benign_mask = np.zeros(len(cic_X_df), dtype=bool)
                cic_benign_mask[benign_test_idx] = True
                rows.extend(score_domain(
                    "CICIDS2017_same_dataset", cic_attacks, cic_benign_mask,
                    cic_family_values, cic_score_full, threshold, inclusive,
                    {**seed_budget, "threshold": threshold, "threshold_inclusive": inclusive,
                     "calibration_fpr_observed": cal_fpr, "fit_seconds": fit_times.get(model_name, sum(fit_times.values())) if model_name != "RankFusion(IF+PCA)" else sum(fit_times.values())},
                ))
                rows.extend(score_domain(
                    "UNSW_NB15_cross_dataset", unsw_attacks, unsw_labels == 0,
                    unsw_families, scores_unsw, threshold, inclusive,
                    {**seed_budget, "threshold": threshold, "threshold_inclusive": inclusive,
                     "calibration_fpr_observed": cal_fpr, "fit_seconds": fit_times.get(model_name, sum(fit_times.values())) if model_name != "RankFusion(IF+PCA)" else sum(fit_times.values())},
                ))
        run_records.append({
            "seed": seed,
            "benign_train_rows": len(train_idx),
            "benign_calibration_rows": len(calibration_idx),
            "benign_cic_test_rows": len(benign_test_idx),
            "cic_attack_rows": int((~cic_benign).sum()),
            "unsw_test_rows": len(unsw_test),
            "unsw_test_benign_rows": int((unsw_labels == 0).sum()),
            "unsw_test_attack_rows": int((unsw_labels == 1).sum()),
            "fit_seconds": fit_times,
        })

    per_family = pd.DataFrame(rows)
    per_family.to_csv(output_dir / "cross_dataset_family_metrics.csv", index=False)
    mean_metrics = (
        per_family.groupby(["domain", "model", "target_fpr", "attack_family"], as_index=False)
        .agg(recall=("recall", "mean"), benign_fpr=("benign_fpr", "mean"),
             alert_rate=("alert_rate", "mean"), auroc=("auroc", "mean"), aupr=("aupr", "mean"),
             attack_rows=("attack_rows", "first"), benign_rows=("benign_rows", "first"))
    )
    summaries = []
    for (domain, model, budget), group in mean_metrics.groupby(["domain", "model", "target_fpr"]):
        family_rows = group[group["attack_family"] != "normal"]
        summaries.append({
            "domain": domain,
            "model": model,
            "target_fpr": budget,
            "macro_family_recall": float(family_rows["recall"].mean()),
            "worst_family_recall": float(family_rows["recall"].min()),
            "mean_family_auroc": float(family_rows["auroc"].mean()),
            "mean_family_aupr": float(family_rows["aupr"].mean()),
            "mean_observed_benign_fpr": float(group["benign_fpr"].mean()),
            "family_count": int(len(family_rows)),
            "seed_count": len(seeds),
        })
    summary = pd.DataFrame(summaries)
    summary.to_csv(output_dir / "cross_dataset_summary.csv", index=False)
    mean_metrics.to_csv(output_dir / "cross_dataset_family_means.csv", index=False)

    protocol_copy = {
        "protocol_version": "cross-dataset-1.0",
        "source_dataset": "CICIDS2017 Kaggle cleaned/preprocessed derivative supplied by the user",
        "target_dataset": "UNSW-NB15 official fixed test partition (82,332 rows)",
        "transfer_direction": "CICIDS2017 benign-only fit and benign calibration -> untouched UNSW-NB15 test partition",
        "unsw_training_partition_use": "row-count and normal-count verification only; not used for fitting, preprocessing, calibration, or evaluation",
        "models": ["IsolationForest", "PCAReconstruction", "RankFusion(IF+PCA)"],
        "seeds": seeds,
        "target_fpr_budgets": budgets,
        "threshold_selection": "CICIDS2017 benign calibration scores only; no UNSW labels used",
        "feature_names": FEATURE_NAMES,
        "cic_source_columns": CIC_FEATURES,
        "unsw_target_columns": UNSW_FEATURES,
        "feature_mapping_notes": {
            "duration_seconds": "CIC Flow Duration is microseconds and is converted to seconds; UNSW dur is seconds.",
            "source_direction": "CIC forward is mapped to UNSW source direction; CIC backward to UNSW destination direction.",
            "destination_packet_count": "Derived as CIC Bwd Packets/s multiplied by Flow Duration in seconds; UNSW dpkts is direct.",
            "total_flow_bytes_per_second": "CIC Flow Bytes/s; UNSW (sbytes+dbytes)/dur. Zero-duration UNSW rows become missing and are median-imputed from CIC training only.",
            "window_sizes": "CIC initial forward/backward TCP windows mapped to UNSW swin/dwin; semantics are similar, extractor details differ.",
        },
        "threshold_tie_rule": "Strict or inclusive comparison selected so no more than floor(n_calibration * target_fpr) calibration records alert.",
        "primary_limitations": [
            "Only a 9-feature semantic intersection is used; this is not a same-feature reproduction of the 52-feature primary results.",
            "CICFlowMeter and Argus/Bro feature construction differ; direction and feature semantics are approximate across tools.",
            "UNSW-NB15 test uses an official fixed partition; transfer results describe this benchmark and one transfer direction only.",
            "The files were obtained from public mirrors because the official UNSW SharePoint link was inaccessible in this environment; their full SHA-256 values match the published official partition fingerprints.",
        ],
    }
    (output_dir / "cross_dataset_protocol.json").write_text(json.dumps(protocol_copy, indent=2), encoding="utf-8")
    metadata = {
        "project_version": __version__,
        "python_version": platform.python_version(),
        "inputs": {
            "cicids2017_parquet": str(cic_path.resolve()),
            "cicids2017_sha256": sha256_file(cic_path),
            "unsw_nb15_train_csv": str(unsw_train_path.resolve()),
            "unsw_nb15_train_sha256": actual_train_hash,
            "unsw_nb15_test_csv": str(unsw_test_path.resolve()),
            "unsw_nb15_test_sha256": actual_test_hash,
        },
        "unsw_counts": {
            "train_rows": len(unsw_train), "train_normal": int((unsw_train["label"] == 0).sum()),
            "test_rows": len(unsw_test), "test_normal": int((unsw_test["label"] == 0).sum()),
            "test_attack": int((unsw_test["label"] == 1).sum()),
            "test_attack_families": {name: int((unsw_families == name).sum()) for name in unsw_attacks},
        },
        "cic_counts": {"rows": len(cic_raw), "benign_rows": int(cic_benign.sum()), "attack_families": cic_attacks},
        "runs": run_records,
        "protocol": protocol_copy,
        "note": "This cross-dataset transfer comparison uses a smaller semantic feature intersection and is separate from the 52-feature primary LOFO results.",
    }
    (output_dir / "cross_dataset_run.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return metadata


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate CICIDS2017-to-UNSW-NB15 transfer")
    parser.add_argument("--cic-input", default="data/processed/cicids2017_cleaned.parquet")
    parser.add_argument("--unsw-train", default="data/raw/unsw-nb15/UNSW_NB15_training-set.csv")
    parser.add_argument("--unsw-test", default="data/raw/unsw-nb15/UNSW_NB15_testing-set.csv")
    parser.add_argument("--output-dir", default="results/cross_dataset_unsw")
    metadata = run(parser.parse_args())
    print(json.dumps(metadata["unsw_counts"], indent=2))


if __name__ == "__main__":
    main()
