"""Train a replayable detector bundle and score flow-record CSV/Parquet files."""

import argparse
import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler

from .data import load_and_split
from .detectors import AutoencoderDetector, IsolationForestDetector, PCAReconstructionDetector


def load_frame(path: Path) -> pd.DataFrame:
    return pd.read_parquet(path) if path.suffix.lower() in {".parquet", ".pq"} else pd.read_csv(path, low_memory=False)


def fit_bundle(input_path: Path, output_path: Path, model_key: str, label_column: str, family_column: str,
               benign_label: str, target_fpr: float, seed: int) -> dict:
    if not 0 < target_fpr < 1:
        raise ValueError("target_fpr must be between 0 and 1")
    frame = load_frame(input_path)
    data = load_and_split(frame, label_column, family_column, benign_label, random_state=seed)
    if model_key == "isolation_forest":
        detector = IsolationForestDetector(random_state=seed)
    elif model_key == "pca":
        detector = PCAReconstructionDetector(random_state=seed)
    elif model_key == "autoencoder":
        detector = AutoencoderDetector(random_state=seed)
    elif model_key == "rank_fusion":
        detector = None
    else:
        raise ValueError("Select isolation_forest, pca, autoencoder, or rank_fusion")
    components = None
    if model_key == "rank_fusion":
        components = [IsolationForestDetector(random_state=seed), PCAReconstructionDetector(random_state=seed)]
        for component in components:
            component.fit(data.X_train)
        raw_calibration = [component.score_samples(data.X_calibration) for component in components]
        fusion_calibration_scores = raw_calibration
        calibration = np.mean([_percentiles(ref, ref) for ref in raw_calibration], axis=0)
    else:
        detector.fit(data.X_train)
        calibration = detector.score_samples(data.X_calibration)
        fusion_calibration_scores = None
    allowed = int(np.floor(len(calibration) * target_fpr))
    if len(calibration) < int(np.ceil(1 / target_fpr)):
        raise ValueError("Not enough benign calibration rows for this FPR budget")
    threshold = float(np.sort(calibration)[-allowed - 1])
    inclusive = int((calibration == threshold).sum()) + int((calibration > threshold).sum()) <= allowed
    # Refit persistent preprocessing using only the same benign training indexes.
    labels = frame[label_column].astype(str).str.strip()
    benign = labels.str.casefold() == benign_label.casefold()
    excluded_cols = {label_column, family_column, "Flow ID", "Source IP", "Destination IP", "Timestamp", "SimillarHTTP"}
    raw_features = [c for c in frame.columns if c not in excluded_cols]
    numeric = frame.loc[:, raw_features].apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan)
    numeric = numeric.dropna(axis=1, how="all")
    # load_and_split returns row labels/indexes in the source frame.
    imputer, scaler = SimpleImputer(strategy="median"), StandardScaler()
    train_raw = numeric.loc[data.train_indexes]
    imputer.fit(train_raw)
    scaler.fit(imputer.transform(train_raw))
    bundle = {
        "detector": detector, "imputer": imputer, "scaler": scaler,
        "components": components,
        "fusion_calibration_scores": fusion_calibration_scores,
        "feature_names": numeric.columns.tolist(), "threshold": threshold,
        "threshold_inclusive": inclusive, "target_fpr": target_fpr,
        "model": model_key, "seed": seed, "dataset": str(input_path),
        "note": "Anomaly score is not an attack probability. This is a research replay model.",
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, output_path)
    return {k: v for k, v in bundle.items() if k not in {"detector", "imputer", "scaler", "components", "fusion_calibration_scores"}}


def _percentiles(reference: np.ndarray, values: np.ndarray) -> np.ndarray:
    sorted_reference = np.sort(reference)
    return np.searchsorted(sorted_reference, values, side="right") / max(1, len(sorted_reference))


def score_frame(frame: pd.DataFrame, bundle: dict) -> pd.DataFrame:
    names = bundle["feature_names"]
    missing = [name for name in names if name not in frame.columns]
    if missing:
        raise ValueError(f"Replay input is missing {len(missing)} trained features (e.g. {missing[:8]})")
    numeric = frame.loc[:, names].apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan)
    X = bundle["scaler"].transform(bundle["imputer"].transform(numeric))
    start = time.perf_counter()
    if bundle["model"] == "rank_fusion":
        raw = [model.score_samples(X) for model in bundle["components"]]
        cal_refs = bundle["fusion_calibration_scores"]
        scores = np.mean([_percentiles(ref, values) for ref, values in zip(cal_refs, raw)], axis=0)
    else:
        scores = bundle["detector"].score_samples(X)
    elapsed = time.perf_counter() - start
    alerts = scores >= bundle["threshold"] if bundle["threshold_inclusive"] else scores > bundle["threshold"]
    result = pd.DataFrame({"anomaly_score": scores, "alert": alerts})
    result["severity"] = np.where(alerts, "Review", "Normal")
    if "attack_family" in frame.columns:
        result.insert(0, "attack_family", frame["attack_family"].astype(str).to_numpy())
    if "Label" in frame.columns:
        result.insert(0, "Label", frame["Label"].astype(str).to_numpy())
    result.attrs["latency_ms_per_row"] = 1000 * elapsed / max(1, len(frame))
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Train replay model or score flow records")
    sub = parser.add_subparsers(dest="command", required=True)
    train = sub.add_parser("train")
    train.add_argument("--input", required=True); train.add_argument("--output", default="models/replay.joblib")
    train.add_argument("--model", choices=["isolation_forest", "pca", "autoencoder", "rank_fusion"], default="isolation_forest")
    train.add_argument("--label-column", default="Label"); train.add_argument("--family-column", default="attack_family")
    train.add_argument("--benign-label", default="BENIGN"); train.add_argument("--target-fpr", type=float, default=0.01)
    train.add_argument("--seed", type=int, default=17)
    score = sub.add_parser("score")
    score.add_argument("--model", default="models/replay.joblib"); score.add_argument("--input", required=True)
    score.add_argument("--output", default="results/replay/alerts.csv")
    args = parser.parse_args()
    if args.command == "train":
        print(json.dumps(fit_bundle(Path(args.input), Path(args.output), args.model, args.label_column,
                                     args.family_column, args.benign_label, args.target_fpr, args.seed), indent=2))
    else:
        result = score_frame(load_frame(Path(args.input)), joblib.load(args.model))
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        result.to_csv(args.output, index=False)
        print(json.dumps({"rows": len(result), "alerts": int(result.alert.sum()),
                          "latency_ms_per_row": result.attrs["latency_ms_per_row"], "output": args.output}, indent=2))


if __name__ == "__main__":
    main()
