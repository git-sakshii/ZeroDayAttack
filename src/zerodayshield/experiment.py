"""Run the frozen-family LOFO evaluation for the implemented core detectors."""

import argparse
import hashlib
import json
import platform
import time
from pathlib import Path

import numpy as np
import pandas as pd
import polars as pl
from sklearn.metrics import average_precision_score, roc_auc_score

from . import __version__
from .data import load_and_split
from .detectors import AutoencoderDetector, IsolationForestDetector, PCAReconstructionDetector


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def model_for(name: str, seed: int, estimators: int, pca_components: float):
    if name == "isolation_forest":
        return "IsolationForest", IsolationForestDetector(n_estimators=estimators, random_state=seed)
    if name == "pca":
        return "PCAReconstruction", PCAReconstructionDetector(n_components=pca_components, random_state=seed)
    if name == "autoencoder":
        return "Autoencoder", AutoencoderDetector(epochs=30, batch_size=512, random_state=seed)
    if name == "rank_fusion":
        return "RankFusion(IF+PCA)", None
    raise ValueError(f"Unsupported model: {name}")


def percentile_scores(reference: np.ndarray, values: np.ndarray) -> np.ndarray:
    """Map a detector score to its empirical calibration percentile."""
    reference = np.sort(reference)
    return np.searchsorted(reference, values, side="right") / max(1, len(reference))


def read_stratified_sample(
    input_path: Path,
    label_column: str,
    family_column: str | None,
    sample_per_family: int,
    seed: int,
) -> pd.DataFrame:
    """Read a deterministic bounded-size uniform sample from each family."""
    key_column = family_column or label_column
    if input_path.suffix.casefold() == ".parquet":
        scan = pl.scan_parquet(input_path)
        columns = scan.collect_schema().names()
        if key_column not in columns:
            raise ValueError(f"Sampling column {key_column!r} not found in Parquet input")
        row_id = "__zs_row_id"
        rank_id = "__zs_rank"
        ranked = scan.with_row_index(row_id).with_columns(pl.col(row_id).hash(seed=seed).alias(rank_id))
        chosen = (
            ranked.group_by(key_column)
            .agg(pl.col(row_id).sort_by(rank_id).head(sample_per_family).alias(row_id))
            .select(pl.col(row_id).explode())
            .collect(engine="streaming")
            .get_column(row_id)
            .to_list()
        )
        return (
            ranked.filter(pl.col(row_id).is_in(chosen))
            .drop(row_id, rank_id)
            .collect(engine="streaming")
            .to_pandas()
        )

    rng = np.random.default_rng(seed)
    reservoirs: dict[str, pd.DataFrame] = {}
    reader = pd.read_csv(input_path, low_memory=False, chunksize=50_000)
    seen: dict[str, int] = {}
    for chunk in reader:
        if key_column not in chunk.columns:
            raise ValueError(f"Sampling column {key_column!r} not found in CSV input")
        keys = chunk[key_column].fillna("unknown").astype(str).str.strip()
        priorities = rng.random(len(chunk))
        chunk = chunk.assign(__zs_rank=priorities)
        for family in keys.unique():
            positions = np.flatnonzero(keys.to_numpy() == family)
            candidate = chunk.iloc[positions]
            old = reservoirs.get(family)
            combined = candidate if old is None else pd.concat([old, candidate], ignore_index=True)
            reservoirs[family] = combined.nsmallest(sample_per_family, "__zs_rank")
            seen[family] = seen.get(family, 0) + len(positions)
    if not reservoirs:
        raise ValueError("No rows were read from the input")
    result = pd.concat(reservoirs.values(), ignore_index=True).drop(columns="__zs_rank")
    result.attrs["sampled_counts"] = {family: len(rows) for family, rows in reservoirs.items()}
    result.attrs["observed_counts"] = seen
    return result


def run(args: argparse.Namespace) -> dict:
    input_path = Path(args.input)
    protocol_path = Path(args.protocol)
    schedule_path = Path(args.schedule)
    protocol = json.loads(protocol_path.read_text(encoding="utf-8"))
    schedule = json.loads(schedule_path.read_text(encoding="utf-8"))
    if protocol.get("splitting", {}).get("fit_preprocessing_on_training_only") is not True:
        raise ValueError("Protocol must require train-only preprocessing")
    if protocol.get("thresholding", {}).get("test_labels_used_for_threshold") is not False:
        raise ValueError("Protocol must prohibit test-label threshold selection")
    if schedule.get("status") != "frozen":
        raise ValueError("Family schedule is not frozen. Audit the labels and predeclare families before running LOFO.")
    if schedule.get("source_checksum_sha256") != sha256_file(input_path):
        raise ValueError("Input checksum does not match the frozen family schedule")
    families = schedule.get("final_test_families", [])
    if not families or any(str(f).startswith("TBD") for f in families):
        raise ValueError("Family schedule has no valid final test families")
    development_families = set(schedule.get("development_families", []))
    if set(families) & development_families:
        raise ValueError("Final-test families must be disjoint from development families")

    if args.sample_per_family:
        frame = read_stratified_sample(
            input_path,
            args.label_column,
            args.family_column,
            args.sample_per_family,
            args.sample_seed,
        )
    else:
        frame = pd.read_parquet(input_path) if input_path.suffix.casefold() == ".parquet" else pd.read_csv(input_path, low_memory=False)
    all_families = set(frame[args.family_column].dropna().astype(str).str.strip()) if args.family_column else set(frame[args.label_column].dropna().astype(str).str.strip())
    all_families = {name for name in all_families if name.casefold() != args.benign_label.casefold()}
    declared_families = set(schedule.get("families", []))
    declared_families.discard("BENIGN")
    if declared_families and not any(name.startswith("TBD") for name in declared_families):
        if declared_families != all_families:
            raise ValueError(
                "Frozen schedule families do not match the input's observed attack families; "
                f"missing={sorted(all_families - declared_families)}, extra={sorted(declared_families - all_families)}"
            )
        if set(families) | development_families != all_families:
            raise ValueError("Every observed attack family must be assigned to development or final-test groups")
    missing = set(families) - all_families
    if missing:
        raise ValueError(f"Scheduled families absent from input: {sorted(missing)}")

    records = []
    seeds = args.seeds or protocol.get("splitting", {}).get("seeds", [17])
    budgets = args.fpr_budgets or protocol.get("thresholding", {}).get("false_positive_rate_budgets", [0.01])
    for seed in seeds:
        for family in families:
            data = load_and_split(
                frame,
                label_column=args.label_column,
                family_column=args.family_column,
                benign_label=args.benign_label,
                test_family=family,
                random_state=seed,
            )
            for model_key in args.models:
                model_name, model = model_for(model_key, seed, args.n_estimators, args.pca_components)
                fit_start = time.perf_counter()
                if model_key == "rank_fusion":
                    components = [
                        IsolationForestDetector(n_estimators=args.n_estimators, random_state=seed),
                        PCAReconstructionDetector(n_components=args.pca_components, random_state=seed),
                    ]
                    for component in components:
                        component.fit(data.X_train)
                    fit_seconds = time.perf_counter() - fit_start
                    calibration_raw = [component.score_samples(data.X_calibration) for component in components]
                    test_start = time.perf_counter()
                    test_raw = [component.score_samples(data.X_test) for component in components]
                    score_seconds = time.perf_counter() - test_start
                    calibration_scores = np.mean(
                        [percentile_scores(reference, reference) for reference in calibration_raw], axis=0
                    )
                    test_scores = np.mean(
                        [percentile_scores(reference, values) for reference, values in zip(calibration_raw, test_raw)], axis=0
                    )
                else:
                    model.fit(data.X_train)
                    fit_seconds = time.perf_counter() - fit_start
                    calibration_scores = model.score_samples(data.X_calibration)
                    score_start = time.perf_counter()
                    test_scores = model.score_samples(data.X_test)
                    score_seconds = time.perf_counter() - score_start
                for budget in budgets:
                    if not 0 < budget < 1:
                        raise ValueError(f"Invalid FPR budget: {budget}")
                    if budget not in protocol.get("thresholding", {}).get("false_positive_rate_budgets", []):
                        raise ValueError(f"FPR budget {budget} is missing from protocol")
                    needed = int(np.ceil(1 / budget))
                    if len(calibration_scores) < needed:
                        raise ValueError(f"FPR budget {budget} needs >= {needed} calibration samples; got {len(calibration_scores)}")
                    allowed = int(np.floor(len(calibration_scores) * budget))
                    ordered = np.sort(calibration_scores)
                    threshold = float(ordered[-allowed - 1])
                    inclusive = int((calibration_scores == threshold).sum()) + int((calibration_scores > threshold).sum()) <= allowed
                    decisions = test_scores >= threshold if inclusive else test_scores > threshold
                    benign = data.y_test == 0
                    attack = data.y_test == 1
                    records.append({
                        "dataset": schedule.get("dataset"),
                        "seed": seed,
                        "held_out_family": family,
                        "model": model_name,
                        "target_fpr": budget,
                        "threshold": threshold,
                        "threshold_inclusive": inclusive,
                        "calibration_fpr_observed": float((calibration_scores >= threshold).mean() if inclusive else (calibration_scores > threshold).mean()),
                        "test_fpr": float(decisions[benign].mean()),
                        "recall": float(decisions[attack].mean()),
                        "auroc": float(roc_auc_score(data.y_test, test_scores)),
                        "aupr": float(average_precision_score(data.y_test, test_scores)),
                        "benign_train_rows": len(data.train_indexes),
                        "benign_calibration_rows": len(data.calibration_indexes),
                        "benign_test_rows": int(benign.sum()),
                        "attack_test_rows": int(attack.sum()),
                        "fit_seconds": fit_seconds,
                        "score_latency_ms_per_row": 1000 * score_seconds / max(1, len(test_scores)),
                    })

    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    results = pd.DataFrame(records)
    results.to_csv(output / "lofo_metrics.csv", index=False)
    results.to_parquet(output / "lofo_metrics.parquet", index=False)
    run_info = {
        "project_version": __version__,
        "python_version": platform.python_version(),
        "input": str(input_path.resolve()),
        "input_sha256": sha256_file(input_path),
        "protocol": str(protocol_path.resolve()),
        "family_schedule": str(schedule_path.resolve()),
        "family_schedule_sha256": sha256_file(schedule_path),
        "models": args.models,
        "seeds": seeds,
        "fpr_budgets": budgets,
        "sampling": {
            "sample_per_family": args.sample_per_family,
            "sample_seed": args.sample_seed if args.sample_per_family else None,
            "sampled_counts": getattr(frame, "attrs", {}).get("sampled_counts"),
            "observed_counts": getattr(frame, "attrs", {}).get("observed_counts"),
            "note": "Per-family sampling preserves family recall comparisons but changes class prevalence and therefore AUPR/precision interpretation." if args.sample_per_family else "No row sampling applied.",
        },
        "rows": len(records),
        "note": "LOFO protocol run. Anomaly scores are not probabilities; held-out families are a zero-day-style proxy.",
    }
    (output / "run.json").write_text(json.dumps(run_info, indent=2), encoding="utf-8")
    (output / "protocol.json").write_text(json.dumps(protocol, indent=2), encoding="utf-8")
    (output / "family_schedule.json").write_text(json.dumps(schedule, indent=2), encoding="utf-8")
    return run_info


def main() -> None:
    parser = argparse.ArgumentParser(description="Run predeclared LOFO evaluation")
    parser.add_argument("--input", required=True, help="Prepared CSV or Parquet file")
    parser.add_argument("--label-column", default="Label")
    parser.add_argument("--family-column", default="attack_family")
    parser.add_argument("--benign-label", default="BENIGN")
    parser.add_argument("--protocol", default="configs/protocol.json")
    parser.add_argument("--schedule", default="configs/family_schedule.json")
    parser.add_argument("--output-dir", default="results/lofo")
    parser.add_argument("--models", nargs="+", choices=["isolation_forest", "pca", "autoencoder", "rank_fusion"], default=["isolation_forest", "pca", "rank_fusion"])
    parser.add_argument("--seeds", type=int, nargs="+")
    parser.add_argument("--fpr-budgets", type=float, nargs="+")
    parser.add_argument("--n-estimators", type=int, default=150)
    parser.add_argument("--pca-components", type=float, default=0.95)
    parser.add_argument("--sample-per-family", type=int, help="Optional bounded-memory uniform row sample cap per family")
    parser.add_argument("--sample-seed", type=int, default=1701)
    args = parser.parse_args()
    run(args)


if __name__ == "__main__":
    main()
