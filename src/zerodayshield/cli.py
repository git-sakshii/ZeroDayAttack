import argparse
import hashlib
import json
import platform
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

from . import __version__
from .data import load_and_split
from .detectors import IsolationForestDetector, PCAReconstructionDetector


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run(args: argparse.Namespace) -> dict:
    input_path = Path(args.input)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    frame = pd.read_csv(input_path, low_memory=False, nrows=args.max_rows)
    if not args.protocol:
        raise ValueError("A protocol JSON is required for reproducible runs")
    protocol_path = Path(args.protocol)
    protocol = json.loads(protocol_path.read_text(encoding="utf-8"))
    if protocol.get("splitting", {}).get("fit_preprocessing_on_training_only") is not True:
        raise ValueError("Protocol must require preprocessing fitted on training data only")
    if protocol.get("thresholding", {}).get("test_labels_used_for_threshold") is not False:
        raise ValueError("Protocol must prohibit test labels for threshold selection")
    protocol_budgets = protocol.get("thresholding", {}).get("false_positive_rate_budgets", [])
    if any(budget not in protocol_budgets for budget in args.fpr_budgets):
        raise ValueError(f"Requested FPR budgets {args.fpr_budgets} are not declared in protocol: {protocol_budgets}")
    data = load_and_split(
        frame,
        label_column=args.label_column,
        family_column=args.family_column,
        benign_label=args.benign_label,
        test_family=args.test_family,
        random_state=args.seed,
    )

    if args.model == "isolation_forest":
        model = IsolationForestDetector(n_estimators=args.n_estimators, random_state=args.seed)
        model_name = "IsolationForest"
    else:
        model = PCAReconstructionDetector(n_components=args.pca_components, random_state=args.seed)
        model_name = "PCAReconstruction"
    fit_start = time.perf_counter()
    model.fit(data.X_train)
    fit_seconds = time.perf_counter() - fit_start
    calibration_scores = model.score_samples(data.X_calibration)
    score_start = time.perf_counter()
    test_scores = model.score_samples(data.X_test)
    score_elapsed = time.perf_counter() - score_start

    records = []
    for target_fpr in args.fpr_budgets:
        if not 0 < target_fpr < 1:
            raise ValueError(f"FPR budget must be between zero and one: {target_fpr}")
        minimum_calibration_rows = int(np.ceil(1 / target_fpr))
        if len(calibration_scores) < minimum_calibration_rows:
            raise ValueError(
                f"FPR budget {target_fpr:g} requires at least {minimum_calibration_rows} benign calibration rows "
                f"for useful empirical tail resolution; got {len(calibration_scores)}. "
                "Use more benign data or omit this budget for a smoke run."
            )
        # Use the order statistic that admits no more than floor(n * budget)
        # calibration exceedances. Strict > handles ties conservatively.
        allowed_alerts = int(np.floor(len(calibration_scores) * target_fpr))
        ordered = np.sort(calibration_scores)
        threshold = float(ordered[-allowed_alerts - 1])
        predictions = test_scores >= threshold
        # For a tied boundary, equality would exceed the requested calibration
        # budget. Use strict comparison only when required, and record it.
        calibration_exceedances = calibration_scores > threshold
        inclusive = int((calibration_scores == threshold).sum()) + int(calibration_exceedances.sum()) <= allowed_alerts
        predictions = test_scores >= threshold if inclusive else test_scores > threshold
        calibration_alert_rate = float((calibration_scores >= threshold).mean() if inclusive else (calibration_scores > threshold).mean())
        benign_test = data.y_test == 0
        attack_test = data.y_test == 1
        fpr = float(predictions[benign_test].mean())
        recall = float(predictions[attack_test].mean())
        records.append({
            "model": model_name,
            "test_family": args.test_family or str(sorted(set(data.families_test) - {"BENIGN"})[-1]),
            "target_fpr": target_fpr,
            "threshold": threshold,
            "test_rows": len(test_scores),
            "benign_test_rows": int(benign_test.sum()),
            "attack_test_rows": int(attack_test.sum()),
            "recall": recall,
            "test_fpr": fpr,
            "calibration_fpr_observed": calibration_alert_rate,
            "threshold_inclusive": inclusive,
            "auroc": float(roc_auc_score(data.y_test, test_scores)),
            "aupr": float(average_precision_score(data.y_test, test_scores)),
            "fit_seconds": fit_seconds,
            "score_latency_ms_per_row": float(1000 * score_elapsed / max(1, len(test_scores))),
        })

    pd.DataFrame(records).to_csv(output_dir / "metrics.csv", index=False)
    metadata = {
        "project_version": __version__,
        "input": str(input_path.resolve()),
        "input_sha256": sha256_file(input_path),
        "seed": args.seed,
        "feature_names": data.feature_names,
        "test_family": args.test_family or str(sorted(set(data.families_test) - {"BENIGN"})[-1]),
        "python_version": platform.python_version(),
        "protocol_copy": str(protocol_path.resolve()),
        "protocol_version": protocol.get("protocol_version"),
        "split_sizes": {
            "benign_train": len(data.train_indexes),
            "benign_calibration": len(data.calibration_indexes),
            "benign_test": int((data.y_test == 0).sum()),
            "held_out_attack_test": int((data.y_test == 1).sum()),
        },
        "n_estimators": args.n_estimators,
        "model": args.model,
        "pca_components": args.pca_components,
        "fpr_budgets": args.fpr_budgets,
        "metrics": records,
        "note": "Anomaly scores are not attack probabilities. This is a one-family smoke baseline, not a final LOFO evaluation.",
    }
    (output_dir / "run.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    (output_dir / "protocol.json").write_text(json.dumps(protocol, indent=2), encoding="utf-8")
    return metadata


def main() -> None:
    parser = argparse.ArgumentParser(description="Run ZeroDayShield Isolation Forest baseline")
    parser.add_argument("--input", required=True, help="Input numeric flow CSV")
    parser.add_argument("--label-column", required=True)
    parser.add_argument("--family-column")
    parser.add_argument("--benign-label", default="BENIGN")
    parser.add_argument("--test-family")
    parser.add_argument("--output-dir", default="results/run")
    parser.add_argument("--protocol", default="configs/protocol.json")
    parser.add_argument("--seed", type=int, default=17)
    parser.add_argument("--n-estimators", type=int, default=150)
    parser.add_argument("--model", choices=["isolation_forest", "pca"], default="isolation_forest")
    parser.add_argument("--pca-components", type=float, default=0.95, help="Variance fraction for PCA, from 0 to 1")
    parser.add_argument("--fpr-budgets", type=float, nargs="+", default=[0.01])
    parser.add_argument("--max-rows", type=int, help="Optional deterministic row cap for memory-limited smoke runs")
    run(parser.parse_args())


if __name__ == "__main__":
    main()
