"""Run matched family-block Friedman checks including sampled supervision."""

import json
from pathlib import Path

import pandas as pd
from scipy.stats import friedmanchisquare


ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "results/cicids2017_core/lofo_metrics.csv"
SUPERVISED = ROOT / "results/supervised_rejection/lofo_metrics.csv"
OUTPUT = ROOT / "results/supervised_rejection/comparison_with_core.json"


def main():
    core = pd.read_csv(CORE)
    supervised = pd.read_csv(SUPERVISED)
    dataset_name = core["dataset"].iloc[0]
    if set(core["held_out_family"]) != set(supervised["held_out_family"]):
        raise ValueError("Core and supervised results must have the same held-out families")
    if set(core["target_fpr"]) != set(supervised["target_fpr"]):
        raise ValueError("Core and supervised results must use the same FPR budgets")
    supervised["dataset"] = dataset_name
    merged = pd.concat([core, supervised], ignore_index=True)
    trial = merged.groupby(
        ["dataset", "held_out_family", "model", "target_fpr"], as_index=False
    ).agg(recall=("recall", "mean"))

    results = {
        "comparison": "IF, PCA, rank fusion, and sampled HistGradientBoosting rejection reference",
        "trial_unit": "held-out CIC aggregate attack family; repeated seeds averaged within family",
        "supervised_run": str((ROOT / "results/supervised_rejection/protocol.json").relative_to(ROOT)),
        "limitations": [
            "Only six family blocks are available and they share benign partitions.",
            "The supervised reference uses up to 1000 rows per class and 15 boosting iterations.",
            "This comparison is exploratory and does not establish equivalence or a universal winner.",
        ],
        "tests": [],
    }
    for budget, rows in trial.groupby("target_fpr"):
        matrix = rows.pivot(index="held_out_family", columns="model", values="recall").dropna()
        statistic, pvalue = friedmanchisquare(*(matrix[name].to_numpy() for name in matrix.columns))
        results["tests"].append({
            "target_fpr": float(budget),
            "family_blocks": int(len(matrix)),
            "models": matrix.columns.tolist(),
            "friedman_statistic": float(statistic),
            "friedman_pvalue": float(pvalue),
            "macro_family_recall": matrix.mean(axis=0).to_dict(),
            "worst_family_recall_after_seed_averaging": matrix.min(axis=0).to_dict(),
        })
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"Wrote {OUTPUT}")


if __name__ == "__main__":
    main()
