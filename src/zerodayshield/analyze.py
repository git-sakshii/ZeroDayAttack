"""Generate paper summary tables and nonparametric model comparisons."""

import argparse
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import friedmanchisquare


def grouped_bootstrap_ci(frame: pd.DataFrame, metric: str, iterations: int, seed: int) -> tuple[float, float]:
    """Percentile CI resampling dataset-family trial units, not seeds."""
    units = frame[["dataset", "held_out_family", metric]].dropna()
    grouped = units.groupby(["dataset", "held_out_family"], as_index=False)[metric].mean()
    values = grouped[metric].to_numpy(dtype=float)
    if len(values) < 2:
        return float("nan"), float("nan")
    rng = np.random.default_rng(seed)
    samples = rng.choice(values, size=(iterations, len(values)), replace=True).mean(axis=1)
    low, high = np.quantile(samples, [0.025, 0.975])
    return float(low), float(high)


def analyze(input_path: Path, output_dir: Path, iterations: int = 5000, seed: int = 17) -> dict:
    source = pd.read_csv(input_path)
    required = {"dataset", "held_out_family", "model", "target_fpr", "seed", "recall", "test_fpr"}
    missing = required - set(source.columns)
    if missing:
        raise ValueError(f"Metrics file is missing required fields: {sorted(missing)}")
    run_path = input_path.parent / "run.json"
    run_info = __import__("json").loads(run_path.read_text(encoding="utf-8")) if run_path.exists() else {}
    sampled = bool(run_info.get("sampling", {}).get("sample_per_family"))

    # Seeds are repeated fits within one dataset-family trial. Average them
    # before inference so they do not inflate the effective sample count.
    keys = ["dataset", "held_out_family", "model", "target_fpr"]
    trial = source.groupby(keys, as_index=False).agg(
        recall=("recall", "mean"),
        test_fpr=("test_fpr", "mean"),
        auroc=("auroc", "mean"),
        aupr=("aupr", "mean"),
        fit_seconds=("fit_seconds", "mean"),
        score_latency_ms_per_row=("score_latency_ms_per_row", "mean"),
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    trial.to_csv(output_dir / "trial_metrics.csv", index=False)

    summaries = []
    for (model, budget), group in trial.groupby(["model", "target_fpr"]):
        for metric in ["recall", "test_fpr", "auroc", "aupr", "fit_seconds", "score_latency_ms_per_row"]:
            low, high = grouped_bootstrap_ci(group, metric, iterations, seed)
            summaries.append({
                "model": model,
                "target_fpr": budget,
                "metric": metric,
                "mean": float(group[metric].mean()),
                "group_bootstrap_ci_95_low": low,
                "group_bootstrap_ci_95_high": high,
                "trial_units": int(group[["dataset", "held_out_family"]].drop_duplicates().shape[0]),
            })
    summary = pd.DataFrame(summaries)
    summary.to_csv(output_dir / "summary_ci.csv", index=False)

    paper_table = trial.groupby(["target_fpr", "model"], as_index=False).agg(
        macro_family_recall=("recall", "mean"),
        worst_family_recall=("recall", "min"),
        mean_test_fpr=("test_fpr", "mean"),
        mean_auroc=("auroc", "mean"),
        mean_aupr=("aupr", "mean"),
        mean_fit_seconds=("fit_seconds", "mean"),
        mean_score_latency_ms_per_row=("score_latency_ms_per_row", "mean"),
    )
    paper_table.to_csv(output_dir / "paper_summary_table.csv", index=False)

    comparisons = []
    try:
        import scikit_posthocs as sp
    except ImportError:
        sp = None
    for budget, group in trial.groupby("target_fpr"):
        matrix = group.pivot_table(index=["dataset", "held_out_family"], columns="model", values="recall", aggfunc="mean")
        matrix = matrix.dropna(axis=0, how="any")
        model_names = matrix.columns.tolist()
        if len(model_names) < 3 or len(matrix) < 2:
            comparisons.append({"target_fpr": budget, "status": "insufficient_complete_blocks", "blocks": len(matrix), "models": model_names})
            continue
        statistic, pvalue = friedmanchisquare(*(matrix[name].to_numpy() for name in model_names))
        comparisons.append({
            "target_fpr": budget,
            "status": "ok",
            "blocks": len(matrix),
            "models": model_names,
            "friedman_statistic": float(statistic),
            "friedman_pvalue": float(pvalue),
        })
        if sp is not None:
            pvalues = sp.posthoc_nemenyi_friedman(matrix.to_numpy())
            pvalues.index = model_names
            pvalues.columns = model_names
            pvalues.to_csv(output_dir / f"nemenyi_pvalues_fpr_{budget:g}.csv")
            ranks = matrix.rank(axis=1, ascending=False).mean(axis=0)
            sp.critical_difference_diagram(ranks, pvalues)
            import matplotlib.pyplot as plt
            plt.tight_layout()
            plt.savefig(output_dir / f"critical_difference_fpr_{budget:g}.png", dpi=180)
            plt.close()
    (output_dir / "statistical_tests.json").write_text(__import__("json").dumps(comparisons, indent=2), encoding="utf-8")
    markdown = [
        "# Autoencoder LOFO comparison" if sampled else "# First full-data LOFO comparison",
        "",
        "Generated from `lofo_metrics.csv` by `zerodayshield.analyze`; do not edit metric values by hand.",
        "",
        "The input is the user-supplied Kaggle CICIDS2017 cleaned/preprocessed derivative. Its six attack labels are aggregated categories. Dataset preprocessing and licence provenance remain unverified; see the repository `DATASETS.md`.",
        *([f"This is an exploratory stratified sample capped at {run_info['sampling']['sample_per_family']:,} rows per family (sampling seed {run_info['sampling'].get('sample_seed')}). It preserves family recall comparisons but changes class prevalence; AUPR and precision do not represent natural traffic prevalence. Do not compare it as a final full-data result."] if sampled else []),
        "",
        "The table reports macro recall across held-out families, the worst family recall, observed benign-test FPR, ranking metrics, and mean runtime. Repeated seeds were averaged within dataset-family trials before family-level aggregation.",
        "",
        "| " + " | ".join(paper_table.columns) + " |",
        "| " + " | ".join(["---"] * len(paper_table.columns)) + " |",
        *[
            "| " + " | ".join(
                f"{value:.4f}" if isinstance(value, (float, np.floating)) else str(value)
                for value in row
            ) + " |"
            for row in paper_table.itertuples(index=False, name=None)
        ],
        "",
        "## Friedman tests",
        "",
    ]
    for item in comparisons:
        if item.get("status") == "ok":
            markdown.append(
                f"- Target FPR {item['target_fpr']:.3%}: Friedman statistic {item['friedman_statistic']:.3f}, "
                f"p = {item['friedman_pvalue']:.4f}, {item['blocks']} complete dataset-family blocks."
            )
        else:
            markdown.append(f"- Target FPR {item['target_fpr']:.3%}: {item['status']} ({item.get('blocks', 0)} blocks).")
    markdown.extend([
        "",
        "Statistical comparison across different models is unavailable in this single-model run.",
        "",
        "This is a pilot comparison on one Kaggle-prepared derivative, not a final claim about zero-day detection across datasets. The anomaly score is not an attack probability. At the 0.1% target budget, observed recall is especially low on rare, stealthy aggregated families.",
        "",
    ])
    (output_dir / "summary.md").write_text("\n".join(markdown), encoding="utf-8")
    return {"trial_rows": len(trial), "summary_rows": len(summary), "comparisons": comparisons}


def main() -> None:
    parser = argparse.ArgumentParser(description="Summarize LOFO metrics and compare models")
    parser.add_argument("--input", required=True, help="lofo_metrics.csv")
    parser.add_argument("--output-dir", default="results/analysis")
    parser.add_argument("--bootstrap-iterations", type=int, default=5000)
    parser.add_argument("--seed", type=int, default=17)
    args = parser.parse_args()
    print(analyze(Path(args.input), Path(args.output_dir), args.bootstrap_iterations, args.seed))


if __name__ == "__main__":
    main()
