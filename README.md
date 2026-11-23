# ZeroDayShield v2

Reproducible research project for evaluating network anomaly detectors on held-out attack families. A held-out family is a zero-day-style proxy, not evidence of detecting real zero-day attacks.

## Quick start

1. Create a Python 3.11 environment and install `requirements.txt`.
2. Put a flow CSV under `data/raw/` and prepare it using the converter below.
3. Use `zerodayshield.experiment` for the frozen-family LOFO protocol; the older `zerodayshield.cli` command is a one-family smoke baseline.

The experiments train anomaly detectors on benign training rows only, calibrate thresholds on separate benign calibration rows, and report recall alongside false-positive rate. Preprocessing is fitted on training rows only. Dataset cleaning, family mapping, and a fixed LOFO family schedule must be audited before final claims.

## Layout

- `configs/protocol.json`: versioned experiment protocol and split rules.
- `configs/family_schedule.json`: frozen schedule for the current local CICIDS2017-derived dataset; a new dataset needs its own reviewed schedule and checksum.
- `DATASETS.md`: primary dataset choice, citations, and audit checklist.
- `src/zerodayshield/`: preprocessing, split logic, detector API, baseline, and CLI.
- `data/`: local inputs and processed data (not committed).
- `results/`: generated metrics and run metadata (not committed).

For CSV inputs, provide a label column and optionally a family column. If no family column exists, labels other than the configured benign label are used as families. The input is expected to contain numeric flow features; non-numeric columns are dropped by the training-fitted preprocessing pipeline.

## Current plan

- Working deadline: 10 November 2026.
- Paper venue and dashboard framework: TBD.
- Hardware target: Windows, 16 GB RAM, integrated Radeon graphics; prioritize CPU-friendly models and small smoke runs.

The one-family CLI reads CSV into memory. The LOFO runner supports Parquet and optional deterministic per-family sampling. Sampling is exploratory unless a representative sample protocol is declared in advance. For target FPR budget `b`, at least `ceil(1/b)` benign calibration rows are required. Test FPR can differ from calibration FPR because both are finite samples.

## Dataset preparation and LOFO

Convert a source CSV to compressed Parquet with label normalization and an audit record:

```powershell
.\.venv\Scripts\python.exe -m zerodayshield.prepare --input data/raw/flows.csv --output data/processed/flows.parquet --label-column Label
```

The converter streams the output, removes exact duplicate rows, quarantines rows with identical non-label features but conflicting families to a separate conflict-signatures Parquet file, and records source/output checksums and normalized label counts. Normalization is not a ground-truth correction; inspect the audit and conflict file before freezing a schedule. Then fill `configs/family_schedule.json`, set its status to `frozen`, use the exact prepared file SHA-256, and provide reviewed `final_test_families` and `development_families`.

Run the current core LOFO models after freezing the schedule:

```powershell
.\.venv\Scripts\python.exe -m zerodayshield.experiment --input data/processed/flows.parquet --label-column Label --family-column attack_family
```

For a memory-limited exploratory run, append `--sample-per-family 10000`. This takes a deterministic uniform sample per label/family while reading in chunks (or scanning Parquet), and records sampled and observed counts. It changes attack prevalence, so use it for model development and per-family recall comparisons; do not interpret its AUPR/precision as natural-traffic performance. Final runs should use the full data or a predeclared representative sample protocol.

Implemented detectors: Isolation Forest, PCA reconstruction, a small CPU PyTorch autoencoder, and rank-averaged score fusion of Isolation Forest and PCA. The fusion maps scores to percentiles using benign calibration scores and averages the percentiles before thresholding. Install `requirements-ml.txt` before selecting the autoencoder. Supervised rejection, dataset-specific correction, and cross-dataset runs remain future work.

## Flow replay and alert dashboard

Train a persistent benign-only detector bundle (the example defaults to Isolation Forest and a 1% benign calibration alert budget):

```powershell
python -m zerodayshield.replay train --input data/processed/cicids2017_cleaned.parquet --output models/replay.joblib --model isolation_forest --target-fpr 0.01
```

Score flow records from a CSV or Parquet with exactly the same feature columns, and write a reviewable CSV of scores and alerts:

```powershell
python -m zerodayshield.replay score --model models/replay.joblib --input path/to/flows.parquet --output results/replay/alerts.csv
```

Install and launch the optional Streamlit dashboard:

```powershell
python -m pip install -r requirements-dashboard.txt
streamlit run src/zerodayshield/dashboard.py
```

The dashboard accepts a model bundle and a flow CSV/Parquet, displays alerts and per-family alert rates when labels are present, and allows downloading scored results. This is offline flow replay; it does not capture raw packets. A packet capture source still requires a compatible flow builder and verified feature mapping before live alerts can be claimed.

Summarize a completed LOFO run and produce grouped bootstrap intervals and (when enough complete trial blocks exist) Friedman/Nemenyi comparisons:

```powershell
.\.venv\Scripts\python.exe -m zerodayshield.analyze --input results/lofo/lofo_metrics.csv --output-dir results/analysis
```

The analysis averages repeated seeds within each dataset-family trial before statistical comparison. The critical-difference diagram and Nemenyi files are written only when there are at least three models and two complete trial blocks.

## Current real-data run

The supplied Kaggle archive and its audit record are documented in `DATASETS.md`. The extracted CSV is `data/raw/cicids2017_cleaned.csv`; the cleaned Parquet is `data/processed/cicids2017_cleaned.parquet`. The predeclared family schedule is in `configs/family_schedule.json`. The first full-data LOFO comparison (Isolation Forest, PCA, and rank fusion; three seeds; 1% and 0.1% FPR budgets) is in `results/cicids2017_core/`, with statistical summaries in `results/cicids2017_analysis/`.
