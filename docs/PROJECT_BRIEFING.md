# ZeroDayShield v2 — Project Briefing

**Prepared for:** team presentation and instructor questions  
**Project type:** research prototype for flow-based network anomaly detection  
**Status:** offline research pipeline and replay dashboard implemented; live capture and cross-dataset validation remain future work.

## 1. Project in one minute

ZeroDayShield compares detectors trained on benign network-flow records. The research question is whether a detector can flag traffic from an attack family it did not see during training, and how many benign records it flags along the way. We approximate a “new” attack by holding out one complete labeled attack family for testing. This is a zero-day-style benchmark proxy, not a real zero-day test.

We implemented Isolation Forest, PCA reconstruction error, a small autoencoder, and equal-weight rank fusion of Isolation Forest and PCA. We calibrated thresholds using a separate benign calibration split, then evaluated attack recall and benign false-positive rate. We also built an offline Streamlit dashboard that scores uploaded flow records. It does not capture live packets yet.

## 2. Dataset and preparation

The local dataset is the user-supplied **CICIDS2017 Cleaned & Preprocessed** derivative from Kaggle, by `ericanacletoribe`. It is a contributor-prepared derivative, not confirmed as the official corrected LycoS release. Its cleaning provenance and license have not been independently verified. Describe it that way in the report and cite the Kaggle dataset; do not call it a verified corrected CICIDS2017 release.

The source CSV had 2,520,751 rows, 52 numeric flow features, and the label column `Attack Type`. It contains the broad categories benign/normal, Bots, Brute Force, DDoS, DoS, Port Scanning, and Web Attacks. Preparation removed 161 exact duplicate rows and quarantined 1,394 rows in 697 groups with identical features but conflicting labels. The retained Parquet has 2,519,196 rows:

| Family | Retained rows |
|---|---:|
| Benign | 2,094,199 |
| DoS | 193,615 |
| DDoS | 128,011 |
| Port scanning | 90,130 |
| Brute force | 9,150 |
| Web attacks | 2,143 |
| Bots | 1,948 |

Because these labels are aggregated, our “family” conclusions are limited to these six broad attack categories. We cannot claim fine-grained attack-type results from this file.

## 3. How the experiment works

1. **Split benign rows:** Each seed (17, 29, 43) makes a deterministic benign-only train, calibration, and benign-test split. In the current implementation, approximately 60% train, 20% calibration, and 20% benign test.
2. **Preprocess without leakage:** Numeric features are imputed and standardized using benign training rows only. Labels, family labels, identifiers, and timestamps are excluded from model features.
3. **Train:** Fit each anomaly detector on benign training rows only. Attack labels are not used to fit the unsupervised detectors.
4. **Calibrate:** Choose a threshold using only benign calibration scores, for target false-positive budgets of 1% and 0.1%.
5. **Evaluate LOFO:** For each of six attack families, score that family together with the disjoint benign test rows. Repeat over three seeds. Held-out attack families are not used for fitting, fusion weights, or threshold selection.
6. **Report:** Recall per family and macro recall, worst-family recall, benign test FPR, AUROC/AUPR, and runtime. The saved metrics—not hand-entered values—are the source for research tables.

All six observed attack categories are listed as final held-out families in `configs/family_schedule.json`; there are no development families in this first fixed-baseline protocol. The family rotation is performed one family at a time. Be clear that the protocol is a single-dataset pilot.

## 4. Models: what they do and why they are included

### Isolation Forest

An ensemble method that isolates unusual observations by randomly splitting feature space. Shorter isolation paths tend to indicate unusual records. It is a fast, established non-neural baseline and gives a useful check that the pipeline works. It is not trained as a malicious-traffic classifier.

### PCA reconstruction

Principal Component Analysis learns a lower-dimensional representation of benign training traffic. The score is the average squared reconstruction error: records that are poorly reconstructed are considered more anomalous. It is a linear baseline and gives a simple comparison to tree-based Isolation Forest.

### Autoencoder

A small feed-forward neural network learns to reconstruct benign training records. Its anomaly score is mean squared reconstruction error. It tests whether a nonlinear reconstruction model helps. It uses CPU PyTorch and costs more to train than the classical baselines.

### Rank fusion (Isolation Forest + PCA)

Each component’s score is converted to a percentile using benign calibration scores; the two percentiles are averaged with equal weights. This combines different notions of unusualness without interpreting raw scores as probabilities. Equal weighting is fixed in advance; it was not tuned using held-out attack labels.

### Alternatives considered

One-Class SVM, Local Outlier Factor, ECOD/COPOD, GMM/Mahalanobis, Kitsune-like ensembles, and a supervised known-attack classifier with an unknown-rejection rule are possible additions. We have not implemented/evaluated those here. Recurrent/Transformer/GNN models were not prioritized because these data are tabular flow summaries without sequence or graph structure in the current setup.

## 5. Main full-data LOFO findings

The following is the saved full-data comparison for Isolation Forest, PCA, and fusion. Values are mean macro recall across the six held-out family trials, with seeds averaged within family trials.

| Detector | Macro recall at 0.1% target FPR | Macro recall at 1% target FPR | Worst-family recall |
|---|---:|---:|---:|
| Isolation Forest | 0.0% | 9.0% | 0.0% at both budgets |
| PCA reconstruction | 5.3% | 19.2% | 0.0% at both budgets |
| IF + PCA rank fusion | 7.4% | 15.3% | 0.0% at both budgets |

Mean observed benign-test FPRs were close to targets: about 0.09–0.10% at the 0.1% budget, and 0.99–1.01% at the 1% budget. PCA had the highest macro recall at 1%; fusion had the highest at 0.1%. Every method missed at least one held-out family completely at each budget. Friedman comparisons across six family blocks did not show a statistically significant difference (p=0.097 at 0.1%, p=0.094 at 1%). This is insufficient evidence to distinguish methods, not proof they are equivalent.

The autoencoder LOFO run is separate and **exploratory**: it capped the sample at 50,000 rows per family due to CPU runtime. Macro recall was 3.4% at the 0.1% target budget and 21.5% at 1%, with worst-family recall of 0% and 0.03%, respectively. Its sample prevalence differs from the full dataset, so its AUPR/precision should not be compared directly to full-data metrics.

### Important demo comparison distinction

`results/replay/replay_balanced_sample.csv` contains 1,000 rows per category (1,000 benign plus 1,000 from each attack category). On this deliberately balanced replay sample, the saved comparison showed:

| Model | Attack recall on balanced replay | Benign FPR on balanced replay |
|---|---:|---:|
| Isolation Forest | 9.1% | 0.2% |
| PCA reconstruction | 19.6% | 1.7% |
| IF + PCA fusion | 15.9% | 0.2% |
| Autoencoder | 22.3% | 1.3% |

This is a dashboard demonstration on a balanced sample, not the main LOFO benchmark. Because attack prevalence was intentionally increased, alert rate and precision do not represent a real network. These alert counts are not proof that the autoencoder is “best”; compare the fixed-FPR LOFO results for the research question.

## 6. Metrics in plain language

- **Anomaly score:** A model-specific measure of unusualness. A higher score means “less like the learned benign pattern.” It is not a calibrated probability of attack, and scores are not comparable across different models unless transformed.
- **Threshold:** The cutoff chosen from benign calibration scores. A flow beyond it is flagged.
- **Alert:** A flow whose score crosses the saved threshold. It means “review this unusual flow,” not “confirmed attack.”
- **Alert rate:** Alerts divided by all scored flows in the uploaded file. It depends on the file’s class mix and is not the same as FPR.
- **Attack recall:** Of the labeled attack flows in an evaluation file, the fraction flagged: `attack alerts / attack flows`. High recall means fewer attacks were missed.
- **Benign FPR (false-positive rate):** Of labeled benign flows, the fraction incorrectly flagged: `benign alerts / benign flows`. A lower FPR means fewer benign flows create alerts.
- **Target FPR / alert budget:** The desired fraction of benign calibration records allowed to exceed the threshold (1% or 0.1%). It is a calibration target; measured test FPR can differ slightly.
- **Macro family recall:** Compute recall separately for each held-out family, then average the family recalls equally. This prevents large categories from dominating the summary.
- **Worst-family recall:** The lowest family-level recall. It highlights a method’s blind spot.
- **AUROC/AUPR:** Ranking measures across thresholds. They do not specify the operating threshold. AUPR depends strongly on attack prevalence, so balanced replay AUPR is not representative of normal traffic prevalence.

## 7. Dashboard: exactly what goes in

Open the local dashboard at `http://localhost:8501` while its Streamlit process is running.

### Compare models (recommended for the demo)

1. In the sidebar, check **Compare all available local models**.
2. Under **Flow records**, upload `results/replay/replay_balanced_sample.csv`.
3. The app locally loads each available model bundle, scores the same uploaded rows, and displays alert counts, alert rate, attack recall, and benign FPR. It can download a comparison CSV.

You do not upload a model bundle in this mode. The app uses the four model bundle files already present in the local `models/` folder.

### Score one model

1. Leave **Compare all available local models** unchecked.
2. Either choose one entry in **Or select a locally trained model**, or leave it as “Upload a model” and upload one `.joblib` bundle under **Model bundle**.
3. Upload `results/replay/replay_balanced_sample.csv` (or another CSV/Parquet that contains all 52 trained features) under **Flow records**.
4. Inspect alerts and, if `Label` exists, the replay recall and benign FPR.

Local bundles (one model per file):

- `models/replay.joblib` — Isolation Forest (historical default filename)
- `models/replay_pca.joblib` — PCA reconstruction
- `models/replay_fusion.joblib` — IF + PCA rank fusion
- `models/replay_autoencoder.joblib` — autoencoder

Each bundle stores one fitted detector (or fusion components), the training-fitted imputer and scaler, feature names, threshold, tie rule, target FPR, model name, and seed. Bundles are generated locally and intentionally excluded from the public GitHub repository. The dashboard cannot score a CSV that lacks the model’s 52 feature columns. A scored output CSV is not valid fresh input because it does not contain those original feature columns.

## 8. Repository and local files

Public code repository: https://github.com/git-sakshii/ZeroDayAttack

- `src/zerodayshield/` — implementation (detectors, preprocessing, experiment runner, replay scorer, dashboard).
- `configs/protocol.json` — experiment rules and fixed settings.
- `configs/family_schedule.json` — dataset checksum and declared family rotation.
- `DATASETS.md` — dataset provenance and audit notes.
- `requirements*.txt`, `pyproject.toml` — environment/dependencies.
- `models/*.joblib` — local trained bundles; ignored by Git.
- `data/raw/`, `data/processed/` — local dataset files; ignored by Git.
- `results/` — local run CSVs, summaries and figures; ignored by Git.

The public repo contains source, protocol/configuration, and documentation. It does not contain the user’s downloaded dataset, local model bundles, local results, or virtual environment.

## 9. What is built and what remains

**Built:** data preparation/audit code, Isolation Forest/PCA/autoencoder/fusion detectors, fixed-protocol LOFO runner, result analysis, replay train-and-score CLI, four local replay bundles, and a Streamlit dashboard with single-model scoring and side-by-side local-model comparison.

**Not yet built/finished:** live packet capture and compatible live flow-feature extraction; supervised classifier with an unknown-rejection rule; cross-dataset validation; full-data autoencoder LOFO; independent external validation; production hardening. The dashboard currently replays saved flow records and should not be described as live monitoring.

## 10. Likely instructor questions and short answers

**Q: Why call this zero-day detection if no real zero-day data exists?**  
A: We do not claim to test true zero-days. We hold out complete attack families as a reproducible proxy for previously unseen attack types and state that limitation.

**Q: Why train only on benign traffic?**  
A: The central methods are anomaly detectors that learn a baseline of normal traffic, so they can score deviations without needing examples of every attack family.

**Q: Why report FPR next to recall?**  
A: A detector could catch many attacks by flagging almost everything. FPR shows the benign-traffic alert cost of the recall.

**Q: Does a 1% target mean 99% accuracy?**  
A: No. It is the intended benign calibration exceedance rate used to choose the threshold. Accuracy is a different metric.

**Q: Is an alert an attack probability?**  
A: No. It is a thresholded anomaly score and a lead for investigation.

**Q: Which model won?**  
A: No one model won at both operating points. PCA had highest macro recall at the 1% target; fusion led at 0.1%. Differences were not statistically significant in the six-family comparison, and worst-family recall was zero for all three full-data methods.

**Q: Why did the dashboard balanced replay autoencoder have the most recall?**  
A: That is a small, intentionally balanced demonstration file, not the fixed-FPR LOFO comparison. It also had a higher benign FPR. We should not use it alone to declare a winner.

**Q: Did the models use attack labels for training?**  
A: The unsupervised anomaly models were fit on benign training rows. Labels were used to create held-out-family evaluation groups and calculate evaluation metrics, not to fit or calibrate the detectors.

**Q: What is the main weakness today?**  
A: Generalization is weak for some held-out families at low false-positive budgets; dataset provenance is not fully verified; and live capture/cross-dataset evaluation are not done yet.

**Q: Is it ready to block attacks?**  
A: No. It is a research prototype that flags anomalous flows for review. It does not block traffic and has not been validated as a production security control.

## 11. Suggested presentation order

1. Problem and research question.
2. Dataset and honest limits of the Kaggle-prepared derivative.
3. Benign-only training, leakage-safe preprocessing, calibration, and family holdout.
4. Four model approaches and why they differ.
5. Main LOFO table at 0.1% and 1% FPR.
6. Explain the statistical result and zero worst-family recall.
7. Demonstrate dashboard comparison using the balanced replay CSV; label it as a demo.
8. Limitations and next steps: verify dataset provenance, cross-dataset test, supervised rejection reference, and feature-compatible live capture.

## 12. Source-of-truth files for reported numbers

- Full-data three-model metrics: `results/cicids2017_core/lofo_metrics.csv`
- Full-data summary: `results/cicids2017_analysis/summary.md`
- Autoencoder exploratory summary: `results/cicids2017_autoencoder_sampled/analysis/summary.md`
- Balanced dashboard replay comparison: `results/replay/balanced_model_comparison.csv`
- Dataset audit: `data/processed/cicids2017_cleaned.audit.json`
- Run metadata and checksums: `results/cicids2017_core/run.json`

All data and result paths above are local files and are not in the public repository. Recreate them by obtaining the dataset and following the repository README.
