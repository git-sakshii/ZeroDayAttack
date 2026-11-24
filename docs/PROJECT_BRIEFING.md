# ZeroDayShield v2 — Project Briefing

**Prepared for:** team presentation and instructor questions  
**Project type:** research prototype for flow-based network anomaly detection  
**Status:** the offline research pipeline, replay dashboard, experimental live-flow scoring path, both CICIDS2017/UNSW-NB15 transfer directions, and a sampled supervised known-attack/unknown-rejection reference are implemented. An IEEE-style two-column paper draft, Word file, and PDF have been prepared with project results, diagrams, and tables. Synthetic-PCAP feature mapping and scoring were smoke-checked. Real interface capture has not been validated because a packet-capture provider is not detected on the Windows machine.

## 1. Project in one minute

ZeroDayShield compares detectors trained on benign network-flow records. The research question is whether a detector can flag traffic from an attack family it did not see during training, and how many benign records it flags along the way. We approximate a “new” attack by holding out one complete labeled attack family for testing. This is a zero-day-style benchmark proxy, not a real zero-day test.

We implemented Isolation Forest, PCA reconstruction error, a small autoencoder, and equal-weight rank fusion of Isolation Forest and PCA. We calibrated thresholds using a separate benign calibration split, then evaluated attack recall and benign false-positive rate. The Streamlit dashboard scores uploaded flow records and can display a local stream of scored live flow summaries when the optional capture process is running. Live packet capture requires Npcap and administrator permission on Windows and is not yet validated on the team's real network.

### The most important idea: what “zero-day” means here

Your original idea is a **benign-only anomaly detector**: learn patterns from normal network traffic, then flag records that look sufficiently different. The IF, PCA, and autoencoder detectors follow that idea. They do not need examples of every kind of attack in order to produce an unusualness score.

The hard part is proving that they catch something genuinely new. A public dataset cannot contain an unknown future exploit that has never existed or been recorded. So our experiment uses a limited proxy: take a known attack family in CICIDS2017, hide every row from that family during fitting and threshold selection, then ask whether the frozen detector flags those rows. The family is known to the researchers because its labels are needed to evaluate recall, but it is withheld from the detector. This tests generalization to a withheld category. It does **not** prove detection of arbitrary novel behavior, a real zero-day exploit, or every attack that differs from normal traffic.

Think of the workflow as: **learn normal → choose a cautious cutoff using separate normal examples → freeze the system → show it a withheld family and normal test records → count detected attacks and wrongly flagged normal records.** The model produces an anomaly score; the threshold turns that score into an alert. The alert means “unusual; review it,” not “confirmed malicious.”

For the CIC-to-UNSW experiment, there is an additional question: if we train and set the cutoff on one dataset, does the cutoff behave similarly on a second dataset? It often did not. The test checks portability and alert drift, not whether UNSW is a real zero-day set.

## 2. Dataset and preparation

The local dataset is the user-supplied **CICIDS2017: Cleaned & Preprocessed** derivative from Kaggle, by Eric Anacleto Ribeiro (`ericanacletoribe`). The public Kaggle metadata API lists version 6 and the license label “CC0: Public Domain.” Its description says the publisher merged CICIDS2017 CSVs, removed duplicate rows/columns, handled infinite/missing values, normalized whitespace, performed feature selection, grouped labels, and removed rare Infiltration and Heartbleed labels. These are the publisher's documented steps and license declaration; our team did not independently reproduce the complete cleaning or perform a legal review. It is not confirmed as the official corrected LycoS release. Cite the Kaggle derivative and the original CICIDS2017 paper separately.

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

We also evaluated transfer to a public mirror copy of the UNSW-NB15 fixed test partition: 82,332 rows, including 37,000 benign and 45,332 attacks across nine attack categories. The row counts, normal/attack counts, labels, and feature layout were checked against the documented partition profile. SHA-256 hashes pin the exact mirror copies; UNSW does not publish checksums, so the copies are not independently authenticated byte-for-byte against provider files. The local files are not committed to the public repository; download provenance, full SHA-256 values, and the citation are in `DATASETS.md` and `results/cross_dataset_unsw/cross_dataset_run.json`.

## 3. How the experiment works

1. **Split benign rows:** Each seed (17, 29, 43) makes a deterministic benign-only train, calibration, and benign-test split. In the current implementation, approximately 60% train, 20% calibration, and 20% benign test.
2. **Preprocess without leakage:** Numeric features are imputed and standardized using benign training rows only. Labels, family labels, identifiers, and timestamps are excluded from model features.
3. **Train:** Fit each anomaly detector on benign training rows only. Attack labels are not used to fit the unsupervised detectors.
4. **Calibrate:** Choose a threshold using only benign calibration scores, for target false-positive budgets of 1% and 0.1%.
5. **Evaluate LOFO:** For each of six attack families, score that family together with the disjoint benign test rows. Repeat over three seeds. Held-out attack families are not used for fitting, fusion weights, or threshold selection.
6. **Report:** Recall per family and macro recall, worst-family recall, benign test FPR, AUROC/AUPR, and runtime. The saved metrics—not hand-entered values—are the source for research tables.

All six observed attack categories are listed as final held-out families in `configs/family_schedule.json`; there are no development families in this first fixed-baseline protocol. The family rotation is performed one family at a time. This 52-feature LOFO comparison is a single-dataset pilot; the separate nine-feature CIC-to-UNSW transfer experiment is described in Section 5A.

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

One-Class SVM, Local Outlier Factor, ECOD/COPOD, GMM/Mahalanobis, and Kitsune-like ensembles remain possible additions. We also implemented a sampled supervised HistGradientBoosting known-attack/unknown-rejection reference; see its limited results below. Recurrent/Transformer/GNN models were not prioritized because these data are tabular flow summaries without sequence or graph structure in the current setup.

## 4.1 Related research: Shone et al. (2018)

The team found a related IEEE paper: Nathan Shone, Tran Nguyen Ngoc, Vu Dinh Phai, and Qi Shi, “A Deep Learning Approach to Network Intrusion Detection,” *IEEE Transactions on Emerging Topics in Computational Intelligence*, vol. 2, no. 1, pp. 41–53, 2018, DOI: 10.1109/TETCI.2017.2772792. It introduces a non-symmetric deep autoencoder (NDAE) for unsupervised feature learning and combines stacked NDAEs with a Random Forest classifier. Its experiments use KDD Cup ’99 and NSL-KDD, and report classification metrics such as accuracy, precision, recall, F-score, and false-alarm rate.

This is useful background for motivating autoencoder-based network intrusion detection and for discussing the use of older benchmark datasets. It is not a direct baseline for our main results: the paper evaluates labeled multi-class classification on KDD Cup ’99 and NSL-KDD, whereas our primary question evaluates benign-only anomaly detectors on whole attack families held out from fitting and threshold calibration in a CICIDS2017 derivative. Its reported results belong to its authors and must not be presented as ZeroDayShield results. The authors explicitly list assessing the model’s zero-day capability as future work, so it does not provide evidence that their method detects unseen attack families under our protocol.

**IEEE reference:** N. Shone, T. N. Ngoc, V. D. Phai, and Q. Shi, “A deep learning approach to network intrusion detection,” *IEEE Transactions on Emerging Topics in Computational Intelligence*, vol. 2, no. 1, pp. 41–53, Feb. 2018, doi: 10.1109/TETCI.2017.2772792.

## 5. Main full-data LOFO findings

The following is the saved full-data comparison for Isolation Forest, PCA, and fusion. Values are mean macro recall across the six held-out family trials, with seeds averaged within family trials.

| Detector | Macro recall at 0.1% target FPR | Macro recall at 1% target FPR | Worst-family recall |
|---|---:|---:|---:|
| Isolation Forest | 0.0% | 9.0% | 0.0% at both budgets |
| PCA reconstruction | 5.3% | 19.2% | 0.0% at 0.1%; 0.0022% at 1% |
| IF + PCA rank fusion | 7.4% | 15.3% | 0.0% at both budgets |

Mean observed benign-test FPRs were close to targets: about 0.09–0.10% at the 0.1% budget, and 0.99–1.01% at the 1% budget. PCA had the highest macro recall at 1%; fusion had the highest at 0.1%. Five of the six method-budget pairs had exactly zero worst-family recall; PCA reached only 0.0022% for its lowest-recall family at the 1% budget. Friedman comparisons across six family blocks did not show a statistically significant difference (p=0.097 at 0.1%, p=0.094 at 1%). The family blocks reuse benign partitions, so treat this as exploratory evidence, not proof that the methods are equivalent.

The autoencoder LOFO run is separate and **exploratory**: it capped the sample at 50,000 rows per family due to CPU runtime. Macro recall was 3.4% at the 0.1% target budget and 21.5% at 1%, with worst-family recall of 0% and 0.03%, respectively. Its sample prevalence differs from the full dataset, so its AUPR/precision should not be compared directly to full-data metrics.

## 5A. Cross-dataset experiment: CICIDS2017 to UNSW-NB15

We reran Isolation Forest, PCA, and rank fusion on a nine-feature semantic intersection, allowing a within-CIC reference and a CIC-to-UNSW transfer comparison in the same input space. The features cover duration, directional packet/byte measurements, mean packet lengths, flow byte rate, and TCP initial window sizes. CIC duration was converted from microseconds to seconds; CIC backward packet count and UNSW total flow byte rate were derived using the documented formulas. Argus/Bro and CICFlowMeter compute flow features differently, so this mapping remains approximate.

The models and preprocessors were fit using CIC benign training rows only. Thresholds were calibrated on CIC benign calibration rows only, then frozen for scoring the entire fixed UNSW-NB15 test-partition mirror. UNSW labels were evaluation-only. Values below average three seeds; these repeat the same public benchmark and do not represent independent network captures. “Target FPR” means the CIC calibration target. The final column is the measured benign FPR on UNSW, which can shift.

| CIC calibration target | Model | CIC macro family recall | UNSW macro family recall | CIC benign test FPR | UNSW benign test FPR |
|---:|---|---:|---:|---:|---:|
| 0.1% | Isolation Forest | 0.10% | 0.28% | 0.095% | 0.197% |
| 0.1% | PCA reconstruction | 0.64% | 1.31% | 0.097% | 1.185% |
| 0.1% | IF + PCA rank fusion | 0.72% | 0.78% | 0.099% | 0.992% |
| 1.0% | Isolation Forest | 1.06% | 2.10% | 0.988% | 5.903% |
| 1.0% | PCA reconstruction | 1.32% | 3.35% | 0.997% | 6.331% |
| 1.0% | IF + PCA rank fusion | 1.06% | 3.04% | 0.984% | 7.560% |

The external UNSW FPR rose above the CIC calibration target for every method and budget. The higher UNSW macro recall therefore does not mean transfer improved detection at a controlled false-alarm cost: the frozen thresholds also flagged more benign UNSW flows. Worst-family recall was zero for each method in both datasets. Treat this as a descriptive result for one transfer direction; attack-family definitions differ between datasets, and this nine-feature run is separate from the 52-feature primary experiment.

## 5B. Reverse transfer: UNSW-NB15 to CICIDS2017

We also reversed the direction. Isolation Forest, PCA reconstruction, and equal-weight rank fusion were fit using only benign rows from the UNSW-NB15 training partition; preprocessing used those benign training rows and thresholds used a separate benign calibration split. The frozen scores were evaluated on the CIC Kaggle derivative and on the fixed UNSW test partition. Both datasets use the same nine approximate semantic features described above. The 0.1% and 1% values are calibration targets, not guaranteed test FPRs.

| Evaluation set | Calibration target | Model | Macro family recall | Worst-family recall | Mean benign FPR |
|---|---:|---|---:|---:|---:|
| CIC derivative | 0.1% | Isolation Forest | 0.08% | 0.00% | 0.16% |
| CIC derivative | 0.1% | PCA reconstruction | 66.98% | 15.60% | 39.61% |
| CIC derivative | 0.1% | IF + PCA rank fusion | 0.62% | 0.00% | 0.54% |
| CIC derivative | 1.0% | Isolation Forest | 0.68% | 0.00% | 0.41% |
| CIC derivative | 1.0% | PCA reconstruction | 72.87% | 45.09% | 43.61% |
| CIC derivative | 1.0% | IF + PCA rank fusion | 6.50% | 0.01% | 11.39% |

The standout PCA recall is accompanied by an unusably high benign alert rate on CIC; it is not a controlled-cost win. The same-domain UNSW test behaved much closer to its calibration targets: mean benign FPRs were 0.12%, 0.23%, and 0.20% for IF, PCA, and fusion at the 0.1% target, and 0.83%, 2.06%, and 1.56% at the 1% target. This asymmetry illustrates dataset and feature-distribution shift. The exact per-family CSVs and run protocol are local under `results/cross_dataset_reverse/`; this result is one public-benchmark transfer direction, not independent real-network evidence.

## 5C. Supervised known-attack classifier with unknown rejection

This contrasting strategy uses benign traffic plus labeled examples from the attack families considered known during training. For each LOFO fold, one complete attack family is excluded from training; the classifier is a HistGradientBoosting model. A high predicted known-attack score or low confidence across learned classes contributes to the unusualness score. The alert cutoff is still set using only a separate benign calibration split. Thus it does not use held-out test labels to choose the cutoff, but it does use labels for the other attack families during fitting.

The run uses three seeds, six held-out families, up to 1,000 training rows per class, and 15 boosting iterations. It is a CPU-friendly exploratory setting, not a tuned or full-data supervised result.

| Calibration target | Macro family recall | Worst family after averaging seeds | Mean benign test FPR |
|---:|---:|---:|---:|
| 0.1% | 3.52% | 0.00% | 0.094% |
| 1.0% | 15.12% | 0.28% | 1.002% |

At the 1% target, recall was strongest on held-out DDoS (62.3%) and weakest on web attacks (0.28%). At 0.1%, it detected almost none of the held-out families consistently. Across the six family blocks, a four-model Friedman comparison with IF, PCA, and fusion gave p=0.158 at the 0.1% target and p=0.054 at 1%; neither crosses the conventional 0.05 significance threshold. Six blocks give limited statistical power, and the supervised model uses sampled training rows, so treat this as exploratory. Saved metrics and settings are in `results/supervised_rejection/`.

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

**Remaining:** validate live capture on an authorized Windows interface after installing/configuring a packet-capture provider; run full-data autoencoder LOFO if time and compute allow; obtain independent real-network validation; and apply any venue-specific paper requirements. The IEEE-style paper draft is complete as a project-results draft, but the team still needs to fill the course, instructor, venue, and any required AI-assistance statement, then check the final venue template and submission rules. The capture/scoring code path exists and a synthetic PCAP confirmed feature mapping and scoring for one example flow, but this is not evidence of a working real-network live demo. Do not describe it as validated live monitoring until an authorized interface capture succeeds and its benign alert behavior is recorded.

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
A: No one model won at both operating points. PCA had highest macro recall at the 1% target; fusion led at 0.1%. Differences were not statistically significant in the six-family comparison. Worst-family recall was zero for all methods at 0.1%; at 1%, it was zero for Isolation Forest and fusion and 0.0022% for PCA.

**Q: Why did the dashboard balanced replay autoencoder have the most recall?**  
A: That is a small, intentionally balanced demonstration file, not the fixed-FPR LOFO comparison. It also had a higher benign FPR. We should not use it alone to declare a winner.

**Q: Did the models use attack labels for training?**  
A: The unsupervised anomaly models were fit on benign training rows. Labels were used to create held-out-family evaluation groups and calculate evaluation metrics, not to fit or calibrate the detectors.

**Q: If the attack family was never used for training, how did you test detection?**  
A: The model did not see that family during fitting or threshold calibration. After freezing the model and threshold, we used the family labels only to check which flows were detected and calculate recall. This tests generalization to a known benchmark category withheld from the model; it is not a real newly discovered exploit.

**Q: Does “unseen” mean we hid all examples of a real exploit from an actual network?**  
A: No. We held out all examples of one labeled family in this dataset. That is a controlled proxy for category novelty; we do not have a true zero-day sample.

**Q: What exactly did we train?**  
A: The primary IF, PCA, and fusion detectors learned from benign CICIDS2017 flow records. We split benign rows into training, calibration, and benign test portions. The autoencoder also learned from benign data, but its LOFO result used a capped sample and is exploratory. In the separate transfer experiment, IF, PCA, and fusion were trained on benign CIC data using a nine-feature mapping before being tested on the UNSW mirror partition.

**Q: When I say “we train on unseen data,” is that right?**  
A: Say instead: “We train the detectors on benign data. During evaluation, we withhold an entire labeled attack family from fitting and cutoff selection, then test whether the frozen detectors flag it.” The attack family is unseen by the model, not unknown to the dataset or research team.

**Q: Is the project doing my original idea?**  
A: Partly. The benign-only detectors learn a normal-traffic baseline and flag departures, which is the core idea. The held-out-family test checks whether they generalize beyond attack families used by the model. The benchmark does not prove detection of arbitrary zero-day attacks. The dashboard scores saved flow records, and an experimental live scoring path exists, but real interface capture remains unvalidated.

**Q: Why might a real new attack still be missed?**  
A: An attack can resemble normal traffic in the features we measure. A detector can only flag deviations that its features and learned boundary make visible. Stealthy attacks may look normal in flow summaries, and benign traffic that changes may look anomalous. We observed very low or zero recall for some held-out families, which is exactly why we avoid claiming universal zero-day detection.

**Q: Why use attack labels at all if training is benign-only?**  
A: Labels let us set aside whole families for the benchmark and later count true detections and misses. They do not teach the unsupervised detector what an attack looks like.

**Q: What is the main answer to our research question?**  
A: There is no universal winner in this experiment. PCA had the highest macro recall at the 1% target, 19.2%; rank fusion led at the 0.1% target, 7.4%. But some family recall was zero or nearly zero for every model and budget, and method differences were not statistically significant across six family blocks. We can say “best among those tested under this protocol,” not “best zero-day detector.”

**Q: What does “the threshold transfers poorly” mean?**  
A: We chose thresholds using benign CIC calibration records, froze them, and applied them to the UNSW test mirror. On UNSW, benign FPR rose as high as about 7.56% when the CIC calibration target was 1%. This means more benign flows were flagged in the target dataset; a percentage calibrated on one dataset is not guaranteed on another.

**Q: What does the dashboard actually do?**  
A: It loads a previously trained local model bundle and a CSV/Parquet of flow records, calculates each record’s score, and flags records whose scores cross the stored cutoff. In comparison mode it scores the same uploaded file with available local models. The balanced replay CSV is only a demonstration. The dashboard can display scored live flow summaries when the experimental capture path is running, but that path has not been validated on a real interface. It does not prove an attack or block traffic.

**Q: Is “alert rate” the same as false-positive rate?**  
A: No. Alert rate is all flagged rows divided by all rows. FPR is flagged benign rows divided by all benign rows. Recall is flagged attack rows divided by all attack rows. They have different denominators.

**Q: Why is high recall alone not enough?**  
A: A detector could obtain high recall by flagging nearly every record. FPR measures that benign alert cost. We compare recall at calibration targets of 0.1% and 1%, then report the measured benign test FPR as well.

**Q: Are model scores probabilities?**  
A: No. IF path-based scores, PCA reconstruction errors, and autoencoder reconstruction errors are different measures of unusualness. We threshold them; we do not interpret them as attack probabilities.

**Q: Why does the autoencoder have a high replay recall but not lead the main results?**  
A: Replay used a balanced, capped demonstration sample and each bundle had a fixed threshold. The autoencoder alerted more benign records there. Its separate capped LOFO experiment is exploratory and is not a like-for-like full-data comparison. We should not choose a winner from that replay result.

**Q: Are the result differences statistically proven?**  
A: No. Friedman p-values were about 0.097 and 0.094, with six family blocks, and no Nemenyi pairwise result was significant. Those family trials reuse benign partitions and have limited independence and statistical power, so the results are exploratory; “not significant” does not prove models are equivalent.

**Q: What was checked about the datasets?**  
A: For CIC, we inspected rows, labels, features, duplicates, and conflicting feature-identical labels, but we did not independently recreate the Kaggle publisher’s full cleaning process or audit the license. For UNSW, documented partition counts and labels were checked and SHA-256 hashes pin the exact mirror copies we used. UNSW does not publish those hashes, so we cannot claim the files were authenticated byte-for-byte against the provider’s originals.

**Q: What is missing before this becomes a stronger system?**  
A: Full-data autoencoder, a broader/tuned supervised-reference comparison, real-interface validation of the experimental capture path, and evaluation on a genuinely independent network. Live capture should only be attempted on a network we own or are authorized to monitor. Until Npcap and a real authorized capture are confirmed, use offline replay for the demo.

**Q: Did you complete live capture?**
A: We added an experimental capture-to-flow-to-score code path and checked feature mapping on a synthetic PCAP. It writes a privacy-minimized scored-flow file without raw packets or endpoint IPs. We have not validated it on a real interface: Npcap is not currently detected on the Windows machine, and no real-network alert results are available. We should describe this as implemented but not yet operationally validated.

**Q: What did the cross-dataset experiment show?**
A: We trained and calibrated on CIC benign traffic, then froze the pipeline for the fixed UNSW-NB15 test-partition mirror using nine mapped features. CIC-calibrated thresholds did not preserve their FPR on UNSW: observed benign FPR reached about 5.9–7.6% at the 1% calibration target. The feature mapping and datasets are imperfect testbed proxies, so this is a limited transfer result.

**Q: What did the reverse transfer show?**
A: Training and calibrating on benign UNSW records then testing on CIC produced severe alert drift for PCA and fusion. PCA's macro recall was high only alongside a 39.6–43.6% benign FPR on CIC. This is not evidence that it is a better detector; it shows that transfer can break the alert budget. Both directions use public benchmark datasets and approximate feature mapping.

**Q: What is the main weakness today?**  
A: Generalization is weak for some held-out families at low false-positive budgets; transfer causes substantial false-alarm drift; and the experimental capture code has not been validated against a real network interface.

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
8. Both cross-dataset transfer directions and the exploratory supervised rejection result.
9. Paper status and limitations: the IEEE-style draft is prepared; explain that full-data autoencoder results and real-interface capture validation remain incomplete, and leave venue-specific formatting until the venue is known.

## 12. Research paper status and contents

An IEEE-style, two-column A4 paper draft has been prepared from the saved project results. It includes the research questions, protocol and dataset limitations, the benign-only and supervised-with-rejection approaches, both transfer directions, the exploratory statistical comparisons, and the live-capture validation status. The draft includes three figures (LOFO protocol flow, system architecture, and family-recall heatmap) and tables for dataset/profile details, mapped features, primary LOFO results, supervised results, both transfer directions, and system validation. The team should verify author details and citations, fill in course/instructor/venue and any required AI-assistance disclosure, and apply the official venue template once known. No claim of true zero-day detection or validated real-network capture is made.

- Editable source: `paper/PAPER_DRAFT.md`
- Word draft: `paper/ZeroDayShield_Research_Paper.docx`
- PDF draft: `paper/ZeroDayShield_Research_Paper.pdf`
- Figure sources and generation scripts: `paper/figures/`, `paper/build_figures.py`, and `paper/build_ieee_paper.py`

## 13. Source-of-truth files for reported numbers

- Full-data three-model metrics: `results/cicids2017_core/lofo_metrics.csv`
- Full-data summary: `results/cicids2017_analysis/summary.md`
- Autoencoder exploratory summary: `results/cicids2017_autoencoder_sampled/analysis/summary.md`
- Balanced dashboard replay comparison: `results/replay/balanced_model_comparison.csv`
- Cross-dataset family metrics, means, and summary: `results/cross_dataset_unsw/cross_dataset_family_metrics.csv`, `cross_dataset_family_means.csv`, and `cross_dataset_summary.csv`
- Cross-dataset input hashes and run metadata: `results/cross_dataset_unsw/cross_dataset_run.json`
- Reverse transfer family metrics, summary, protocol, and run metadata: `results/cross_dataset_reverse/`
- Supervised reference metrics, summary, protocol, and run metadata: `results/supervised_rejection/`
- Dataset audit: `data/processed/cicids2017_cleaned.audit.json`
- Run metadata and checksums: `results/cicids2017_core/run.json`

All data and result paths above are local files and are not in the public repository. Recreate them by obtaining the dataset and following the repository README. The paper source and rendered Word/PDF drafts are tracked in the repository under `paper/`; final venue-specific formatting and any required course disclosure remain for the team to complete.

