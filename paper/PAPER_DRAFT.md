# Evaluating Benign-Only Anomaly Detectors on Held-Out Network Attack Families

**Sakshi Singh, Rushil Chaudhary, Zoya Parveen, Yashsvi Sharma**  
Department of Computer Science and Engineering (Artificial Intelligence), Galgotias College of Engineering & Technology, Greater Noida, India  
**Course / instructor:** [fill in]  
**Citation style:** IEEE (assumed; confirm with instructor)

## Abstract

Network intrusion detectors are often evaluated on attack classes represented during training, which does not directly measure behavior on an unseen attack category. This study compares three benign-only anomaly-detection strategies on a Kaggle-prepared CICIDS2017 derivative using leave-one-attack-family-out (LOFO) evaluation. Isolation Forest, PCA reconstruction error, and equal-weight rank fusion were trained using benign traffic only. Thresholds were calibrated using separate benign calibration data at target false-positive rates (FPRs) of 0.1% and 1%. The dataset contains 2,519,196 retained flow records, 52 numeric features, and six aggregated attack families. Across six held-out-family trials, PCA produced the highest macro recall at the 1% target FPR (19.2%); rank fusion was highest at 0.1% (7.4%). Worst-family recall was zero for all methods at both operating points. Friedman tests did not identify statistically significant differences among the methods (p=0.094–0.097, six family blocks). These findings show that benchmark-level discrimination and operational alert budgets can leave substantial blind spots on some held-out families. The results are a single-dataset pilot: the Kaggle derivative's publisher documents its cleaning pipeline and declares a CC0 license, but we did not independently audit the preprocessing or conduct a legal review; held-out families are a zero-day-style proxy rather than real zero-day attacks.

**Keywords:** network intrusion detection; anomaly detection; CICIDS2017; held-out families; false-positive rate; score fusion

## 1. Introduction

Network intrusion detection systems increasingly use machine learning to identify suspicious activity in flow records. A central difficulty is generalization: a model may perform well on attacks similar to its training examples yet fail when it encounters a different attack family. In operational settings, false alarms also matter. A detector that flags many benign flows may overwhelm analysts even if it catches a portion of attacks [1].

This work asks: **Among the tested benign-only anomaly detectors, which achieves the strongest recall on attack families excluded from model fitting at a fixed benign false-alarm budget?** We use whole-family holdout as a reproducible zero-day-style proxy. A real zero-day is not present in the benchmark; therefore this paper does not claim real zero-day detection.

We compare Isolation Forest, PCA reconstruction error, and equal-weight rank fusion. We train on benign rows only, fit preprocessing on training rows only, choose alert thresholds on benign calibration rows only, and report false-positive rate with recall. Our contributions are (1) a reproducible flow-data preparation and LOFO pipeline; (2) a fixed-budget comparison of three established anomaly-scoring approaches; (3) family-level analysis of their blind spots; and (4) an offline replay dashboard for inspecting scores and alerts.

## 2. Related Work

Isolation Forest identifies unusual observations through random recursive partitioning [2]. PCA-based network anomaly detection uses residuals or subspace deviations to find observations that do not fit a learned low-dimensional normal pattern; prior work also highlights its sensitivity to modeling choices [3]. Autoencoder approaches use neural reconstruction error and have been explored in network anomaly detection, including Kitsune [4]. Score fusion can combine complementary rankings but may not improve every family or operating point.

Security ML evaluation requires careful control of leakage, realistic splits, and operational metrics. Arp et al. discuss common methodological pitfalls in machine-learning security research [1]. LOFO evaluation complements random row splits by withholding attack categories, but it remains a dataset proxy and not evidence of performance on real unseen intrusions.

## 3. Research Questions

- **RQ1:** Which detector has the highest macro recall across unseen held-out attack families at fixed benign FPR budgets of 0.1% and 1%?
- **RQ2:** Does equal-weight score fusion improve worst-case held-out-family recall?
- **RQ3:** [Not answered in this paper.] How much does performance degrade across independent datasets? A compatible second dataset has not yet been evaluated.

## 4. Dataset and Preparation

### 4.1 Dataset

We used the user-supplied “CICIDS2017: Cleaned & Preprocessed” Kaggle dataset by Eric Anacleto Ribeiro [5]. Kaggle's public dataset metadata identifies version 6, last updated January 12, 2025, and lists the license as “CC0: Public Domain.” The dataset description reports that original CICIDS2017 CSVs were merged; duplicate rows and columns removed; infinities replaced with missing values; rows with missing values removed; column whitespace normalized; constant and highly correlated features and other features selected out; labels aggregated into broad `Attack Type` categories; and rare Infiltration and Heartbleed labels removed. These are the dataset publisher's documented steps and license declaration; our team did not independently reproduce or audit the publisher's preprocessing or legal status. This is a contributor-prepared derivative and is not confirmed as the official LycoS corrected release. The downloaded file contains 2,520,751 rows, 52 numeric flow features, and the label column `Attack Type`.

### 4.2 Cleaning and label audit

The preparation script normalized label strings, removed 161 exact duplicate rows, and quarantined 1,394 rows across 697 groups whose non-label features were identical while labels conflicted. The prepared Parquet contains 2,519,196 rows: 2,094,199 benign, 193,615 DoS, 128,011 DDoS, 90,130 port scanning, 9,150 brute force, 2,143 web attacks, and 1,948 bots. Automatic normalization is not ground-truth correction. Results are limited to the six aggregate attack labels available in the file.

The Kaggle dataset description links its processing notebook and project repository [7]. The original CICIDS2017 dataset page asks users to cite the dataset paper [6]. The source CSV SHA-256 is `0ce5a39edffcde3fce59d0dc4aabc9b1f6acab2c626fd7163be9c694f224c292`; prepared Parquet SHA-256 is `34c6c45d067bbbfa9d8fc91b40fc6606801c8e103896db08710adff4c41a2be7`. Dataset files are not included in the public repository.

## 5. Methods

### 5.1 LOFO protocol and leakage controls

For each of three random seeds (17, 29, 43), benign rows were deterministically divided into approximately 60% training, 20% calibration, and 20% benign test data. The preprocessing pipeline converts usable features to numeric values, replaces invalid/infinite values with missing values, median-imputes, and standardizes. The imputer and scaler are fit only on benign training rows. Labels, family labels, timestamps, and known identifiers are excluded from model inputs.

Each detector is fit only on benign training rows. For each of the six families, the held-out test set contains all records of that family plus the disjoint benign test partition. Calibration thresholds are chosen from benign calibration scores, never using held-out-family labels. Target budgets are 0.1% and 1%. Model settings and equal fusion weights are fixed in protocol v0.2.0. No attack-family tuning is performed in this first comparison. The schedule rotates each observed attack family as the held-out family; there are no development families in the current frozen schedule.

### 5.2 Detectors

**Isolation Forest (IF).** A tree ensemble that isolates observations through random feature splits [2]. The negative of the implementation’s normality score is used so larger values indicate more anomalous traffic. Settings: 150 estimators and automatic maximum subsample size.

**PCA reconstruction.** PCA is fit to the standardized benign training matrix with 95% explained-variance retention using a full solver. The anomaly score is row-wise mean squared reconstruction error. PCA sensitivity to model and aggregation choices is a known concern [3].

**Rank fusion.** IF and PCA scores are each mapped to empirical percentiles using benign calibration scores. The two percentiles are averaged with equal weight. This fixed fusion avoids directly averaging differently scaled raw scores.

**Autoencoder (exploratory only).** A small dense feed-forward autoencoder (hidden width 32, bottleneck 8, 30 epochs, batch size 512, Adam learning rate 0.001) is also implemented. Kitsune is a related online ensemble of autoencoders for network intrusion detection [4]. Our evaluation used a deterministic stratified sample capped at 50,000 rows per family because full-data CPU training was impractical. It is not included in the full-data three-model statistical comparison.

### 5.3 Metrics and statistics

At each target FPR we report family-level attack recall, macro family recall, worst-family recall, observed benign test FPR, AUROC, AUPR, training time, and score latency. Macro recall gives equal weight to the six attack families. The statistical trial unit is the held-out family, not the repeated seed; seed results are averaged within family before comparison. We use Friedman tests and Nemenyi post-hoc comparisons. Grouped bootstrap confidence intervals resample family trial units. There are six family blocks, so statistical power is limited.

## 6. Results

### 6.1 Main comparison

| Target FPR | Detector | Macro family recall | Worst-family recall | Mean observed benign test FPR | Mean AUROC | Mean AUPR |
|---:|---|---:|---:|---:|---:|---:|
| 0.1% | Isolation Forest | 0.0% | 0.0% | 0.091% | 0.7189 | 0.2767 |
| 0.1% | PCA reconstruction | 5.3% | 0.0% | 0.096% | 0.7881 | 0.3498 |
| 0.1% | IF + PCA fusion | 7.4% | 0.0% | 0.098% | 0.7845 | 0.3285 |
| 1.0% | Isolation Forest | 9.0% | 0.0% | 1.011% | 0.7189 | 0.2767 |
| 1.0% | PCA reconstruction | 19.2% | 0.0% | 0.989% | 0.7881 | 0.3498 |
| 1.0% | IF + PCA fusion | 15.3% | 0.0% | 1.000% | 0.7845 | 0.3285 |

PCA produced the highest macro recall at the 1% budget, while fusion produced the highest at 0.1%. Isolation Forest had the lowest macro recall at both. All three methods had zero worst-family recall at both budgets, demonstrating that aggregate averages conceal complete misses on some held-out categories. Observed benign test FPRs were near, but not exactly equal to, the calibration targets.

### 6.2 Statistical comparison

The Friedman test did not reach conventional statistical significance: at 0.1% target FPR, statistic 4.667 and p=0.0970; at 1%, statistic 4.727 and p=0.0941 (six complete family blocks). Nemenyi pairwise results are saved in the analysis output. These results do not demonstrate equivalence; with six blocks, the comparison has limited power.

### 6.3 Autoencoder exploratory result

The autoencoder’s separately sampled LOFO run reported macro family recall of 3.4% at 0.1% target FPR and 21.5% at 1%; worst-family recall was 0% and 0.03%, respectively. Because this is an exploratory capped sample and attack prevalence differs from the full-data run, these numbers should not be used as a like-for-like statistical ranking against the full-data IF/PCA/fusion results. Its AUPR is not directly comparable under changed prevalence.

### 6.4 Replay dashboard demonstration

The dashboard replay demo uses a balanced 7,000-row file with 1,000 rows from each of six attack labels and 1,000 benign rows. On this demonstration sample, recall/FPR were: IF 9.1%/0.2%, PCA 19.6%/1.7%, fusion 15.9%/0.2%, and autoencoder 22.3%/1.3%. This differs from the main experiment because the replay sample is balanced and each model uses its replay bundle’s fixed threshold. The demo is for visualizing outputs, not the primary benchmark or natural traffic prevalence estimate.

## 7. Discussion

No detector is uniformly best in this pilot. PCA is strongest by macro recall at the 1% budget, while fusion is strongest at 0.1%, yet all have at least one completely missed family at both operating points. This supports reporting per-family outcomes and false-alarm cost rather than relying on a single ranking metric. Fusion did not establish a statistically significant improvement over its components. It may help at one budget while degrading at another.

The dashboard provides practical inspection of flow scores, alert rates, and labeled replay metrics. It loads one locally trained bundle per model or compares all available local bundles. An alert means that a flow score crossed a benign-calibrated threshold; it is not a probability or proof of compromise. The current application performs offline flow replay only and does not capture packets or block traffic.

## 8. Threats to Validity, Limitations, and Ethics

**Dataset provenance.** The only dataset is a Kaggle-prepared derivative. Its cleaning and license provenance are not independently confirmed. The data are from a simulated/testbed setting and have broad aggregate labels.

**Proxy validity.** Holding out a family simulates category novelty but does not reproduce an actual unknown exploit, changing adversary, or production network. Claims must say “held-out-family zero-day-style proxy.”

**External validity.** One dataset cannot establish cross-dataset or real-world generalization. Feature-extraction semantics may differ across datasets and capture tools.

**Statistical power.** Only six family-level blocks are available. Repeated seeds are not independent networks. Non-significant tests are not evidence of equal performance.

**Sampled autoencoder.** The autoencoder result is an exploratory capped sample, not part of the full-data main comparison.

**Operational and ethical limits.** No live capture or blocking is implemented. Flow alerts are leads for human investigation. Any future capture must be limited to networks the team owns or is authorized to monitor, and traffic data must be handled securely.

## 9. Conclusion and Future Work

This single-dataset pilot compared Isolation Forest, PCA reconstruction, and equal-weight rank fusion on six held-out aggregate attack families at 0.1% and 1% benign FPR budgets. PCA led macro recall at 1%; fusion led at 0.1%; no method avoided a zero-recall worst-case family, and statistical tests did not distinguish the methods at p<0.05. The evidence supports a limited conclusion: **among these methods, on this dataset derivative, under this protocol, recall is low at strict alert budgets and varies by family.** It does not establish performance on real zero-day attacks.

Future work should verify dataset provenance and license, validate on a second dataset with a defensible feature mapping, add a supervised known-attack model with an unknown-rejection rule, run a more complete autoencoder experiment if feasible, and build feature-compatible replay/live capture only after validating the flow extractor. Any live alerts should be calibrated on authorized benign network traffic.

## Data and Code Availability

Source and protocol: https://github.com/git-sakshii/ZeroDayAttack. The public repository contains code/configuration/documentation but not the locally downloaded dataset, local model bundles, or generated results. Dataset acquisition and all local artifact paths must therefore be documented for reproducibility.

## References

[1] D. Arp, E. Quiring, F. Pendlebury, A. Warnecke, F. Pierazzi, C. Wressnegger, L. Cavallaro, and K. Rieck, “Dos and Don’ts of Machine Learning in Computer Security,” in *Proc. 31st USENIX Security Symp.*, 2022, pp. 3971–3988. [Online]. Available: https://www.usenix.org/conference/usenixsecurity22/presentation/arp

[2] F. T. Liu, K. M. Ting, and Z.-H. Zhou, “Isolation Forest,” in *Proc. 8th IEEE Int. Conf. on Data Mining (ICDM)*, 2008, pp. 413–422, doi: 10.1109/ICDM.2008.17.

[3] H. Ringberg, A. Soule, J. Rexford, and C. Diot, “Sensitivity of PCA for traffic anomaly detection,” *ACM SIGMETRICS Performance Evaluation Review*, vol. 35, no. 1, pp. 109–120, 2007, doi: 10.1145/1269899.1254895.

[4] Y. Mirsky, T. Doitshman, Y. Elovici, and A. Shabtai, “Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection,” in *Proc. Network and Distributed System Security Symp. (NDSS)*, 2018, doi: 10.14722/ndss.2018.23204.

[5] E. A. Ribeiro, “CICIDS2017: Cleaned & Preprocessed,” Kaggle dataset, version 6, Jan. 12, 2025. Kaggle metadata lists the license as CC0: Public Domain. [Online]. Available: https://www.kaggle.com/datasets/ericanacletoribe/cicids2017-cleaned-and-preprocessed. [Accessed: Nov. 23, 2026].

[6] I. Sharafaldin, A. H. Lashkari, and A. A. Ghorbani, “Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization,” in *Proc. 4th Int. Conf. on Information Systems Security and Privacy (ICISSP)*, 2018, pp. 108–116, doi: 10.5220/0006639801080116.

[7] E. A. Ribeiro, “CICIDS2017—Comprehensive Data Processing for ML,” Kaggle notebook; and “ML Intrusion Detection CICIDS2017,” GitHub repository. [Online]. Available: https://www.kaggle.com/code/ericanacletoribeiro/cicids2017-comprehensive-data-processing-for-ml and https://github.com/anacletu/ml-intrusion-detection-cicids2017. [Accessed: Nov. 23, 2026].

---

## Submission checklist (remove this section before final submission)

- Fill course/instructor and submission date, and confirm IEEE style and affiliation spelling with the college.
- Record that Kaggle metadata declares CC0, and retain the Kaggle dataset page and original CICIDS2017 attribution/citation. Ask the instructor if the institution requires additional license review.
- Confirm the college’s preferred department/affiliation wording.
- Generate final tables/figures only from saved result files in `results/cicids2017_analysis/`.
- Include or regenerate the family recall plot and critical-difference plots if required.
- Decide whether the autoencoder sampled result belongs in the paper; keep it explicitly secondary/exploratory.
- Disclose reused code, datasets, and AI assistance according to course rules.
- Run plagiarism review and proofread after placing this draft in the required template.
- Do not state the project has live monitoring, cross-dataset validation, or confirmed real zero-day performance.
