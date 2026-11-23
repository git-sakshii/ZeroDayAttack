# Dataset choice and audit notes

## Current local input: Kaggle cleaned/preprocessed derivative

The user supplied `archive.zip` from <https://www.kaggle.com/datasets/ericanacletoribe/cicids2017-cleaned-and-preprocessed>. It contains `cicids2017_cleaned.csv` with 2,520,751 rows, 52 numeric feature columns, and an `Attack Type` field. Observed labels are Normal Traffic, Bots, Brute Force, DDoS, DoS, Port Scanning, and Web Attacks. Initial streaming checks found no null or infinite values. This is a contributor-prepared derivative, not the original CIC day files and not the LycoS or DistriNet corrected release.

Kaggle's public metadata API reports creator/owner Eric Anacleto Ribeiro, dataset version 6, last update 2025-01-12, file size 717,247,573 bytes, and license label “CC0: Public Domain.” The Kaggle dataset description documents merging source CSVs, duplicate row/column removal, infinity and missing-value handling, whitespace normalization, constant/correlated/other feature selection, broad attack-label aggregation, and removal of rare Infiltration and Heartbleed labels. It links the processing notebook and an associated project repository. These are the publisher's stated provenance and license; we did not independently reproduce the full preprocessing or conduct a legal review. Cite the Kaggle derivative and the original CICIDS2017 dataset paper separately. Do not call the derivative an official corrected release.

The broad labels permit LOFO only at these aggregated family categories. Do not claim results for finer attack types that are not represented in this file. Keep the archive, CSV, and preparation audit checksums with the run materials.

Archive CRC passed. Integrity and preparation record:

- Archive SHA-256: `aa28731a9dea99d58a22f3a8faea90fd9b3719bc02576787eeddbb69c81f518e`
- Extracted CSV SHA-256: `0ce5a39edffcde3fce59d0dc4aabc9b1f6acab2c626fd7163be9c694f224c292`
- Prepared Parquet SHA-256: `34c6c45d067bbbfa9d8fc91b40fc6606801c8e103896db08710adff4c41a2be7`
- Raw rows: 2,520,751; retained: 2,519,196.
- Exact duplicates removed: 161 rows. Feature-identical conflicting-label rows: 1,394 across 697 groups; details are in the conflict-signatures Parquet file.
- Normalized retained labels: benign 2,094,199; DDoS 128,011; DoS 193,615; port scanning 90,130; brute force 9,150; web attacks 2,143; bots 1,948.

The first full-data LOFO comparison is saved in `results/cicids2017_core/`; grouped intervals and statistical comparisons are in `results/cicids2017_analysis/`. Treat these as pilot results on this Kaggle derivative, not as final dataset-independent claims.

## Primary: LYCOS-IDS2017

The current primary candidate is LYCOS-IDS2017, the corrected flow dataset derived from CIC-IDS2017. Its project page says the flow CSVs and source code are publicly available for research, and gives the citation below. The corrected flows are generated with LycoSTand from the source PCAPs; do not assume their feature names or values are interchangeable with CICFlowMeter output.

- Project and dataset page: <https://lycos-ids.univ-lemans.fr/>
- Source repository linked by the project page: <https://maupiti-git.univ-lemans.fr/lycos/lycos-ids2017>
- Required dataset citation: A. Rosay, F. Carlier, E. Cheval, and P. Leroux, “From CIC-IDS2017 to LYCOS-IDS2017: A corrected dataset for better performance,” WI-IAT 2021, DOI: <https://doi.org/10.1145/3486622.3493973>.
- Related extraction analysis: A. Rosay, E. Cheval, F. Carlier, and P. Leroux, “Network Intrusion Detection: A Comprehensive Analysis of CIC-IDS2017,” ICISSP 2022, DOI: <https://doi.org/10.5220/0010774000003120>.

Before freezing the family schedule, record:

1. The exact downloaded file name, source URL, file size, and SHA-256.
2. The exact raw label strings and normalized family mapping; manually review aliases and ambiguous labels.
3. The dataset's feature list and any non-feature columns, including identifiers and timestamps.
4. Exact duplicate counts, feature-identical rows with conflicting labels, missing values, and invalid numeric values. The converter removes exact duplicates and writes conflict signatures separately while excluding those rows from the prepared Parquet file. Review the conflict file before deciding whether these rows should remain quarantined.
5. The source's licensing/usage terms and the paper citations.

The project page references the underlying CIC-IDS2017 PCAPs and labels. The LOFO benchmark can use the published LycoS flow CSVs without re-extracting PCAPs, but must state that its feature extractor differs from CICFlowMeter. Live capture would need the same feature definitions to claim direct model compatibility.

## Cross-dataset evaluation: UNSW-NB15

We completed a one-way transfer experiment from the CICIDS2017 derivative to a mirror copy of the UNSW-NB15 fixed test partition. UNSW's dataset page documents 175,341 training rows, 82,332 test rows, nine attack categories, and 49 generated features; it permits academic research use subject to citation. Its SharePoint download link could not be retrieved directly in this environment, so we obtained public copies of the fixed CSV partitions from Hugging Face. The full SHA-256 values below pin the exact local mirror files and are rechecked by the experiment. UNSW does not publish corresponding file checksums, so these hashes do not independently authenticate the copies against the provider's original files. The CSV copies in `data/raw/unsw-nb15/` are local-only and ignored by Git.

| Local file | Rows | SHA-256 | Verification |
|---|---:|---|---|
| `UNSW_NB15_training-set.csv` | 175,341 | `bec7dd5ec88dc2a0ccc7a07879d338395ed7421750f675fd0339e07dfe0648fa` | Pinned SHA-256 for the exact mirror copy used |
| `UNSW_NB15_testing-set.csv` | 82,332 | `734fe6642edf758f7c94d7d9149426b49d202fe8e7bf0bef47392489c3c0a559` | Pinned SHA-256 for the exact mirror copy used |

The files were fetched from public copies under [Mouwiya/UNSW-NB15](https://huggingface.co/datasets/Mouwiya/UNSW-NB15) and [Mireu-Lab/UNSW-NB15](https://huggingface.co/datasets/Mireu-Lab/UNSW-NB15); some mirrors reverse the filenames, so we selected the files by row counts, labels, and feature layout. The run script checks pinned mirror-file hashes and expected partition row/normal counts before fitting. Cite the original dataset page and Moustafa and Slay's dataset paper; do not cite the mirrors as dataset creators.

### Feature alignment and protocol

The CIC and UNSW flow-generation tools do not produce identical schemas. The experiment therefore uses nine semantically corresponding features: duration in seconds; source/forward packet count and bytes; source/forward and destination/backward mean packet sizes; total flow bytes per second; destination/backward packet count; and initial source/forward and destination/backward TCP window sizes. CIC duration is converted from microseconds to seconds. CIC backward packet count is derived from backward packets-per-second times duration. UNSW total flow byte rate is derived from `(sbytes + dbytes) / dur`. The direction mapping and formulas are saved in `results/cross_dataset_unsw/cross_dataset_protocol.json`.

Isolation Forest, PCA reconstruction, and equal-weight rank fusion are fitted on benign CIC training rows. Imputation, scaling, and both alert thresholds are fit/calibrated only on CIC benign training/calibration rows. The frozen model and thresholds are then applied to all rows of the fixed UNSW test-partition mirror; its labels are only used to calculate metrics. The experiment also reruns the within-CIC six-family comparison on the same nine-feature intersection, so its source and target summaries use the same input feature space. Three seeds repeat the fixed benchmark split and are not independent networks.

Because Argus/Bro and CICFlowMeter feature construction differ, the common feature map is an explicit approximation. This is one transfer direction between simulated/testbed datasets, not a guarantee of general cross-network transfer. The most operationally important result is whether the CIC-calibrated benign FPR is retained on UNSW; report the observed UNSW FPR rather than calling it a fixed 0.1% or 1% test FPR.

The reproducible run is `python -m zerodayshield.cross_dataset`. Its code, protocol, row-level family metrics, summary, input hashes, and family means are saved under `results/cross_dataset_unsw/` locally. Cite:

- UNSW-NB15 landing page: <https://research.unsw.edu.au/projects/unsw-nb15-dataset>
- N. Moustafa and J. Slay, “UNSW-NB15: a comprehensive data set for network intrusion detection systems (UNSW-NB15 network data set),” MilCIS, 2015, DOI: <https://doi.org/10.1109/MilCIS.2015.7348942>.

No dataset files are included in this repository. The converter's automatic label normalization is a convenience for auditing and is not a correction of ground truth.
