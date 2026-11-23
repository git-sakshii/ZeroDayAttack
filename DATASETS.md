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

## Cross-dataset candidate

CSE-CIC-IDS2018 is a candidate only after matching feature names, units, flow-generation semantics, and family definitions. If the datasets do not have a defensible common feature map, do not report a direct cross-dataset transfer result. UNSW-NB15 likewise requires a separately declared common-feature mapping.

No dataset files are included in this repository. The converter's automatic label normalization is a convenience for auditing and is not a correction of ground truth.
