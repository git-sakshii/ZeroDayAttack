"""Bounded-memory conversion and basic label audit for flow CSV files."""

import argparse
import hashlib
import json
import re
from pathlib import Path

import polars as pl


def normalize_label(value: str) -> str:
    text = value.strip().casefold()
    text = re.sub(r"[^a-z0-9]+", "_", text).strip("_")
    if text in {"benign", "normal", "normal_traffic"}:
        return "BENIGN"
    return text or "unknown"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def convert_csv(input_path: Path, output_path: Path, label_column: str, chunk_size: int) -> dict:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    lazy = pl.scan_csv(input_path, infer_schema_length=10000)
    names = lazy.collect_schema().names()
    if label_column not in names:
        raise ValueError(f"Label column {label_column!r} absent; columns include: {names[:30]}")
    lazy = lazy.with_columns(
        pl.col(label_column).cast(pl.String).alias("label_raw"),
        pl.col(label_column).cast(pl.String).map_elements(normalize_label, return_dtype=pl.String).alias("attack_family")
    )
    # Output label field is consistently named for downstream commands.
    if label_column != "Label":
        lazy = lazy.rename({label_column: "Label"})
    # Standardize the binary-fit label while retaining the original text above.
    lazy = lazy.with_columns(pl.col("attack_family").alias("Label"))

    raw_rows = int(lazy.select(pl.len()).collect(engine="streaming").item())
    all_columns = lazy.collect_schema().names()
    label_columns = {"Label", "label_raw", "attack_family"}
    feature_columns = [column for column in all_columns if column not in label_columns]
    if not feature_columns:
        raise ValueError("No feature columns remain for duplicate/conflict auditing")

    deduplicated = lazy.unique(maintain_order=False)
    unique_rows = int(deduplicated.select(pl.len()).collect(engine="streaming").item())
    exact_duplicate_rows = raw_rows - unique_rows

    conflicts = (
        deduplicated.group_by(feature_columns)
        .agg(
            pl.col("attack_family").n_unique().alias("__label_count"),
            pl.col("attack_family").unique().alias("__families"),
            pl.len().alias("__rows"),
        )
        .filter(pl.col("__label_count") > 1)
    )
    conflict_summary = conflicts.select(
        pl.len().alias("conflicting_feature_groups"),
        pl.col("__rows").sum().alias("quarantined_rows"),
    ).collect(engine="streaming")
    conflicting_groups = int(conflict_summary["conflicting_feature_groups"][0] or 0)
    quarantined_rows = int(conflict_summary["quarantined_rows"][0] or 0)
    conflict_path = output_path.with_suffix(".conflicts.parquet")
    if conflicting_groups:
        conflicts.sink_parquet(conflict_path, compression="zstd", row_group_size=chunk_size)
        conflict_keys = conflicts.select(feature_columns)
        cleaned = deduplicated.join(conflict_keys, on=feature_columns, how="anti")
    else:
        conflict_path = None
        cleaned = deduplicated

    # Stream the cleaned output. Exact duplicate records are collapsed and any
    # feature-identical rows with conflicting families are excluded.
    cleaned.sink_parquet(output_path, compression="zstd", row_group_size=chunk_size, maintain_order=False)
    count_rows = (
        pl.scan_parquet(output_path)
        .group_by("attack_family")
        .len()
        .collect(engine="streaming")
    )
    counts = {row["attack_family"]: row["len"] for row in count_rows.iter_rows(named=True)}
    total = sum(counts.values())
    if total == 0:
        raise ValueError("No rows were read from the CSV")
    audit = {
        "input": str(input_path.resolve()),
        "input_sha256": sha256_file(input_path),
        "output": str(output_path.resolve()),
        "output_sha256": sha256_file(output_path),
        "rows": total,
        "raw_rows": raw_rows,
        "exact_duplicate_rows_removed": exact_duplicate_rows,
        "conflicting_feature_groups": conflicting_groups,
        "conflicting_rows_quarantined": quarantined_rows,
        "conflict_signatures_file": str(conflict_path.resolve()) if conflict_path else None,
        "label_column": label_column,
        "normalized_family_counts": counts,
        "label_mapping": "trim, casefold, replace non-alphanumeric runs with underscore; benign aliases map to BENIGN",
        "duplicate_policy": "Exact duplicate rows removed; all rows whose non-label feature signature has conflicting attack_family labels quarantined to a separate conflict-signatures Parquet file.",
        "warning": "Automatic normalization is not an audited ground-truth correction. Review family counts, conflict signatures, and source labels before experiments.",
    }
    output_path.with_suffix(".audit.json").write_text(json.dumps(audit, indent=2), encoding="utf-8")
    return audit


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert a flow CSV to compressed Parquet and audit labels")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--label-column", default="Label")
    parser.add_argument("--chunk-size", type=int, default=200_000)
    args = parser.parse_args()
    result = convert_csv(Path(args.input), Path(args.output), args.label_column, args.chunk_size)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
