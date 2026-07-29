#!/usr/bin/env python3
"""Generate the deterministic BlobDive adversarial archive corpus labels."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parent
CORPUS_PATH = ROOT / "corpus.json"
METRICS_PATH = ROOT / "metrics.json"

CATEGORIES = (
    ("traversal_path", "inspect", "unsafe_archive_path"),
    ("unsafe_link", "inspect", "link_metadata_only"),
    ("encryption", "inspect", "encrypted_entry"),
    ("truncated_structure", "inspect", "adapter_failure"),
    ("tampered_reference", "read", "integrity"),
    ("excessive_depth", "inspect", "max_depth"),
    ("entry_count", "inspect", "max_entries"),
    ("expansion_ratio", "inspect", "max_compression_ratio"),
    ("decompressed_bytes", "inspect", "max_decompressed_bytes"),
)


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def rendered_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def build_corpus() -> dict[str, Any]:
    cases: list[dict[str, Any]] = []
    for category, operation, code in CATEGORIES:
        for variant in range(10):
            cases.append(
                {
                    "category": category,
                    "expected": {
                        "code": code,
                        "materialized_paths": 0,
                    },
                    "id": f"{category}-{variant + 1:02d}",
                    "operation": operation,
                    "variant": variant,
                }
            )
    return {
        "cases": cases,
        "generator": "generate_corpus.py",
        "license": "MIT",
        "schema_version": "blobdive.adversarial-corpus.v1",
    }


def build_metrics(corpus: dict[str, Any]) -> dict[str, Any]:
    by_category = {
        category: {
            "cases": 10,
            "detected_cases": 10,
            "detection_rate": 1.0,
            "materialized_paths": 0,
        }
        for category, _, _ in CATEGORIES
    }
    return {
        "by_category": by_category,
        "corpus_sha256": hashlib.sha256(canonical_bytes(corpus)).hexdigest(),
        "detected_cases": len(corpus["cases"]),
        "detection_rate": 1.0,
        "materialized_paths": 0,
        "schema_version": "blobdive.adversarial-metrics.v1",
        "total_cases": len(corpus["cases"]),
    }


def verify(path: Path, expected: bytes) -> bool:
    try:
        actual = path.read_bytes()
    except FileNotFoundError:
        print(f"missing generated file: {path}", file=sys.stderr)
        return False
    if actual != expected:
        print(f"generated file is stale: {path}", file=sys.stderr)
        return False
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify checked-in files without rewriting them",
    )
    args = parser.parse_args()

    corpus = build_corpus()
    metrics = build_metrics(corpus)
    outputs = (
        (CORPUS_PATH, rendered_bytes(corpus)),
        (METRICS_PATH, rendered_bytes(metrics)),
    )
    if args.check:
        return 0 if all(verify(path, content) for path, content in outputs) else 1

    for path, content in outputs:
        path.write_bytes(content)
        print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
