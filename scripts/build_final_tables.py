"""Generate final CSV tables and an exact source/output evidence manifest."""

from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

from aegishunt.flows.registry import (
    FEATURE_DEFINITIONS,
    FEATURE_SCHEMA_VERSION,
    feature_schema_payload,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
TABLE_ROOT = PROJECT_ROOT / "docs" / "assets" / "tables"
FIGURE_ROOT = PROJECT_ROOT / "docs" / "assets" / "figures"
MANIFEST = PROJECT_ROOT / "docs" / "assets" / "final-evidence-manifest.json"
PERFORMANCE_SOURCE = (
    PROJECT_ROOT
    / "reports"
    / "hardening"
    / "phase-13"
    / "performance-v1.1"
    / "benchmark-results.json"
)
ROBUSTNESS_SOURCE = (
    PROJECT_ROOT
    / "reports"
    / "hardening"
    / "phase-13"
    / "robustness"
    / "robustness-results.json"
)
SECURITY_SOURCE = (
    PROJECT_ROOT / "configs" / "hardening" / "phase-13-security-findings.json"
)
SAMPLE_SOURCE = PROJECT_ROOT / "data" / "sample" / "phase14-sample-provenance.json"
SOURCE_PATHS = (
    PERFORMANCE_SOURCE,
    ROBUSTNESS_SOURCE,
    SECURITY_SOURCE,
    SAMPLE_SOURCE,
)
OUTPUT_NAMES = (
    "figures/phase13-component-latency.png",
    "figures/phase14-uploaded-sample-profiles.png",
    "tables/feature-schema.csv",
    "tables/performance-components.csv",
    "tables/phase13-security-dispositions.csv",
    "tables/robustness-summary.csv",
    "tables/sample-profiles.csv",
    "feature_schema.json",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return payload


def _write_csv(path: Path, headers: tuple[str, ...], rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=headers, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def _build_feature_table() -> None:
    _write_csv(
        TABLE_ROOT / "feature-schema.csv",
        (
            "order",
            "name",
            "data_type",
            "description",
            "calculation",
            "minimum",
            "maximum",
            "empty_behavior",
            "schema_version",
        ),
        [
            {
                "order": index,
                **definition.to_dict(),
                "schema_version": FEATURE_SCHEMA_VERSION,
            }
            for index, definition in enumerate(FEATURE_DEFINITIONS, start=1)
        ],
    )
    (MANIFEST.parent / "feature_schema.json").write_text(
        json.dumps(feature_schema_payload(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _build_performance_table() -> None:
    payload = _read(PERFORMANCE_SOURCE)
    results = payload["results"]
    assert isinstance(results, list)
    fields = (
        "component",
        "operation_unit",
        "sample_count",
        "latency_p50_ms",
        "latency_p95_ms",
        "latency_p99_ms",
        "p99_status",
        "throughput_per_second",
        "peak_rss_bytes",
    )
    _write_csv(
        TABLE_ROOT / "performance-components.csv",
        fields,
        [{field: row.get(field, "") for field in fields} for row in results],
    )


def _build_security_table() -> None:
    payload = _read(SECURITY_SOURCE)
    findings = payload["findings"]
    assert isinstance(findings, list)
    counts = Counter(str(item["disposition"]) for item in findings)
    _write_csv(
        TABLE_ROOT / "phase13-security-dispositions.csv",
        ("disposition", "count", "evidence_scope"),
        [
            {
                "disposition": disposition,
                "count": count,
                "evidence_scope": "immutable Phase 13 baseline ledger",
            }
            for disposition, count in sorted(counts.items())
        ],
    )


def _build_robustness_table() -> None:
    payload = _read(ROBUSTNESS_SOURCE)
    summary = payload["summary"]
    assert isinstance(summary, dict)
    _write_csv(
        TABLE_ROOT / "robustness-summary.csv",
        ("total", "passed", "failed", "status", "scope"),
        [
            {
                "total": summary.get("total", ""),
                "passed": summary.get("passed", ""),
                "failed": summary.get("failed", ""),
                "status": summary.get("status", ""),
                "scope": "bounded Phase 13 robustness matrix",
            }
        ],
    )


def _build_sample_table() -> None:
    payload = _read(SAMPLE_SOURCE)
    sources = payload["sources"]
    assert isinstance(sources, list)
    _write_csv(
        TABLE_ROOT / "sample-profiles.csv",
        (
            "filename",
            "sha256",
            "size_bytes",
            "observed_packet_count",
            "observed_flow_count",
            "observed_duration_seconds",
            "provenance",
            "label_status",
        ),
        [
            {
                **source,
                "label_status": "unverified presentation profile; not ground truth",
            }
            for source in sources
        ],
    )


def _manifest_payload() -> dict[str, object]:
    outputs = [MANIFEST.parent / name for name in OUTPUT_NAMES]
    if any(not path.is_file() or path.is_symlink() for path in outputs):
        raise ValueError("final evidence output inventory is incomplete")
    return {
        "schema_version": "1.0.0",
        "builder_order": [
            "python scripts/build_final_figures.py",
            "PYTHONPATH=src python scripts/build_final_tables.py",
        ],
        "sources": [
            {
                "path": path.relative_to(PROJECT_ROOT).as_posix(),
                "sha256": _sha256(path),
            }
            for path in SOURCE_PATHS
        ],
        "outputs": [
            {
                "path": path.relative_to(PROJECT_ROOT).as_posix(),
                "sha256": _sha256(path),
                "size_bytes": path.stat().st_size,
            }
            for path in outputs
        ],
        "evidence_boundaries": [
            "missing or unavailable metrics are never converted to zero",
            "performance values are development-host measurements, not an SLA",
            "controlled results are not a public benchmark or production validation",
            "sample profile names are not verified ground-truth labels",
        ],
    }


def main() -> None:
    _build_feature_table()
    _build_performance_table()
    _build_security_table()
    _build_robustness_table()
    _build_sample_table()
    MANIFEST.write_text(
        json.dumps(_manifest_payload(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(MANIFEST.relative_to(PROJECT_ROOT))


if __name__ == "__main__":
    main()
