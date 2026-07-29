from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from scripts.phase13_benchmark_support import measure, percentile, write_results


def test_percentile_uses_deterministic_linear_interpolation() -> None:
    assert percentile([4.0, 1.0, 3.0, 2.0], 0.0) == 1.0
    assert percentile([4.0, 1.0, 3.0, 2.0], 0.5) == 2.5
    assert percentile([4.0, 1.0, 3.0, 2.0], 0.95) == pytest.approx(3.85)
    assert percentile([4.0, 1.0, 3.0, 2.0], 1.0) == 4.0
    with pytest.raises(ValueError, match="at least one"):
        percentile([], 0.5)


def test_measure_records_latency_throughput_cpu_and_memory() -> None:
    calls = 0

    def operation() -> int:
        nonlocal calls
        calls += 1
        return 3

    result = measure(
        "deterministic-operation",
        operation,
        warmups=2,
        repetitions=4,
        operation_unit="rows",
    )

    assert calls == 6
    assert result["operations"] == 12
    assert result["throughput_per_second"] > 0
    assert result["latency_min_ms"] <= result["latency_p50_ms"]
    assert result["latency_p50_ms"] <= result["latency_p95_ms"]
    assert result["latency_p95_ms"] <= result["latency_p99_ms"]
    assert result["latency_p99_ms"] <= result["latency_max_ms"]
    assert result["cpu_seconds"] >= 0
    assert result["peak_rss_bytes"] > 0
    assert result["rss_delta_bytes"] >= 0


def test_write_results_exports_reviewable_json_csv_and_markdown(tmp_path: Path) -> None:
    result = {
        "component": "component",
        "operation_unit": "rows",
        "warmups": 1,
        "repetitions": 2,
        "operations": 4,
        "throughput_per_second": 100.0,
        "latency_min_ms": 1.0,
        "latency_mean_ms": 2.0,
        "latency_p50_ms": 2.0,
        "latency_p95_ms": 2.9,
        "latency_p99_ms": 2.98,
        "latency_max_ms": 3.0,
        "cpu_seconds": 0.01,
        "peak_rss_bytes": 1024,
        "rss_delta_bytes": 128,
    }
    payload: dict[str, object] = {
        "method": {"warmups": 1, "repetitions": 2},
        "workload": {
            "sample_name": "sample.pcap",
            "sample_sha256": "a" * 64,
            "feature_schema_version": "1.0.0",
        },
        "artifact_sizes_bytes": {"model": 123},
        "results": [result],
    }

    json_path, csv_path, markdown_path = write_results(tmp_path, payload)

    assert json.loads(json_path.read_text(encoding="utf-8"))["results"] == [result]
    with csv_path.open(encoding="utf-8", newline="") as source:
        assert list(csv.DictReader(source))[0]["component"] == "component"
    report = markdown_path.read_text(encoding="utf-8")
    assert "controlled development-host research baseline" in report
    assert "not an SLA" in report
    assert "public benchmark" in report
