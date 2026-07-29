from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from scripts.phase13_benchmark_support import (
    environment,
    measure,
    percentile,
    write_results,
)
from scripts.run_phase13_benchmark import (
    API_READ_COMPONENTS,
    _require_successful_api_read,
    _require_unchanged_get_counts,
)


def test_percentile_uses_deterministic_linear_interpolation() -> None:
    assert percentile([4.0, 1.0, 3.0, 2.0], 0.0) == 1.0
    assert percentile([4.0, 1.0, 3.0, 2.0], 0.5) == 2.5
    assert percentile([4.0, 1.0, 3.0, 2.0], 0.95) == pytest.approx(3.85)
    assert percentile([4.0, 1.0, 3.0, 2.0], 1.0) == 4.0
    with pytest.raises(ValueError, match="at least one"):
        percentile([], 0.5)


def test_measure_marks_p99_unavailable_for_insufficient_samples() -> None:
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
    assert result["latency_p99_ms"] is None
    assert result["p99_status"] == "insufficient_samples"
    assert result["sample_count"] == 4
    assert result["cpu_seconds"] >= 0
    assert result["baseline_rss_bytes"] > 0
    assert result["peak_rss_bytes"] > 0
    assert result["rss_delta_bytes"] >= 0
    assert result["memory_status"] == "available"


def test_measure_reports_p99_only_after_one_hundred_measured_samples() -> None:
    calls = 0

    def operation() -> int:
        nonlocal calls
        calls += 1
        return 1

    result = measure(
        "micro-operation",
        operation,
        warmups=3,
        repetitions=100,
        operation_unit="rows",
    )

    assert calls == 103
    assert result["sample_count"] == 100
    assert result["operations"] == 100
    assert result["latency_p99_ms"] is not None
    assert result["latency_p95_ms"] <= result["latency_p99_ms"]
    assert result["latency_p99_ms"] <= result["latency_max_ms"]
    assert result["p99_status"] == "available"


def test_measure_reports_unavailable_memory_as_null(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "scripts.phase13_benchmark_support.current_rss_bytes",
        lambda: None,
    )

    result = measure(
        "memory-unavailable",
        lambda: 1,
        warmups=0,
        repetitions=1,
        operation_unit="rows",
    )

    assert result["memory_status"] == "unavailable"
    assert result["baseline_rss_bytes"] is None
    assert result["peak_rss_bytes"] is None
    assert result["rss_delta_bytes"] is None


def test_api_read_contract_covers_required_reads_and_rejects_failures() -> None:
    assert API_READ_COMPONENTS == (
        "api_health",
        "api_system_status",
        "api_flows_page",
        "api_alerts_page",
        "api_runtime_status",
        "api_demo_status",
        "api_flow_detail",
    )
    _require_successful_api_read("/health", 200)
    with pytest.raises(ValueError, match="returned 500"):
        _require_successful_api_read("/health", 500)
    _require_unchanged_get_counts({"flows": 1}, {"flows": 1})
    with pytest.raises(ValueError, match="mutated persistent"):
        _require_unchanged_get_counts({"flows": 1}, {"flows": 2})


def test_environment_metadata_excludes_hostnames_and_absolute_paths() -> None:
    payload = environment(Path.cwd())
    serialized = json.dumps(payload, sort_keys=True)

    assert "hostname" not in payload
    assert str(Path.cwd()) not in serialized


def test_write_results_exports_reviewable_json_csv_and_markdown(tmp_path: Path) -> None:
    result = {
        "component": "component",
        "operation_unit": "rows",
        "warmups": 1,
        "repetitions": 2,
        "sample_count": 2,
        "operations": 4,
        "throughput_per_second": 100.0,
        "latency_min_ms": 1.0,
        "latency_mean_ms": 2.0,
        "latency_stddev_ms": 1.0,
        "latency_p50_ms": 2.0,
        "latency_p95_ms": 2.9,
        "latency_p99_ms": None,
        "p99_status": "insufficient_samples",
        "latency_max_ms": 3.0,
        "cpu_seconds": 0.01,
        "baseline_rss_bytes": 896,
        "peak_rss_bytes": 1024,
        "rss_delta_bytes": 128,
        "rss_sampling_interval_seconds": 0.002,
        "memory_status": "available",
    }
    payload: dict[str, object] = {
        "method": {
            "micro_warmups": 1,
            "micro_repetitions": 2,
            "full_pipeline_repetitions": 2,
        },
        "workload": {
            "sample_name": "sample.pcap",
            "sample_sha256": "a" * 64,
            "feature_schema_version": "1.0.0",
        },
        "artifact_sizes_bytes": {"model": 123},
        "results": [result],
        "memory_results": [
            {
                "scenario": "baseline_process_rss",
                "sample_count": 1,
                "baseline_rss_bytes": 896,
                "peak_rss_bytes": 896,
                "rss_delta_bytes": 0,
                "status": "available",
                "limitation": "single observation",
            }
        ],
    }

    json_path, csv_path, markdown_path = write_results(tmp_path, payload)

    assert json.loads(json_path.read_text(encoding="utf-8"))["results"] == [result]
    with csv_path.open(encoding="utf-8", newline="") as source:
        assert list(csv.DictReader(source))[0]["component"] == "component"
    report = markdown_path.read_text(encoding="utf-8")
    assert "controlled development-host research baseline" in report
    assert "not an SLA" in report
    assert "public benchmark" in report
    assert "insufficient_samples" in report
    assert "p99: reported only" in report
