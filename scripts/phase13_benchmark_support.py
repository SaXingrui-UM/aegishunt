"""Reusable statistics and output helpers for the Phase 13 benchmark."""

from __future__ import annotations

import csv
import json
import math
import os
import platform
import statistics
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Mapping
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

import psutil

BENCHMARK_SCHEMA_VERSION = "1.1.0"
P99_MINIMUM_SAMPLES = 100
RSS_SAMPLING_INTERVAL_SECONDS = 0.002
DEPENDENCIES = (
    "fastapi",
    "numpy",
    "pydantic",
    "scikit-learn",
    "skops",
    "sqlalchemy",
)


class PeakRssSampler:
    """Sample process RSS at a fixed small interval during one workload."""

    def __init__(self, interval_seconds: float = RSS_SAMPLING_INTERVAL_SECONDS) -> None:
        self._interval_seconds = interval_seconds
        self._stop = threading.Event()
        self._process: psutil.Process | None = None
        self._thread = threading.Thread(target=self._sample, daemon=True)
        self.peak_bytes = current_rss_bytes()
        if self.peak_bytes is not None:
            self._process = psutil.Process()

    def _sample(self) -> None:
        while not self._stop.wait(self._interval_seconds):
            if self._process is None or self.peak_bytes is None:
                return
            try:
                self.peak_bytes = max(self.peak_bytes, self._process.memory_info().rss)
            except (OSError, psutil.Error):
                self.peak_bytes = None
                return

    def __enter__(self) -> PeakRssSampler:
        if self._process is not None:
            self._thread.start()
        return self

    def __exit__(self, *_exc_info: object) -> None:
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=1)
        final = current_rss_bytes()
        if self.peak_bytes is not None and final is not None:
            self.peak_bytes = max(self.peak_bytes, final)
        else:
            self.peak_bytes = None


def current_rss_bytes() -> int | None:
    """Return current process RSS, or None when the platform sampler is unavailable."""

    try:
        return psutil.Process().memory_info().rss
    except (OSError, psutil.Error):
        return None


def percentile(values: list[float], fraction: float) -> float:
    """Return one deterministic linearly interpolated percentile."""

    if not values:
        raise ValueError("percentile requires at least one value")
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def measure(
    component: str,
    operation: Callable[[], int],
    *,
    warmups: int,
    repetitions: int,
    operation_unit: str,
) -> dict[str, int | float | str | None]:
    """Measure one deterministic callable without applying noisy pass/fail thresholds."""

    if warmups < 0 or repetitions < 1:
        raise ValueError("benchmark warmups and repetitions are out of range")
    for _ in range(warmups):
        if operation() < 1:
            raise ValueError(f"{component} warm-up returned no operations")

    latencies_ms: list[float] = []
    operation_count = 0
    rss_start = current_rss_bytes()
    cpu_start = time.process_time()
    with PeakRssSampler() as sampler:
        for _ in range(repetitions):
            started = time.perf_counter_ns()
            completed = operation()
            elapsed = time.perf_counter_ns() - started
            if completed < 1:
                raise ValueError(f"{component} returned no operations")
            operation_count += completed
            latencies_ms.append(elapsed / 1_000_000)
    cpu_seconds = time.process_time() - cpu_start
    wall_seconds = sum(latencies_ms) / 1_000
    p99_available = repetitions >= P99_MINIMUM_SAMPLES
    peak_rss = sampler.peak_bytes
    if rss_start is not None and peak_rss is not None:
        memory_status = "available"
        rss_delta: int | None = peak_rss - rss_start
    else:
        memory_status = "unavailable"
        rss_delta = None
    return {
        "component": component,
        "operation_unit": operation_unit,
        "warmups": warmups,
        "repetitions": repetitions,
        "sample_count": len(latencies_ms),
        "operations": operation_count,
        "throughput_per_second": operation_count / wall_seconds,
        "latency_min_ms": min(latencies_ms),
        "latency_mean_ms": sum(latencies_ms) / len(latencies_ms),
        "latency_stddev_ms": statistics.pstdev(latencies_ms),
        "latency_p50_ms": percentile(latencies_ms, 0.50),
        "latency_p95_ms": percentile(latencies_ms, 0.95),
        "latency_p99_ms": percentile(latencies_ms, 0.99) if p99_available else None,
        "p99_status": "available" if p99_available else "insufficient_samples",
        "latency_max_ms": max(latencies_ms),
        "cpu_seconds": cpu_seconds,
        "baseline_rss_bytes": rss_start,
        "peak_rss_bytes": peak_rss,
        "rss_delta_bytes": rss_delta,
        "rss_sampling_interval_seconds": RSS_SAMPLING_INTERVAL_SECONDS,
        "memory_status": memory_status,
    }


def git_commit(project_root: Path) -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=project_root,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return completed.stdout.strip()


def dependency_versions() -> dict[str, str]:
    result: dict[str, str] = {}
    for package in DEPENDENCIES:
        try:
            result[package] = version(package)
        except PackageNotFoundError:
            result[package] = "unavailable"
    return result


def environment(project_root: Path) -> dict[str, object]:
    """Return reviewable host metadata without hostname or absolute paths."""

    return {
        "git_commit": git_commit(project_root),
        "python": sys.version.split()[0],
        "implementation": platform.python_implementation(),
        "operating_system": platform.system(),
        "os_release": platform.release(),
        "architecture": platform.machine(),
        "processor": platform.processor() or "unavailable",
        "logical_cpu_count": os.cpu_count(),
        "dependencies": dependency_versions(),
    }


def directory_size(path: Path) -> int:
    return sum(item.stat().st_size for item in path.rglob("*") if item.is_file())


def _markdown(payload: Mapping[str, Any]) -> str:
    lines = [
        "# AegisHunt Phase 13 Development-Host Performance Baseline",
        "",
        (
            "This is a controlled development-host research baseline. It is not an SLA, "
            "production capacity claim, public benchmark, or detection-performance result."
        ),
        "",
        "## Method",
        "",
        f"- Micro/API warm-ups: {payload['method']['micro_warmups']}",
        f"- Micro/API measured samples: {payload['method']['micro_repetitions']}",
        f"- Full-pipeline measured samples: {payload['method']['full_pipeline_repetitions']}",
        f"- Sample: `{payload['workload']['sample_name']}`",
        f"- Sample SHA-256: `{payload['workload']['sample_sha256']}`",
        f"- Feature schema: `{payload['workload']['feature_schema_version']}`",
        "- Execution: single process, offline, loopback-free, no root, no live capture",
        "- Percentiles: deterministic linear interpolation over measured per-iteration latency",
        "- p99: reported only for scenarios with at least 100 measured samples",
        "- Peak RSS: 2 ms process sampling during each measured component",
        "",
        "## Results",
        "",
        (
            "| Component | Samples | Unit | Operations | Throughput/s | p50 ms | p95 ms | "
            "p99 ms | p99 status | CPU s | Peak RSS bytes |"
        ),
        "|---|---:|---:|---:|---:|---:|---:|---:|---|---:|---:|",
    ]
    for result in payload["results"]:
        p99 = result["latency_p99_ms"]
        p99_display = "n/a" if p99 is None else f"{p99:.6f}"
        lines.append(
            "| {component} | {sample_count} | {operation_unit} | {operations} | "
            "{throughput_per_second:.6f} | {latency_p50_ms:.6f} | "
            "{latency_p95_ms:.6f} | {p99_display} | {p99_status} | "
            "{cpu_seconds:.6f} | {peak_rss_bytes} |".format(
                **result,
                p99_display=p99_display,
            )
        )
    lines.extend(
        [
            "",
            "## Memory Scenarios",
            "",
            "| Scenario | Samples | Baseline RSS | Peak RSS | Delta RSS | Status | Limitation |",
            "|---|---:|---:|---:|---:|---|---|",
            *(
                "| {scenario} | {sample_count} | {baseline_rss_bytes} | "
                "{peak_rss_bytes} | {rss_delta_bytes} | {status} | {limitation} |".format(
                    **item
                )
                for item in payload["memory_results"]
            ),
            "",
            "## Artifact Sizes",
            "",
            *(
                f"- {name}: {size} bytes"
                for name, size in sorted(payload["artifact_sizes_bytes"].items())
            ),
            "",
            "## Limitations",
            "",
            "- The workload is a small controlled synthetic PCAP.",
            "- Host scheduling and thermal state can affect latency.",
            "- RSS sampling can miss peaks shorter than the two-millisecond interval.",
            "- Model and policy evidence is isolated and was not activated globally.",
            "- No frozen test set, model selection, or fusion threshold was reopened.",
            "",
        ]
    )
    return "\n".join(lines)


def write_results(output_dir: Path, payload: dict[str, object]) -> tuple[Path, ...]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "benchmark-results.json"
    csv_path = output_dir / "benchmark-results.csv"
    markdown_path = output_dir / "performance-baseline.md"
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with csv_path.open("w", encoding="utf-8", newline="") as destination:
        results = payload["results"]
        if not isinstance(results, list) or not results:
            raise ValueError("benchmark results cannot be empty")
        fieldnames = sorted({field for result in results for field in result})
        writer = csv.DictWriter(
            destination,
            fieldnames=fieldnames,
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(results)
    markdown_path.write_text(_markdown(payload), encoding="utf-8")
    return json_path, csv_path, markdown_path
