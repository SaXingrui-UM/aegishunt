"""Reusable statistics and output helpers for the Phase 13 benchmark."""

from __future__ import annotations

import csv
import json
import math
import os
import platform
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Mapping
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

import psutil

BENCHMARK_SCHEMA_VERSION = "1.0.0"
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

    def __init__(self, interval_seconds: float = 0.002) -> None:
        self._interval_seconds = interval_seconds
        self._stop = threading.Event()
        self._process = psutil.Process()
        self._thread = threading.Thread(target=self._sample, daemon=True)
        self.peak_bytes = self._process.memory_info().rss

    def _sample(self) -> None:
        while not self._stop.wait(self._interval_seconds):
            self.peak_bytes = max(self.peak_bytes, self._process.memory_info().rss)

    def __enter__(self) -> PeakRssSampler:
        self._thread.start()
        return self

    def __exit__(self, *_exc_info: object) -> None:
        self._stop.set()
        self._thread.join(timeout=1)
        self.peak_bytes = max(self.peak_bytes, self._process.memory_info().rss)


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
) -> dict[str, int | float | str]:
    """Measure one deterministic callable without applying noisy pass/fail thresholds."""

    if warmups < 0 or repetitions < 1:
        raise ValueError("benchmark warmups and repetitions are out of range")
    for _ in range(warmups):
        if operation() < 1:
            raise ValueError(f"{component} warm-up returned no operations")

    latencies_ms: list[float] = []
    operation_count = 0
    rss_start = psutil.Process().memory_info().rss
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
    return {
        "component": component,
        "operation_unit": operation_unit,
        "warmups": warmups,
        "repetitions": repetitions,
        "operations": operation_count,
        "throughput_per_second": operation_count / wall_seconds,
        "latency_min_ms": min(latencies_ms),
        "latency_mean_ms": sum(latencies_ms) / len(latencies_ms),
        "latency_p50_ms": percentile(latencies_ms, 0.50),
        "latency_p95_ms": percentile(latencies_ms, 0.95),
        "latency_p99_ms": percentile(latencies_ms, 0.99),
        "latency_max_ms": max(latencies_ms),
        "cpu_seconds": cpu_seconds,
        "peak_rss_bytes": sampler.peak_bytes,
        "rss_delta_bytes": sampler.peak_bytes - rss_start,
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
        f"- Warm-ups: {payload['method']['warmups']}",
        f"- Repetitions: {payload['method']['repetitions']}",
        f"- Sample: `{payload['workload']['sample_name']}`",
        f"- Sample SHA-256: `{payload['workload']['sample_sha256']}`",
        f"- Feature schema: `{payload['workload']['feature_schema_version']}`",
        "- Execution: single process, offline, loopback-free, no root, no live capture",
        "- Percentiles: deterministic linear interpolation over per-iteration latency",
        "- Peak RSS: 2 ms process sampling during each measured component",
        "",
        "## Results",
        "",
        (
            "| Component | Unit | Operations | Throughput/s | p50 ms | p95 ms | "
            "p99 ms | CPU s | Peak RSS bytes |"
        ),
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for result in payload["results"]:
        lines.append(
            "| {component} | {operation_unit} | {operations} | "
            "{throughput_per_second:.6f} | {latency_p50_ms:.6f} | "
            "{latency_p95_ms:.6f} | {latency_p99_ms:.6f} | "
            "{cpu_seconds:.6f} | {peak_rss_bytes} |".format(**result)
        )
    lines.extend(
        [
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
            "- RSS sampling can miss peaks shorter than the sampling interval.",
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
        writer = csv.DictWriter(destination, fieldnames=list(results[0]))
        writer.writeheader()
        writer.writerows(results)
    markdown_path.write_text(_markdown(payload), encoding="utf-8")
    return json_path, csv_path, markdown_path
