"""Comparable anomaly scoring latency, size, memory, and determinism evidence."""

from __future__ import annotations

import time
import tracemalloc

import numpy as np
from numpy.typing import NDArray
from sklearn.pipeline import Pipeline

from aegishunt.ml.anomaly.bundle import estimator_bytes
from aegishunt.ml.anomaly.contracts import AnomalyOperationalMetrics, ScoreNormalization
from aegishunt.ml.anomaly.errors import AnomalyEvaluationError
from aegishunt.ml.anomaly.normalization import normalize_scores
from aegishunt.ml.anomaly.scoring import score_pipeline


def measure_operational_metrics(
    estimator: Pipeline,
    normalizer: ScoreNormalization,
    features: NDArray[np.float64],
    *,
    training_duration_seconds: float,
    repetitions: int,
) -> AnomalyOperationalMetrics:
    if not len(features) or repetitions < 1:
        raise AnomalyEvaluationError("anomaly operational measurement requires data")
    _, canonical = score_pipeline(estimator, features)
    reference = normalize_scores(canonical, normalizer)
    latencies: list[float] = []
    deterministic = True
    tracemalloc.start()
    try:
        for _ in range(repetitions):
            started = time.perf_counter_ns()
            _, repeated_canonical = score_pipeline(estimator, features)
            repeated = normalize_scores(repeated_canonical, normalizer)
            latencies.append((time.perf_counter_ns() - started) / 1_000_000.0)
            deterministic = deterministic and np.array_equal(reference, repeated)
        _, peak_memory = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    values = np.asarray(latencies, dtype=np.float64)
    total_seconds = float(np.sum(values)) / 1_000.0
    throughput = len(features) * repetitions / total_seconds if total_seconds else 0.0
    return AnomalyOperationalMetrics(
        training_duration_seconds=training_duration_seconds,
        batch_size=len(features),
        repetitions=repetitions,
        batch_latency_p50_ms=float(np.percentile(values, 50)),
        batch_latency_p95_ms=float(np.percentile(values, 95)),
        batch_latency_p99_ms=float(np.percentile(values, 99)),
        per_sample_latency_p50_ms=float(np.percentile(values, 50)) / len(features),
        throughput_samples_per_second=throughput,
        estimator_serialized_size_bytes=len(estimator_bytes(estimator)),
        deterministic_scores=deterministic,
        peak_memory_bytes=peak_memory,
    )
