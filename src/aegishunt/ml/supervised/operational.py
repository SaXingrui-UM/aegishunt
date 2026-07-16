"""Comparable validation-time operational measurements for supervised candidates."""

from __future__ import annotations

import time
import tracemalloc

import numpy as np
import skops.io as sio
from numpy.typing import NDArray
from sklearn.pipeline import Pipeline

from aegishunt.ml.supervised.calibration import ProbabilityCalibrator
from aegishunt.ml.supervised.candidates import raw_positive_scores
from aegishunt.ml.supervised.contracts import OperationalMetrics
from aegishunt.ml.supervised.errors import EvaluationError


def serialize_candidate(
    estimator: Pipeline,
    calibrator: ProbabilityCalibrator,
) -> bytes:
    """Serialize the complete inference path only for size/integrity measurement."""

    payload = {
        "estimator": estimator,
        "calibration_method": calibrator.method,
        "calibration_estimator": calibrator.estimator,
    }
    try:
        serialized = sio.dumps(payload)
    except (OSError, TypeError, ValueError) as exc:
        raise EvaluationError("candidate serialization failed") from exc
    if not isinstance(serialized, bytes):
        raise EvaluationError("candidate serialization did not produce bytes")
    return serialized


def _predict_probabilities(
    estimator: Pipeline,
    calibrator: ProbabilityCalibrator,
    features: NDArray[np.float64],
) -> NDArray[np.float64]:
    return calibrator.transform(raw_positive_scores(estimator, features))


def measure_operational_metrics(
    estimator: Pipeline,
    calibrator: ProbabilityCalibrator,
    features: NDArray[np.float64],
    *,
    training_duration_seconds: float,
    repetitions: int,
) -> OperationalMetrics:
    """Measure one warmed batch repeatedly on the same process and hardware."""

    if not len(features) or repetitions < 1:
        raise EvaluationError("operational measurement requires data and repetitions")
    reference = _predict_probabilities(estimator, calibrator, features)
    latencies: list[float] = []
    deterministic = True
    tracemalloc.start()
    try:
        for _ in range(repetitions):
            started = time.perf_counter_ns()
            probabilities = _predict_probabilities(estimator, calibrator, features)
            latencies.append((time.perf_counter_ns() - started) / 1_000_000.0)
            deterministic = deterministic and np.array_equal(reference, probabilities)
        _, peak_memory = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    values = np.asarray(latencies, dtype=np.float64)
    total_seconds = float(np.sum(values)) / 1_000.0
    throughput = len(features) * repetitions / total_seconds if total_seconds else 0.0
    bundle_size = len(serialize_candidate(estimator, calibrator))
    return OperationalMetrics(
        training_duration_seconds=training_duration_seconds,
        batch_size=len(features),
        repetitions=repetitions,
        batch_latency_p50_ms=float(np.percentile(values, 50)),
        batch_latency_p95_ms=float(np.percentile(values, 95)),
        batch_latency_p99_ms=float(np.percentile(values, 99)),
        per_sample_latency_p50_ms=float(np.percentile(values, 50)) / len(features),
        throughput_samples_per_second=throughput,
        serialized_size_bytes=bundle_size,
        deterministic_predictions=deterministic,
        peak_memory_bytes=peak_memory,
    )
