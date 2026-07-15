"""Numerically stable, deterministic single-flow behavioral features."""

from __future__ import annotations

import math
import statistics
from collections.abc import Sequence
from datetime import datetime, timedelta

from aegishunt.flows.errors import FeatureCalculationError
from aegishunt.flows.registry import FEATURE_DEFINITIONS, feature_names
from aegishunt.flows.state import (
    TCP_ACK,
    TCP_SYN,
    FlowDirection,
    FlowState,
)
from aegishunt.schemas.base import JsonObject
from aegishunt.schemas.enums import NetworkProtocol

_BURST_WINDOW = timedelta(seconds=1)


def _mean(values: Sequence[int | float]) -> float:
    return 0.0 if not values else float(statistics.fmean(values))


def _std(values: Sequence[int | float]) -> float:
    return 0.0 if len(values) < 2 else float(statistics.pstdev(values))


def _quantile(values: Sequence[int | float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(float(value) for value in values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def _iats(timestamps: Sequence[datetime]) -> list[float]:
    ordered = sorted(timestamps)
    return [
        max(0.0, (current - previous).total_seconds())
        for previous, current in zip(ordered, ordered[1:], strict=False)
    ]


def _ratio(numerator: int | float, denominator: int | float) -> float:
    return 0.0 if denominator == 0 else float(numerator / denominator)


def _handshake_indicator(state: FlowState) -> int:
    phase = 0
    for observation in state.tcp_observations:
        has_syn = bool(observation.flags & TCP_SYN)
        has_ack = bool(observation.flags & TCP_ACK)
        if (
            phase == 0
            and observation.direction is FlowDirection.FORWARD
            and has_syn
            and not has_ack
        ):
            phase = 1
        elif phase == 1 and observation.direction is FlowDirection.BACKWARD and has_syn and has_ack:
            phase = 2
        elif phase == 2 and observation.direction is FlowDirection.FORWARD and has_ack:
            return 1
    return 0


def _burst_score(timestamps: Sequence[datetime]) -> float:
    if not timestamps:
        return 0.0
    ordered = sorted(timestamps)
    left = 0
    largest = 1
    for right, timestamp in enumerate(ordered):
        while timestamp - ordered[left] > _BURST_WINDOW:
            left += 1
        largest = max(largest, right - left + 1)
    return largest / len(ordered)


def _periodicity_score(iats: Sequence[float]) -> float:
    if len(iats) < 3:
        return 0.0
    mean = _mean(iats)
    if mean <= 0.0:
        return 0.0
    return 1.0 / (1.0 + _std(iats) / mean)


def _validate_features(features: JsonObject) -> JsonObject:
    if tuple(features) != feature_names():
        raise FeatureCalculationError("feature vector order does not match the registry")
    for definition in FEATURE_DEFINITIONS:
        value = features[definition.name]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise FeatureCalculationError(f"feature is not numeric: {definition.name}")
        numeric = float(value)
        if not math.isfinite(numeric):
            raise FeatureCalculationError(f"feature is not finite: {definition.name}")
        if definition.minimum is not None and numeric < definition.minimum:
            raise FeatureCalculationError(f"feature is below its minimum: {definition.name}")
        if definition.maximum is not None and numeric > definition.maximum:
            raise FeatureCalculationError(f"feature is above its maximum: {definition.name}")
    return features


def extract_features(state: FlowState) -> JsonObject:
    """Calculate the version-1 ordered feature vector for one finalized state."""

    if not state.finalized or state.first_seen is None or state.last_seen is None:
        raise FeatureCalculationError("only a non-empty finalized flow can produce features")
    duration = max(0.0, (state.last_seen - state.first_seen).total_seconds())
    total_packets = state.packet_count
    total_bytes = state.forward_bytes + state.backward_bytes
    iats = _iats(state.packet_timestamps)
    forward_iats = _iats(state.forward_timestamps)
    backward_iats = _iats(state.backward_timestamps)
    handshake = _handshake_indicator(state) if state.protocol is NetworkProtocol.TCP else 0
    syn_count = state.tcp_flag_counts["syn"]
    rst_count = state.tcp_flag_counts["rst"]
    ack_count = state.tcp_flag_counts["ack"]
    failed = int(
        state.protocol is NetworkProtocol.TCP
        and (rst_count > 0 or (syn_count > 0 and handshake == 0))
    )

    features: JsonObject = {
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "forward_packets": state.forward_packet_count,
        "backward_packets": state.backward_packet_count,
        "forward_bytes": state.forward_bytes,
        "backward_bytes": state.backward_bytes,
        "packets_per_second": _ratio(total_packets, duration),
        "bytes_per_second": _ratio(total_bytes, duration),
        "forward_backward_packet_ratio": _ratio(
            state.forward_packet_count, state.backward_packet_count
        ),
        "forward_backward_byte_ratio": _ratio(state.forward_bytes, state.backward_bytes),
        "mean_packet_size": _mean(state.packet_sizes),
        "std_packet_size": _std(state.packet_sizes),
        "min_packet_size": float(min(state.packet_sizes, default=0)),
        "max_packet_size": float(max(state.packet_sizes, default=0)),
        "median_packet_size": _quantile(state.packet_sizes, 0.5),
        "packet_size_q25": _quantile(state.packet_sizes, 0.25),
        "packet_size_q75": _quantile(state.packet_sizes, 0.75),
        "forward_mean_packet_size": _mean(state.forward_packet_sizes),
        "backward_mean_packet_size": _mean(state.backward_packet_sizes),
        "flow_duration": duration,
        "mean_inter_arrival_time": _mean(iats),
        "std_inter_arrival_time": _std(iats),
        "min_inter_arrival_time": min(iats, default=0.0),
        "max_inter_arrival_time": max(iats, default=0.0),
        "median_inter_arrival_time": _quantile(iats, 0.5),
        "iat_q25": _quantile(iats, 0.25),
        "iat_q75": _quantile(iats, 0.75),
        "forward_mean_iat": _mean(forward_iats),
        "backward_mean_iat": _mean(backward_iats),
        "syn_count": syn_count,
        "ack_count": ack_count,
        "fin_count": state.tcp_flag_counts["fin"],
        "rst_count": rst_count,
        "psh_count": state.tcp_flag_counts["psh"],
        "urg_count": state.tcp_flag_counts["urg"],
        "syn_ratio": _ratio(syn_count, total_packets),
        "rst_ratio": _ratio(rst_count, total_packets),
        "ack_ratio": _ratio(ack_count, total_packets),
        "completed_handshake_indicator": handshake,
        "asymmetry_score": _ratio(
            abs(state.forward_bytes - state.backward_bytes), total_bytes
        ),
        "connection_burst_score": _burst_score(state.packet_timestamps),
        "periodicity_score": _periodicity_score(iats),
        "failed_connection_indicator": failed,
    }
    return _validate_features(features)
