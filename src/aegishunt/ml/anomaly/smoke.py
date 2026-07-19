"""Fixed post-selection smoke fixture for validation-qualified anomaly candidates."""

from __future__ import annotations

import hashlib
import json
from typing import Literal

from aegishunt.flows.registry import feature_names

SMOKE_FIXTURE_ID: Literal["phase-06-fixed-syn-burst-v1"] = (
    "phase-06-fixed-syn-burst-v1"
)


def predefined_sample_anomaly() -> tuple[float, ...]:
    """Return the unchanged 128-packet SYN-burst feature vector."""

    values = {
        "total_packets": 128.0,
        "total_bytes": 7_680.0,
        "forward_packets": 128.0,
        "backward_packets": 0.0,
        "forward_bytes": 7_680.0,
        "backward_bytes": 0.0,
        "packets_per_second": 1_007.8740157480315,
        "bytes_per_second": 60_472.44094488189,
        "forward_backward_packet_ratio": 0.0,
        "forward_backward_byte_ratio": 0.0,
        "mean_packet_size": 60.0,
        "std_packet_size": 0.0,
        "min_packet_size": 60.0,
        "max_packet_size": 60.0,
        "median_packet_size": 60.0,
        "packet_size_q25": 60.0,
        "packet_size_q75": 60.0,
        "forward_mean_packet_size": 60.0,
        "backward_mean_packet_size": 0.0,
        "flow_duration": 0.127,
        "mean_inter_arrival_time": 0.001,
        "std_inter_arrival_time": 0.0,
        "min_inter_arrival_time": 0.001,
        "max_inter_arrival_time": 0.001,
        "median_inter_arrival_time": 0.001,
        "iat_q25": 0.001,
        "iat_q75": 0.001,
        "forward_mean_iat": 0.001,
        "backward_mean_iat": 0.0,
        "syn_count": 128.0,
        "ack_count": 0.0,
        "fin_count": 0.0,
        "rst_count": 0.0,
        "psh_count": 0.0,
        "urg_count": 0.0,
        "syn_ratio": 1.0,
        "rst_ratio": 0.0,
        "ack_ratio": 0.0,
        "completed_handshake_indicator": 0.0,
        "asymmetry_score": 1.0,
        "connection_burst_score": 1.0,
        "periodicity_score": 1.0,
        "failed_connection_indicator": 1.0,
    }
    if set(values) != set(feature_names()):
        raise RuntimeError("sample anomaly fixture does not match the feature contract")
    return tuple(values[name] for name in feature_names())


def smoke_fixture_checksum() -> str:
    payload = json.dumps(predefined_sample_anomaly(), separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
