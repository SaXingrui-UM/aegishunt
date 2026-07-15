"""Versioned, explicitly ordered flow-feature registry."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

from aegishunt.flows.errors import FeatureCalculationError

FEATURE_SCHEMA_VERSION = "1.0.0"


@dataclass(frozen=True, slots=True)
class FeatureDefinition:
    name: str
    data_type: Literal["integer", "number"]
    description: str
    calculation: str
    minimum: float | int | None
    maximum: float | int | None
    empty_behavior: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _count(name: str, description: str, calculation: str) -> FeatureDefinition:
    return FeatureDefinition(name, "integer", description, calculation, 0, None, "0")


def _number(
    name: str,
    description: str,
    calculation: str,
    *,
    maximum: float | None = None,
    empty: str = "0.0",
) -> FeatureDefinition:
    return FeatureDefinition(name, "number", description, calculation, 0.0, maximum, empty)


FEATURE_DEFINITIONS: tuple[FeatureDefinition, ...] = (
    _count("total_packets", "Packets observed in both directions.", "forward + backward packets"),
    _count("total_bytes", "IP-layer bytes in both directions.", "forward + backward bytes"),
    _count("forward_packets", "Packets matching the first packet direction.", "forward count"),
    _count("backward_packets", "Packets opposite the first packet direction.", "backward count"),
    _count("forward_bytes", "IP-layer bytes in the forward direction.", "sum forward sizes"),
    _count("backward_bytes", "IP-layer bytes in the backward direction.", "sum backward sizes"),
    _number(
        "packets_per_second",
        "Total packet rate over flow duration.",
        "total_packets / duration; zero when duration is zero",
    ),
    _number(
        "bytes_per_second",
        "Total IP-layer byte rate over flow duration.",
        "total_bytes / duration; zero when duration is zero",
    ),
    _number(
        "forward_backward_packet_ratio",
        "Forward packets divided by backward packets.",
        "forward_packets / backward_packets; zero when backward is zero",
    ),
    _number(
        "forward_backward_byte_ratio",
        "Forward bytes divided by backward bytes.",
        "forward_bytes / backward_bytes; zero when backward is zero",
    ),
    _number("mean_packet_size", "Mean IP packet size.", "population arithmetic mean"),
    _number("std_packet_size", "Population standard deviation of IP packet sizes.", "pstdev"),
    _number("min_packet_size", "Smallest IP packet size.", "minimum"),
    _number("max_packet_size", "Largest IP packet size.", "maximum"),
    _number("median_packet_size", "Median IP packet size.", "linear median"),
    _number("packet_size_q25", "25th percentile IP packet size.", "linear interpolation q=0.25"),
    _number("packet_size_q75", "75th percentile IP packet size.", "linear interpolation q=0.75"),
    _number(
        "forward_mean_packet_size",
        "Mean forward IP packet size.",
        "forward arithmetic mean",
    ),
    _number(
        "backward_mean_packet_size",
        "Mean backward IP packet size.",
        "backward arithmetic mean; zero when absent",
    ),
    _number("flow_duration", "Seconds between earliest and latest packet.", "max time - min time"),
    _number(
        "mean_inter_arrival_time",
        "Mean non-negative inter-arrival time in seconds.",
        "mean of adjacent sorted timestamps",
    ),
    _number(
        "std_inter_arrival_time",
        "Population standard deviation of inter-arrival times.",
        "pstdev of adjacent sorted timestamps",
    ),
    _number("min_inter_arrival_time", "Minimum inter-arrival time.", "minimum sorted IAT"),
    _number("max_inter_arrival_time", "Maximum inter-arrival time.", "maximum sorted IAT"),
    _number("median_inter_arrival_time", "Median inter-arrival time.", "linear median"),
    _number("iat_q25", "25th percentile inter-arrival time.", "linear interpolation q=0.25"),
    _number("iat_q75", "75th percentile inter-arrival time.", "linear interpolation q=0.75"),
    _number(
        "forward_mean_iat",
        "Mean inter-arrival time among forward packets.",
        "mean adjacent sorted forward timestamps",
    ),
    _number(
        "backward_mean_iat",
        "Mean inter-arrival time among backward packets.",
        "mean adjacent sorted backward timestamps; zero when unavailable",
    ),
    _count("syn_count", "TCP packets with SYN set.", "bit count across packets"),
    _count("ack_count", "TCP packets with ACK set.", "bit count across packets"),
    _count("fin_count", "TCP packets with FIN set.", "bit count across packets"),
    _count("rst_count", "TCP packets with RST set.", "bit count across packets"),
    _count("psh_count", "TCP packets with PSH set.", "bit count across packets"),
    _count("urg_count", "TCP packets with URG set.", "bit count across packets"),
    _number(
        "syn_ratio", "Fraction of packets with SYN set.", "syn_count / total_packets", maximum=1.0
    ),
    _number(
        "rst_ratio", "Fraction of packets with RST set.", "rst_count / total_packets", maximum=1.0
    ),
    _number(
        "ack_ratio", "Fraction of packets with ACK set.", "ack_count / total_packets", maximum=1.0
    ),
    FeatureDefinition(
        "completed_handshake_indicator",
        "integer",
        "Observed SYN, reverse SYN+ACK, then forward ACK in capture order.",
        "bounded evidence indicator; not a full TCP state-machine proof",
        0,
        1,
        "0 for non-TCP or incomplete evidence",
    ),
    _number(
        "asymmetry_score",
        "Absolute directional byte imbalance.",
        "abs(forward_bytes - backward_bytes) / total_bytes",
        maximum=1.0,
    ),
    _number(
        "connection_burst_score",
        "Largest share of packets observed in any one-second window.",
        "max one-second-window packet count / total_packets",
        maximum=1.0,
    ),
    _number(
        "periodicity_score",
        "Regularity proxy from inter-arrival coefficient of variation.",
        "1 / (1 + IAT coefficient of variation); zero with fewer than three IATs",
        maximum=1.0,
    ),
    FeatureDefinition(
        "failed_connection_indicator",
        "integer",
        "TCP reset or incomplete SYN evidence indicator.",
        "1 when TCP has RST, or SYN without the bounded handshake indicator",
        0,
        1,
        "0 for non-TCP",
    ),
)


def feature_names() -> tuple[str, ...]:
    """Return the only supported training/inference feature order."""

    return tuple(definition.name for definition in FEATURE_DEFINITIONS)


def feature_schema_payload() -> dict[str, object]:
    """Build a deterministic, machine-readable schema object."""

    return {
        "schema_version": FEATURE_SCHEMA_VERSION,
        "feature_count": len(FEATURE_DEFINITIONS),
        "ordering": "explicit",
        "numeric_policy": "finite values only; no NaN or Infinity",
        "features": [definition.to_dict() for definition in FEATURE_DEFINITIONS],
    }


def feature_schema_json() -> str:
    """Serialize the registry identically across repeated runs."""

    return json.dumps(feature_schema_payload(), indent=2, ensure_ascii=False) + "\n"


def export_feature_schema(path: Path) -> Path:
    """Export the schema to an explicit caller-selected path."""

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(feature_schema_json(), encoding="utf-8")
    except OSError as exc:
        raise FeatureCalculationError("unable to export the feature schema") from exc
    return path
