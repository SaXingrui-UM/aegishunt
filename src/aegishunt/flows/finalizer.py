"""Convert finalized flow state into the persistent NetworkFlow contract."""

from __future__ import annotations

from uuid import uuid5

from aegishunt.flows.aggregator import FinalizedFlowState
from aegishunt.flows.errors import FlowStateError
from aegishunt.flows.features import extract_features
from aegishunt.schemas.telemetry import NetworkFlow


def finalize_network_flow(finalized: FinalizedFlowState) -> NetworkFlow:
    """Create one deterministic, source-scoped persistent flow record."""

    state = finalized.state
    if state.first_seen is None or state.last_seen is None:
        raise FlowStateError("finalized flow is missing timestamps")
    identity = "|".join(
        (
            state.key.serialize(),
            str(finalized.segment_index),
            state.first_seen.isoformat(),
            state.last_seen.isoformat(),
        )
    )
    return NetworkFlow(
        flow_id=uuid5(state.source_id, identity),
        source_id=state.source_id,
        capture_session_id=state.capture_session_id,
        first_seen=state.first_seen,
        last_seen=state.last_seen,
        duration=max(0.0, (state.last_seen - state.first_seen).total_seconds()),
        source_ip=state.forward_source.address,
        destination_ip=state.forward_destination.address,
        source_port=state.forward_source.port,
        destination_port=state.forward_destination.port,
        protocol=state.protocol,
        forward_packet_count=state.forward_packet_count,
        backward_packet_count=state.backward_packet_count,
        forward_bytes=state.forward_bytes,
        backward_bytes=state.backward_bytes,
        behavioral_features=extract_features(state),
    )
