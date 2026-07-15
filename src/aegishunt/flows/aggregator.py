"""Deterministic timeout-driven bidirectional flow aggregation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from aegishunt.config import FlowSettings
from aegishunt.flows.errors import FlowLimitError, FlowStateError
from aegishunt.flows.keys import CanonicalFlowKey, canonical_flow_key
from aegishunt.flows.packets import PacketRecord
from aegishunt.flows.state import FlowEndReason, FlowState


@dataclass(frozen=True, slots=True)
class FinalizedFlowState:
    """One finalized state together with deterministic segmentation provenance."""

    state: FlowState
    reason: FlowEndReason
    segment_index: int


class FlowAggregator:
    """Aggregate packets while enforcing active-flow and observation bounds."""

    def __init__(
        self,
        settings: FlowSettings,
        *,
        source_id: UUID,
        capture_session_id: str,
    ) -> None:
        self._settings = settings
        self._source_id = source_id
        self._capture_session_id = capture_session_id
        self._active: dict[CanonicalFlowKey, FlowState] = {}
        self._segment_counts: dict[CanonicalFlowKey, int] = {}

    @property
    def active_count(self) -> int:
        return len(self._active)

    def _timeout_reason(
        self,
        state: FlowState,
        timestamp: datetime,
    ) -> FlowEndReason | None:
        if state.first_seen is None or state.last_seen is None:
            raise FlowStateError("active flow is missing timestamp evidence")
        active_elapsed = max(0.0, (timestamp - state.first_seen).total_seconds())
        idle_elapsed = max(0.0, (timestamp - state.last_seen).total_seconds())
        if active_elapsed >= self._settings.active_timeout_seconds:
            return FlowEndReason.ACTIVE_TIMEOUT
        if idle_elapsed >= self._settings.idle_timeout_seconds:
            return FlowEndReason.IDLE_TIMEOUT
        return None

    def _finalize(
        self,
        key: CanonicalFlowKey,
        reason: FlowEndReason,
    ) -> FinalizedFlowState:
        state = self._active.pop(key)
        state.mark_finalized()
        segment_index = self._segment_counts.get(key, 0)
        self._segment_counts[key] = segment_index + 1
        return FinalizedFlowState(
            state=state,
            reason=reason,
            segment_index=segment_index,
        )

    def _expire(self, timestamp: datetime) -> list[FinalizedFlowState]:
        expired: list[tuple[CanonicalFlowKey, FlowEndReason]] = []
        for key, state in self._active.items():
            reason = self._timeout_reason(state, timestamp)
            if reason is not None:
                expired.append((key, reason))
        return [self._finalize(key, reason) for key, reason in sorted(expired)]

    def _new_state(self, packet: PacketRecord) -> FlowState:
        if len(self._active) >= self._settings.max_active_flows:
            raise FlowLimitError("capture reached the configured active-flow limit")
        state = FlowState.from_first_packet(
            packet,
            source_id=self._source_id,
            capture_session_id=self._capture_session_id,
            max_packets=self._settings.max_packets_per_flow,
        )
        self._active[state.key] = state
        return state

    def process(self, packet: PacketRecord) -> list[FinalizedFlowState]:
        """Process one packet and return every state finalized at this timestamp."""

        finalized = self._expire(packet.timestamp)
        key = canonical_flow_key(packet)
        state = self._active.get(key)
        if state is None:
            self._new_state(packet)
            return finalized
        if state.packet_count >= self._settings.max_packets_per_flow:
            finalized.append(self._finalize(key, FlowEndReason.CAPACITY))
            self._new_state(packet)
            return finalized
        state.add(packet)
        return finalized

    def _flush(self, reason: FlowEndReason) -> list[FinalizedFlowState]:
        keys = sorted(self._active)
        return [self._finalize(key, reason) for key in keys]

    def flush_capture_end(self) -> list[FinalizedFlowState]:
        """Finalize all remaining states at end-of-capture; repeated calls are empty."""

        return self._flush(FlowEndReason.CAPTURE_END)

    def flush_manual(self) -> list[FinalizedFlowState]:
        """Explicitly finalize all active states; repeated calls are empty."""

        return self._flush(FlowEndReason.MANUAL)
