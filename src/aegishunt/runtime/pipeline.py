"""Streaming offline PCAP replay through the verified Phase 3–9 pipeline."""

from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Sequence
from functools import partial
from pathlib import Path
from uuid import UUID

from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from aegishunt.config import ApplicationSettings
from aegishunt.correlation.service import AlertCorrelationService
from aegishunt.detection.service import DetectionAlertService
from aegishunt.flows.aggregator import FlowAggregator
from aegishunt.flows.errors import FlowProcessingError
from aegishunt.flows.finalizer import finalize_network_flow
from aegishunt.flows.packets import parse_packet
from aegishunt.flows.pcap_reader import PcapPacketReader
from aegishunt.hunting.service import ThreatHypothesisService
from aegishunt.runtime.clock import RuntimeClock
from aegishunt.runtime.config import LoadedRuntimePolicy
from aegishunt.runtime.contracts import (
    RuntimeCounters,
    RuntimeJob,
    RuntimeOutputLedger,
    RuntimeStage,
)
from aegishunt.runtime.control import RuntimeControlMonitor
from aegishunt.runtime.errors import (
    ReplayInterrupted,
    RuntimePersistenceError,
    RuntimePreflightError,
    RuntimeReplayError,
)
from aegishunt.runtime.preflight import RuntimePreflightVerifier
from aegishunt.runtime.replay import ReplayPacer
from aegishunt.runtime.repositories import (
    RuntimeJobRepository,
    RuntimeOutputLedgerRepository,
    RuntimeWorkerRepository,
)
from aegishunt.runtime.resources import ProcessResourceSampler
from aegishunt.schemas import (
    AlertGroup,
    DetectionResult,
    NetworkFlow,
    SecurityAlert,
    ThreatHypothesis,
)
from aegishunt.storage import Database
from aegishunt.storage.repositories import (
    AlertGroupRepository,
    AuditLogRepository,
    DetectionResultRepository,
    NetworkFlowRepository,
    SecurityAlertRepository,
    TelemetrySourceRepository,
    ThreatHypothesisRepository,
)


def _increment(counters: RuntimeCounters, **changes: int) -> RuntimeCounters:
    payload = counters.model_dump(mode="python")
    for name, delta in changes.items():
        payload[name] = int(payload[name]) + delta
    return RuntimeCounters.model_validate(payload)


_OUTPUT_COUNTER_FIELDS = (
    "flows_created",
    "flows_reused",
    "detections_created",
    "detections_reused",
    "alerts_created",
    "alerts_reused",
    "groups_created",
    "groups_reused",
    "hypotheses_created",
    "hypotheses_reused",
)


def _completed_counters(
    observed: RuntimeCounters,
    durable: RuntimeCounters,
) -> RuntimeCounters:
    """Combine final packet observations with transaction-backed output counts."""

    payload = observed.model_dump(mode="python")
    for field in _OUTPUT_COUNTER_FIELDS:
        payload[field] = getattr(durable, field)
    return RuntimeCounters.model_validate(payload)


def _output_checksum(
    flow: NetworkFlow,
    detection: DetectionResult,
    alert: SecurityAlert | None,
) -> str:
    payload = json.dumps(
        {
            "flow": flow.model_dump(mode="json"),
            "detection": detection.model_dump(mode="json"),
            "alert": (
                None
                if alert is None
                else alert.model_dump(mode="json")
            ),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def _groups_for_job(
    groups: Sequence[AlertGroup],
    job_alert_ids: set[str],
) -> tuple[AlertGroup, ...]:
    """Retain correlation groups containing evidence emitted by one runtime job."""

    return tuple(
        group
        for group in groups
        if not job_alert_ids.isdisjoint(group.alert_ids)
    )


def _hypotheses_for_groups(
    hypotheses: Sequence[ThreatHypothesis],
    group_ids: set[UUID],
) -> tuple[ThreatHypothesis, ...]:
    """Retain hypotheses derived from correlation groups attributed to one job."""

    return tuple(
        hypothesis
        for hypothesis in hypotheses
        if hypothesis.group_id is not None and hypothesis.group_id in group_ids
    )


class RuntimePipelineRunner:
    """Process one claimed job, preserving transactional and restart invariants."""

    def __init__(
        self,
        database: Database,
        *,
        settings: ApplicationSettings,
        runtime_policy: LoadedRuntimePolicy,
        project_root: Path,
        worker_id: str,
        stop_event: threading.Event,
        clock: RuntimeClock | None = None,
        resource_sampler: ProcessResourceSampler | None = None,
    ) -> None:
        self._database = database
        self._settings = settings
        self._runtime = runtime_policy
        self._worker_id = worker_id
        self._stop = stop_event
        self._clock = clock or RuntimeClock()
        self._control = RuntimeControlMonitor(
            database,
            runtime_policy=runtime_policy,
            worker_id=worker_id,
            stop_event=stop_event,
            clock=self._clock,
            resource_sampler=resource_sampler or ProcessResourceSampler(),
        )
        self._preflight = RuntimePreflightVerifier(
            settings=settings,
            runtime_policy=runtime_policy,
            project_root=project_root,
        )
        self._last_correlation_alert_count = 0
        self._observed_group_ids: set[UUID] = set()
        self._observed_hypothesis_ids: set[UUID] = set()

    def run(self, job: RuntimeJob) -> RuntimeCounters:
        """Replay from packet zero; committed ledgers make recovery idempotent."""

        with self._database.session() as session:
            source = TelemetrySourceRepository(session).get(job.source_id)
        if source is None:
            raise RuntimePreflightError("runtime source disappeared before replay")
        loaded = self._preflight.verify(source, expected_snapshot=job.snapshot)
        with self._database.session() as session, session.begin():
            audit = AuditLogRepository(session)
            RuntimeJobRepository(session, audit).mark_running(
                job.job_id,
                worker_id=self._worker_id,
                now=self._clock.now(),
                actor=self._worker_id,
            )
            workers = RuntimeWorkerRepository(session)
            worker = workers.get(self._worker_id)
            if worker is not None:
                workers.upsert(
                    worker.model_copy(
                        update={"model_load_state": "verified_per_job_preflight"}
                    )
                )
        self._control.capture_resource_sample(job.job_id)

        reader = PcapPacketReader(
            max_records=self._settings.ingestion.max_records,
            max_packet_bytes=self._settings.flows.max_packet_bytes,
            max_interfaces=self._settings.flows.max_pcapng_interfaces,
        )
        aggregator = FlowAggregator(
            self._settings.flows,
            source_id=job.source_id,
            capture_session_id=job.snapshot.capture_session_id,
        )
        replay = self._runtime.policy.replay
        pacer = ReplayPacer(
            speed=job.replay_speed,
            maximum_sleep_seconds=replay.maximum_sleep_seconds,
            sleep_quantum_seconds=replay.sleep_quantum_seconds,
            clock=self._clock,
        )
        observed_counters = RuntimeCounters()
        durable_counters = job.counters
        pending: list[NetworkFlow] = []
        total_packets = job.progress_total
        try:
            for captured in reader.packets(loaded.source_path):
                delay = pacer.delay_for(captured.timestamp)
                observed_counters = _increment(
                    observed_counters,
                    out_of_order_packets=int(delay.out_of_order),
                    capped_gaps=int(delay.capped_gap),
                )
                counters_at_sleep = observed_counters
                progress_at_sleep = min(
                    (
                        0.0
                        if total_packets is None
                        else observed_counters.captured_packets / total_packets
                    ),
                    0.999999,
                )
                if not pacer.sleep(
                    delay,
                    should_stop=self._stop.is_set,
                    on_quantum=partial(
                        self._control.check,
                        job.job_id,
                        counters_at_sleep,
                        progress_at_sleep,
                    ),
                ):
                    raise ReplayInterrupted("worker shutdown requested")
                observed_counters = _increment(
                    observed_counters,
                    captured_packets=1,
                )
                if (
                    total_packets is not None
                    and observed_counters.captured_packets > total_packets
                ):
                    raise RuntimeReplayError(
                        "replayed packet count exceeds pinned source evidence"
                    )
                packet = parse_packet(
                    captured.frame,
                    timestamp=captured.timestamp,
                    link_type=captured.link_type,
                )
                if packet is None:
                    observed_counters = _increment(
                        observed_counters,
                        skipped_packets=1,
                    )
                else:
                    observed_counters = _increment(
                        observed_counters,
                        decoded_packets=1,
                    )
                    pending.extend(
                        finalize_network_flow(item) for item in aggregator.process(packet)
                    )
                if len(pending) >= self._runtime.policy.worker.persistence_batch_size:
                    self._control.record_observed_progress(
                        job.job_id,
                        observed_counters,
                        (
                            0.0
                            if total_packets is None
                            else min(
                                observed_counters.captured_packets / total_packets,
                                0.999999,
                            )
                        ),
                    )
                    durable_counters = self._persist_batch(
                        job,
                        loaded,
                        pending,
                        durable_counters,
                    )
                    pending.clear()
                    durable_counters = self._maybe_correlate(
                        job,
                        loaded,
                        durable_counters,
                    )
                self._control.check(
                    job.job_id,
                    observed_counters,
                    (
                        0.0
                        if total_packets is None
                        else min(
                            observed_counters.captured_packets / total_packets,
                            0.999999,
                        )
                    ),
                )
            pending.extend(
                finalize_network_flow(item) for item in aggregator.flush_capture_end()
            )
            if (
                total_packets is not None
                and observed_counters.captured_packets != total_packets
            ):
                raise RuntimeReplayError(
                    "replayed packet count differs from pinned source evidence"
            )
            if pending:
                self._control.record_observed_progress(
                    job.job_id,
                    observed_counters,
                    (
                        0.0
                        if total_packets is None
                        else min(
                            observed_counters.captured_packets / total_packets,
                            0.999999,
                        )
                    ),
                )
                durable_counters = self._persist_batch(
                    job,
                    loaded,
                    pending,
                    durable_counters,
                )
                durable_counters = self._maybe_correlate(
                    job,
                    loaded,
                    durable_counters,
                )
            completed = self._finalize_downstream(
                job,
                loaded,
                observed_counters,
                durable_counters,
            )
            self._control.capture_resource_sample(job.job_id)
            return completed
        except ReplayInterrupted:
            self._control.record_observed_progress(
                job.job_id,
                observed_counters,
                (
                    0.0
                    if total_packets is None
                    else min(
                        observed_counters.captured_packets / total_packets,
                        0.999999,
                    )
                ),
            )
            raise
        except (FlowProcessingError, OSError, ValueError) as exc:
            self._control.record_observed_progress(
                job.job_id,
                observed_counters,
                (
                    0.0
                    if total_packets is None
                    else min(
                        observed_counters.captured_packets / total_packets,
                        0.999999,
                    )
                ),
            )
            raise RuntimeReplayError("stored PCAP replay failed safely") from exc

    def _persist_batch(
        self,
        job: RuntimeJob,
        loaded: object,
        flows: Sequence[NetworkFlow],
        durable_counters: RuntimeCounters,
    ) -> RuntimeCounters:
        from aegishunt.runtime.preflight import LoadedRuntimePipeline

        if not isinstance(loaded, LoadedRuntimePipeline):
            raise TypeError("loaded pipeline has an invalid type")
        updated = durable_counters
        try:
            with self._database.session() as session, session.begin():
                audit = AuditLogRepository(session)
                flow_repository = NetworkFlowRepository(session, audit)
                detection_repository = DetectionResultRepository(session, audit)
                alert_repository = SecurityAlertRepository(session, audit)
                ledger_repository = RuntimeOutputLedgerRepository(session)
                detection_service = DetectionAlertService(
                    session,
                    risk_policy=loaded.risk_policy,
                    explanation_artifact=loaded.explanation_artifact,
                    local_top_k=self._settings.detection.local_explanation_top_k,
                    local_max_features=self._settings.detection.local_explanation_max_features,
                )
                for flow in flows:
                    ledger = ledger_repository.get_for_flow(job.job_id, flow.flow_id)
                    if ledger is not None:
                        stored_flow = flow_repository.get(flow.flow_id)
                        detection = detection_repository.get(ledger.detection_id)
                        alert = (
                            None
                            if ledger.alert_id is None
                            else alert_repository.get(ledger.alert_id)
                        )
                        if (
                            stored_flow is None
                            or detection is None
                            or _output_checksum(stored_flow, detection, alert)
                            != ledger.output_checksum
                        ):
                            raise RuntimePersistenceError(
                                "runtime output ledger conflicts with persisted evidence"
                            )
                        updated = _increment(
                            updated,
                            flows_reused=1,
                            detections_reused=1,
                            alerts_reused=int(alert is not None),
                        )
                        continue
                    stored_flow = flow_repository.get(flow.flow_id)
                    if stored_flow is None:
                        stored_flow = flow_repository.add(flow, actor=self._worker_id)
                        updated = _increment(updated, flows_created=1)
                    elif stored_flow != flow:
                        raise RuntimePersistenceError(
                            "deterministic flow identity exists with different evidence"
                        )
                    else:
                        updated = _increment(updated, flows_reused=1)
                    if detection_repository.get_by_flow(flow.flow_id) is not None:
                        raise RuntimePersistenceError(
                            "flow has detection evidence outside this runtime ledger"
                        )
                    detection, alert = detection_service.evaluate_flow(
                        stored_flow,
                        loaded.scorer(scored_at=stored_flow.last_seen),
                        actor=self._worker_id,
                    )
                    updated = _increment(
                        updated,
                        detections_created=1,
                        alerts_created=int(alert is not None),
                    )
                    ledger_repository.add(
                        RuntimeOutputLedger(
                            job_id=job.job_id,
                            source_id=job.source_id,
                            flow_id=stored_flow.flow_id,
                            detection_id=detection.detection_id,
                            alert_id=None if alert is None else alert.alert_id,
                            output_checksum=_output_checksum(
                                stored_flow,
                                detection,
                                alert,
                            ),
                            created_at=self._clock.now(),
                        )
                    )
                RuntimeJobRepository(session, audit).update_durable_progress(
                    job.job_id,
                    worker_id=self._worker_id,
                    counters=updated,
                    progress_current=0,
                    progress=0.0,
                    now=self._clock.now(),
                )
        except RuntimePersistenceError:
            raise
        except (IntegrityError, SQLAlchemyError) as exc:
            raise RuntimePersistenceError(
                "runtime output batch rolled back after persistence failure"
            ) from exc
        return updated

    def _finalize_downstream(
        self,
        job: RuntimeJob,
        loaded: object,
        observed_counters: RuntimeCounters,
        durable_counters: RuntimeCounters,
    ) -> RuntimeCounters:
        from aegishunt.runtime.preflight import LoadedRuntimePipeline

        if not isinstance(loaded, LoadedRuntimePipeline):
            raise TypeError("loaded pipeline has an invalid type")
        return self._run_downstream(
            job,
            loaded,
            observed_counters,
            durable_counters,
            complete=True,
        )

    def _maybe_correlate(
        self,
        job: RuntimeJob,
        loaded: object,
        durable_counters: RuntimeCounters,
    ) -> RuntimeCounters:
        alert_count = (
            durable_counters.alerts_created + durable_counters.alerts_reused
        )
        if (
            alert_count - self._last_correlation_alert_count
            < self._runtime.policy.worker.correlation_alert_batch_size
        ):
            return durable_counters
        updated = self._run_downstream(
            job,
            loaded,
            RuntimeCounters(),
            durable_counters,
            complete=False,
        )
        self._last_correlation_alert_count = alert_count
        return updated

    def _run_downstream(
        self,
        job: RuntimeJob,
        loaded: object,
        observed_counters: RuntimeCounters,
        durable_counters: RuntimeCounters,
        *,
        complete: bool,
    ) -> RuntimeCounters:
        from aegishunt.runtime.preflight import LoadedRuntimePipeline

        if not isinstance(loaded, LoadedRuntimePipeline):
            raise TypeError("loaded pipeline has an invalid type")
        committed_group_ids: set[UUID] = set()
        committed_hypothesis_ids: set[UUID] = set()
        updated = durable_counters
        try:
            with self._database.session() as session, session.begin():
                groups_repository = AlertGroupRepository(session)
                hypotheses_repository = ThreatHypothesisRepository(session)
                job_alert_ids = {
                    item.alert_id
                    for item in RuntimeOutputLedgerRepository(session).list_for_job(
                        job.job_id
                    )
                    if item.alert_id is not None
                }
                serialized_job_alert_ids = {
                    str(alert_id) for alert_id in job_alert_ids
                }
                before_groups = _groups_for_job(
                    groups_repository.list(),
                    serialized_job_alert_ids,
                )
                before_group_ids = {item.group_id for item in before_groups}
                before_hypothesis_ids = {
                    item.hypothesis_id
                    for item in _hypotheses_for_groups(
                        hypotheses_repository.list(),
                        before_group_ids,
                    )
                }
                jobs = RuntimeJobRepository(
                    session,
                    AuditLogRepository(session),
                )
                jobs.set_stage(
                    job.job_id,
                    worker_id=self._worker_id,
                    stage=RuntimeStage.CORRELATION,
                    now=self._clock.now(),
                    actor=self._worker_id,
                )
                groups = _groups_for_job(
                    AlertCorrelationService(
                        session,
                        loaded.correlation_policy,
                        clock=self._clock.now,
                    ).correlate(
                        actor=self._worker_id,
                        alert_ids=job_alert_ids,
                    ),
                    serialized_job_alert_ids,
                )
                group_ids = {item.group_id for item in groups}
                hypotheses = _hypotheses_for_groups(
                    ThreatHypothesisService(
                        session,
                        loaded.correlation_policy,
                        clock=self._clock.now,
                    ).generate(actor=self._worker_id),
                    group_ids,
                )
                hypothesis_ids = {item.hypothesis_id for item in hypotheses}
                new_group_observations = group_ids - self._observed_group_ids
                new_hypothesis_observations = (
                    hypothesis_ids - self._observed_hypothesis_ids
                )
                updated = _increment(
                    durable_counters,
                    groups_created=len(new_group_observations - before_group_ids),
                    groups_reused=len(new_group_observations & before_group_ids),
                    hypotheses_created=len(
                        new_hypothesis_observations - before_hypothesis_ids
                    ),
                    hypotheses_reused=len(
                        new_hypothesis_observations & before_hypothesis_ids
                    ),
                )
                if complete:
                    completed_counters = _completed_counters(
                        observed_counters,
                        updated,
                    )
                    jobs.complete(
                        job.job_id,
                        worker_id=self._worker_id,
                        counters=completed_counters,
                        observed_counters=observed_counters,
                        now=self._clock.now(),
                        actor=self._worker_id,
                    )
                    updated = completed_counters
                else:
                    jobs.update_durable_progress(
                        job.job_id,
                        worker_id=self._worker_id,
                        counters=updated,
                        progress_current=0,
                        progress=0.0,
                        now=self._clock.now(),
                    )
                    jobs.set_stage(
                        job.job_id,
                        worker_id=self._worker_id,
                        stage=RuntimeStage.REPLAY,
                        now=self._clock.now(),
                        actor=self._worker_id,
                    )
                committed_group_ids = group_ids
                committed_hypothesis_ids = hypothesis_ids
        except (IntegrityError, SQLAlchemyError) as exc:
            raise RuntimePersistenceError(
                "runtime downstream finalization rolled back"
            ) from exc
        self._observed_group_ids.update(committed_group_ids)
        self._observed_hypothesis_ids.update(committed_hypothesis_ids)
        return updated
