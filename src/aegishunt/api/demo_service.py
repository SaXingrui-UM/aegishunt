"""Idempotent controlled sample demonstration orchestration."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from aegishunt.api.contracts import DemoRequest, DemoResult, DemoStatus
from aegishunt.api.errors import ApiError
from aegishunt.cases.config import load_case_feedback_policy
from aegishunt.cases.service import InvestigationCaseService
from aegishunt.config import ApplicationSettings
from aegishunt.demo import DemoArtifactManager
from aegishunt.ingestion.service import IngestionService
from aegishunt.runtime.config import load_runtime_policy
from aegishunt.runtime.contracts import RuntimeJobStatus
from aegishunt.runtime.repositories import RuntimeJobRepository
from aegishunt.runtime.service import RuntimeJobService
from aegishunt.runtime.worker import RuntimeWorkerProcess
from aegishunt.schemas.base import JsonObject
from aegishunt.storage import Database
from aegishunt.storage.repositories import (
    AlertGroupRepository,
    DetectionResultRepository,
    InvestigationCaseRepository,
    NetworkFlowRepository,
    SecurityAlertRepository,
    TelemetrySourceRepository,
    ThreatHypothesisRepository,
)


class SampleDemoService:
    """Run the existing Phase 2–11 pipeline with isolated verified artifacts."""

    def __init__(self, database: Database, settings: ApplicationSettings) -> None:
        self._database = database
        self._settings = settings
        self._ingestion = IngestionService(
            database,
            settings.ingestion,
            flow_settings=settings.flows,
        )
        self._project_root = self._find_project_root(settings.ingestion.sample_root)
        self._artifacts = DemoArtifactManager(
            settings,
            project_root=self._project_root,
        )

    @staticmethod
    def _find_project_root(sample_root: Path) -> Path:
        resolved = sample_root.resolve()
        manifest = resolved / "manifest.yaml"
        if not manifest.is_file() or resolved.name != "sample":
            raise ApiError(
                "configured sample root is unavailable",
                code="demo_sample_root_unavailable",
                status_code=503,
            )
        project_root = resolved.parent.parent
        if not (project_root / "pyproject.toml").is_file():
            raise ApiError(
                "configured sample root is not within the project",
                code="demo_project_root_unavailable",
                status_code=503,
            )
        return project_root

    def status(self) -> DemoStatus:
        if not self._settings.web.sample_mode_enabled:
            return DemoStatus(
                available=False,
                sample_ids=[],
                previous_run=None,
                limitations=("sample demonstration mode is disabled by configuration",),
            )
        descriptors = {item.sample_id: item for item in self._ingestion.list_samples()}
        available_ids = [
            sample_id
            for sample_id in self._settings.web.demo_sample_ids
            if sample_id in descriptors
        ]
        previous_candidates: list[tuple[datetime, JsonObject]] = []
        with self._database.session() as session:
            for sample_id in available_ids:
                descriptor = descriptors[sample_id]
                source = TelemetrySourceRepository(session).get_by_checksum(
                    descriptor.checksum
                )
                runtime_job = (
                    None
                    if source is None
                    else RuntimeJobRepository(session).get_by_source(source.source_id)
                )
                if source is None:
                    continue
                payload: JsonObject = {
                    "namespace": self._namespace,
                    "sample_id": sample_id,
                    "source_id": str(source.source_id),
                    "runtime_job_id": (
                        None if runtime_job is None else str(runtime_job.job_id)
                    ),
                    "runtime_status": (
                        None if runtime_job is None else runtime_job.status.value
                    ),
                }
                updated_at = (
                    runtime_job.updated_at
                    if runtime_job is not None
                    else source.completed_at
                    or source.started_at
                    or datetime.min.replace(tzinfo=UTC)
                )
                previous_candidates.append((updated_at, payload))
        previous = (
            max(previous_candidates, key=lambda item: item[0])[1]
            if previous_candidates
            else None
        )
        return DemoStatus(
            available=bool(available_ids),
            sample_ids=available_ids,
            previous_run=previous,
            limitations=(
                "explicit local action only; no network, root, or live capture",
                "controlled synthetic pipeline verification only",
                "not a public benchmark or production validation",
                (
                    "demo-only artifacts are checksum-verified and reused"
                    if self._artifacts.is_prepared()
                    else "demo-only artifacts will be created only after confirmation"
                ),
            ),
        )

    @property
    def _namespace(self) -> str:
        return (
            f"{self._settings.web.demo_namespace}:"
            f"{self._settings.web.demo_operation_version}"
        )

    def run(self, request: DemoRequest) -> DemoResult:
        if not self._settings.web.sample_mode_enabled:
            raise ApiError(
                "sample demonstration mode is disabled",
                code="demo_mode_disabled",
                status_code=409,
            )
        if request.sample_id not in self._settings.web.demo_sample_ids:
            raise ApiError(
                "sample ID is not allowlisted for the full demonstration",
                code="demo_sample_not_allowlisted",
                status_code=400,
            )
        self._database.initialize()
        environment = self._artifacts.prepare()
        descriptor = next(
            (
                item
                for item in self._ingestion.list_samples()
                if item.sample_id == request.sample_id
            ),
            None,
        )
        if descriptor is None:
            raise ApiError(
                "sample ID is not available",
                code="demo_sample_unavailable",
                status_code=503,
            )
        with self._database.session() as session:
            source = TelemetrySourceRepository(session).get_by_checksum(
                descriptor.checksum
            )
        if source is None:
            ingestion_job = self._ingestion.ingest_sample(
                request.sample_id,
                actor=request.actor,
            )
            source_id = ingestion_job.job_id
        else:
            source_id = source.source_id

        runtime = self._runtime(environment.settings)
        with self._database.session() as session:
            runtime_job = RuntimeJobRepository(session).get_by_source(source_id)
        if runtime_job is None:
            runtime_job = runtime.create_replay(
                source_id,
                actor=request.actor,
                speed=self._settings.web.demo_replay_speed,
            )
        if runtime_job.status is RuntimeJobStatus.QUEUED:
            RuntimeWorkerProcess(
                self._database,
                settings=environment.settings,
                runtime_policy=load_runtime_policy(
                    environment.settings.runtime.policy_path
                ),
                project_root=self._project_root,
                worker_id=self._settings.web.demo_worker_id,
            ).run_one_and_stop()
            runtime_job = runtime.get(runtime_job.job_id)
        if runtime_job.status is not RuntimeJobStatus.COMPLETED:
            raise ApiError(
                "sample runtime job did not complete",
                code="demo_runtime_incomplete",
                status_code=409,
            )

        (
            flow_ids,
            alert_ids,
            group_ids,
            hypothesis_ids,
        ) = self._output_ids(source_id)
        if not flow_ids or not alert_ids or not group_ids or not hypothesis_ids:
            raise ApiError(
                "sample pipeline completed without the required traced outputs",
                code="demo_output_incomplete",
                status_code=409,
            )
        case_id = (
            self._create_case(hypothesis_ids[0], actor=request.actor)
            if request.create_case
            else None
        )
        return DemoResult(
            namespace=self._namespace,
            source_id=source_id,
            runtime_job_id=runtime_job.job_id,
            flow_ids=flow_ids,
            alert_ids=alert_ids,
            group_ids=group_ids,
            hypothesis_ids=hypothesis_ids,
            case_id=case_id,
            state="completed",
            limitations=(
                "controlled synthetic pipeline verification only",
                "not a public benchmark or production validation",
                "risk and correlation scores are not attack probabilities",
                "alerts and hypotheses require analyst review and are not facts",
                (
                    "verified demo-only artifacts were reused"
                    if environment.reused
                    else "verified demo-only artifacts were created in an isolated namespace"
                ),
            ),
        )

    def _runtime(self, settings: ApplicationSettings) -> RuntimeJobService:
        return RuntimeJobService(
            self._database,
            settings=settings,
            runtime_policy=load_runtime_policy(settings.runtime.policy_path),
            project_root=self._project_root,
        )

    def _output_ids(
        self,
        source_id: UUID,
    ) -> tuple[list[UUID], list[UUID], list[UUID], list[UUID]]:
        with self._database.session() as session:
            flows = NetworkFlowRepository(session).list_by_source(source_id)
            detections = [
                detection
                for flow in flows
                if (
                    detection := DetectionResultRepository(session).get_by_flow(
                        flow.flow_id
                    )
                )
                is not None
            ]
            alerts = [
                alert
                for detection in detections
                if (
                    alert := SecurityAlertRepository(session).get_by_detection(
                        detection.detection_id
                    )
                )
                is not None
            ]
            alert_ids = {str(item.alert_id) for item in alerts}
            groups = [
                item
                for item in AlertGroupRepository(session).list()
                if not alert_ids.isdisjoint(item.alert_ids)
            ]
            group_ids = {item.group_id for item in groups}
            hypotheses = [
                item
                for item in ThreatHypothesisRepository(session).list()
                if item.group_id in group_ids
            ]
        return (
            [item.flow_id for item in flows],
            [item.alert_id for item in alerts],
            [item.group_id for item in groups],
            [item.hypothesis_id for item in hypotheses],
        )

    def _create_case(self, hypothesis_id: UUID, *, actor: str) -> UUID:
        with self._database.session() as session:
            existing = InvestigationCaseRepository(session).get_by_hypothesis(
                hypothesis_id
            )
        if existing is not None:
            return existing.case_id
        loaded = load_case_feedback_policy(self._settings.case_feedback.policy_path)
        with self._database.session() as session, session.begin():
            created = InvestigationCaseService(
                session,
                loaded,
            ).create_from_hypothesis(hypothesis_id, actor=actor)
        return created.case_id
