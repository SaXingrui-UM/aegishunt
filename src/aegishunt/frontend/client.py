"""Typed HTTP client used by every production Streamlit page."""

from __future__ import annotations

from collections.abc import Mapping
from types import TracebackType
from typing import Any, BinaryIO, Literal, TypeVar

import httpx
from pydantic import BaseModel

from aegishunt.api.contracts import (
    AlertDetail,
    AlertGroupDetail,
    AlertGroupPage,
    AnalystFeedbackPage,
    ArtifactResult,
    CaseAuditEventPage,
    CaseDetail,
    DemoResult,
    DemoStatus,
    DetectionDetail,
    DetectionResultPage,
    EffectiveModelState,
    EvaluationDescriptor,
    EvaluationPage,
    EvaluationSummary,
    FlowSummary,
    FusionEvaluationDiscovery,
    HypothesisDetail,
    InvestigationCasePage,
    ModelDescriptor,
    ModelImportance,
    ModelPage,
    NetworkFlowPage,
    ReplayStatistics,
    RuntimeJobDetail,
    RuntimeJobPage,
    RuntimeOverview,
    RuntimeRunOnceResult,
    RuntimeWorkerPage,
    SecurityAlertPage,
    SystemStatus,
    TelemetrySourcePage,
    ThreatHypothesisPage,
)
from aegishunt.ingestion.schemas import IngestionJob, IngestionJobPage, SampleDescriptor
from aegishunt.runtime.contracts import RuntimeJob
from aegishunt.schemas import (
    AnalystFeedback,
    CaseEvidenceReference,
    CaseNote,
    InvestigationCase,
    NetworkFlow,
    SecurityAlert,
    ThreatHypothesis,
)

ResponseT = TypeVar("ResponseT", bound=BaseModel)


class ApiClientError(RuntimeError):
    """Sanitized frontend-visible API or transport failure."""

    def __init__(
        self,
        message: str,
        *,
        error_code: str = "api_unavailable",
        request_id: str | None = None,
        status_code: int | None = None,
        retryable: bool = False,
    ) -> None:
        super().__init__(message)
        self.error_code = error_code
        self.request_id = request_id
        self.status_code = status_code
        self.retryable = retryable


class AegisHuntApiClient:
    """Bounded typed client; it never opens SQLite or artifact paths."""

    def __init__(
        self,
        base_url: str,
        *,
        timeout_seconds: float = 15.0,
        runtime_worker_timeout_seconds: float = 600.0,
        page_size: int = 50,
        actor_header: str = "X-AegisHunt-Actor",
        safe_download_types: tuple[str, ...] = (
            "case_report",
            "feedback_export",
            "retraining_candidate",
        ),
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not 1 <= page_size <= 100:
            raise ValueError("frontend page size must be between 1 and 100")
        if timeout_seconds <= 0.0 or runtime_worker_timeout_seconds <= 0.0:
            raise ValueError("frontend request timeouts must be positive")
        self._client = httpx.Client(
            base_url=base_url.rstrip("/"),
            timeout=timeout_seconds,
            transport=transport,
            follow_redirects=False,
        )
        self._page_size = page_size
        self._runtime_worker_timeout_seconds = runtime_worker_timeout_seconds
        self._actor_header = actor_header
        self._safe_download_types = frozenset(safe_download_types)

    def __enter__(self) -> AegisHuntApiClient:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc_value, traceback
        self.close()

    def close(self) -> None:
        self._client.close()

    def _request(
        self,
        method: str,
        path: str,
        response_type: type[ResponseT],
        *,
        params: Mapping[str, object] | None = None,
        json: Mapping[str, object] | None = None,
        files: Mapping[str, Any] | None = None,
        data: Mapping[str, object] | None = None,
        timeout_seconds: float | None = None,
    ) -> ResponseT:
        clean_params = {
            key: str(value)
            for key, value in (params or {}).items()
            if value is not None and value != ""
        }
        actor = (json or {}).get("actor") or (data or {}).get("actor")
        headers = (
            {self._actor_header: str(actor)}
            if isinstance(actor, str) and actor.strip()
            else None
        )
        try:
            request_options: dict[str, Any] = {
                "params": clean_params,
                "json": json,
                "files": files,
                "data": data,
                "headers": headers,
            }
            if timeout_seconds is not None:
                request_options["timeout"] = timeout_seconds
            response = self._client.request(method, path, **request_options)
        except httpx.RequestError as exc:
            raise ApiClientError("AegisHunt API is unavailable") from exc
        if response.is_error:
            try:
                payload = response.json()
            except ValueError as exc:
                raise ApiClientError(
                    "AegisHunt API returned an invalid error response",
                    status_code=response.status_code,
                ) from exc
            raise ApiClientError(
                str(payload.get("message", "request could not be completed")),
                error_code=str(payload.get("error_code", "api_error")),
                request_id=(
                    str(payload["request_id"]) if payload.get("request_id") else None
                ),
                status_code=response.status_code,
                retryable=bool(payload.get("retryable", False)),
            )
        return response_type.model_validate(response.json())

    def _get(
        self,
        path: str,
        response_type: type[ResponseT],
        params: Mapping[str, object] | None = None,
    ) -> ResponseT:
        return self._request("GET", path, response_type, params=params)

    def system_status(self) -> SystemStatus:
        return self._get("/system/status", SystemStatus)

    def runtime_status(self) -> RuntimeOverview:
        return self._get("/runtime/status", RuntimeOverview)

    def runtime_jobs(self, *, limit: int | None = None, offset: int = 0) -> RuntimeJobPage:
        return self._get(
            "/runtime/jobs",
            RuntimeJobPage,
            {"limit": limit or self._page_size, "offset": offset},
        )

    def runtime_job(self, job_id: str) -> RuntimeJobDetail:
        return self._get(f"/runtime/jobs/{job_id}", RuntimeJobDetail)

    def replay_statistics(self, source_id: str) -> ReplayStatistics:
        return self._get(
            f"/runtime/replay-statistics/{source_id}",
            ReplayStatistics,
        )

    def runtime_workers(
        self, *, limit: int | None = None, offset: int = 0
    ) -> RuntimeWorkerPage:
        return self._get(
            "/runtime/workers",
            RuntimeWorkerPage,
            {"limit": limit or self._page_size, "offset": offset},
        )

    def runtime_action(
        self,
        job_id: str,
        action: str,
        *,
        actor: str,
        reason: str,
    ) -> RuntimeJob:
        if action not in {"pause", "resume", "recover"}:
            raise ValueError("runtime action is not allowlisted")
        return self._request(
            "POST",
            f"/runtime/jobs/{job_id}/{action}",
            RuntimeJob,
            json={"actor": actor, "reason": reason},
        )

    def run_runtime_worker_once(
        self,
        *,
        actor: str,
        reason: str,
    ) -> RuntimeRunOnceResult:
        return self._request(
            "POST",
            "/runtime/workers/run-once",
            RuntimeRunOnceResult,
            json={
                "actor": actor,
                "reason": reason,
                "confirm": True,
            },
            timeout_seconds=self._runtime_worker_timeout_seconds,
        )

    def ingestion_jobs(
        self, *, limit: int | None = None, offset: int = 0
    ) -> IngestionJobPage:
        return self._get(
            "/ingestion/jobs",
            IngestionJobPage,
            {"limit": limit or self._page_size, "offset": offset},
        )

    def telemetry_sources(
        self, *, limit: int | None = None, offset: int = 0
    ) -> TelemetrySourcePage:
        return self._get(
            "/ingestion/sources",
            TelemetrySourcePage,
            {"limit": limit or self._page_size, "offset": offset},
        )

    def samples(self) -> list[SampleDescriptor]:
        payload = self._client.get("/ingestion/samples")
        if payload.is_error:
            raise ApiClientError("sample registry is unavailable")
        return [SampleDescriptor.model_validate(item) for item in payload.json()]

    def ingest_sample(
        self,
        sample_id: str,
        *,
        actor: str,
        reason: str,
    ) -> IngestionJob:
        return self._request(
            "POST",
            "/ingestion/sample",
            IngestionJob,
            json={
                "sample_id": sample_id,
                "actor": actor,
                "reason": reason,
                "confirm": True,
            },
        )

    def upload(
        self,
        kind: str,
        *,
        filename: str,
        stream: BinaryIO,
        content_type: str,
        actor: str,
        reason: str,
    ) -> IngestionJob:
        if kind not in {"pcap", "csv", "json"}:
            raise ValueError("upload type is not allowlisted")
        return self._request(
            "POST",
            f"/ingestion/{kind}",
            IngestionJob,
            files={"file": (filename, stream, content_type)},
            data={"actor": actor, "reason": reason, "confirm": "true"},
        )

    def create_replay(
        self,
        source_id: str,
        *,
        speed: float,
        actor: str,
        reason: str,
    ) -> RuntimeJob:
        return self._request(
            "POST",
            "/ingestion/replay",
            RuntimeJob,
            json={
                "source_id": source_id,
                "speed": speed,
                "run_now": False,
                "actor": actor,
                "reason": reason,
                "confirm": True,
            },
        )

    def flows(self, **filters: object) -> NetworkFlowPage:
        filters.setdefault("limit", self._page_size)
        return self._get("/flows", NetworkFlowPage, filters)

    def flow(self, flow_id: str) -> NetworkFlow:
        return self._get(f"/flows/{flow_id}", NetworkFlow)

    def flow_summary(self, *, job_id: str | None = None) -> FlowSummary:
        return self._get("/flows/summary", FlowSummary, {"job_id": job_id})

    def alerts(self, **filters: object) -> SecurityAlertPage:
        filters.setdefault("limit", self._page_size)
        return self._get("/alerts", SecurityAlertPage, filters)

    def detections(self, **filters: object) -> DetectionResultPage:
        filters.setdefault("limit", self._page_size)
        return self._get("/detections", DetectionResultPage, filters)

    def detection(self, detection_id: str) -> DetectionDetail:
        return self._get(f"/detections/{detection_id}", DetectionDetail)

    def alert(self, alert_id: str) -> AlertDetail:
        return self._get(f"/alerts/{alert_id}", AlertDetail)

    def update_alert_verdict(
        self,
        alert_id: str,
        *,
        verdict: str,
        actor: str,
        reason: str,
    ) -> SecurityAlert:
        return self._request(
            "PATCH",
            f"/alerts/{alert_id}",
            SecurityAlert,
            json={
                "analyst_verdict": verdict,
                "actor": actor,
                "reason": reason,
            },
        )

    def groups(
        self, *, limit: int | None = None, offset: int = 0, **filters: object
    ) -> AlertGroupPage:
        filters.update({"limit": limit or self._page_size, "offset": offset})
        return self._get(
            "/alert-groups",
            AlertGroupPage,
            filters,
        )

    def group(self, group_id: str) -> AlertGroupDetail:
        return self._get(f"/alert-groups/{group_id}", AlertGroupDetail)

    def hypotheses(
        self, *, limit: int | None = None, offset: int = 0, **filters: object
    ) -> ThreatHypothesisPage:
        filters.update({"limit": limit or self._page_size, "offset": offset})
        return self._get(
            "/hypotheses",
            ThreatHypothesisPage,
            filters,
        )

    def hypothesis(self, hypothesis_id: str) -> HypothesisDetail:
        return self._get(f"/hypotheses/{hypothesis_id}", HypothesisDetail)

    def update_hypothesis(
        self,
        hypothesis_id: str,
        *,
        status: str,
        actor: str,
        reason: str,
    ) -> ThreatHypothesis:
        return self._request(
            "PATCH",
            f"/hypotheses/{hypothesis_id}",
            ThreatHypothesis,
            json={"status": status, "actor": actor, "reason": reason},
        )

    def create_case(
        self,
        hypothesis_id: str,
        *,
        actor: str,
        reason: str,
    ) -> InvestigationCase:
        return self._request(
            "POST",
            f"/hypotheses/{hypothesis_id}/create-case",
            InvestigationCase,
            json={"actor": actor, "reason": reason, "confirm": True},
        )

    def cases(
        self, *, limit: int | None = None, offset: int = 0, **filters: object
    ) -> InvestigationCasePage:
        filters.update({"limit": limit or self._page_size, "offset": offset})
        return self._get(
            "/cases",
            InvestigationCasePage,
            filters,
        )

    def case(self, case_id: str) -> CaseDetail:
        return self._get(f"/cases/{case_id}", CaseDetail)

    def case_audit_events(
        self,
        case_id: str,
        *,
        page: int = 1,
        page_size: int | None = None,
        action: str | None = None,
        actor: str | None = None,
        created_from: str | None = None,
        created_to: str | None = None,
        order: str = "desc",
    ) -> CaseAuditEventPage:
        if order not in {"asc", "desc"}:
            raise ValueError("audit order is not allowlisted")
        return self._get(
            f"/cases/{case_id}/audit-events",
            CaseAuditEventPage,
            {
                "page": page,
                "page_size": page_size or self._page_size,
                "action": action,
                "actor": actor,
                "created_from": created_from,
                "created_to": created_to,
                "order": order,
            },
        )

    def update_case(
        self,
        case_id: str,
        *,
        actor: str,
        reason: str,
        **update: object,
    ) -> InvestigationCase:
        return self._request(
            "PATCH",
            f"/cases/{case_id}",
            InvestigationCase,
            json={"actor": actor, "reason": reason, **update},
        )

    def add_case_note(
        self,
        case_id: str,
        *,
        body: str,
        actor: str,
        reason: str,
    ) -> CaseNote:
        return self._request(
            "POST",
            f"/cases/{case_id}/notes",
            CaseNote,
            json={
                "body": body,
                "note_type": "investigation",
                "actor": actor,
                "reason": reason,
            },
        )

    def add_case_evidence(
        self,
        case_id: str,
        *,
        object_type: str,
        object_id: str,
        description: str,
        actor: str,
        reason: str,
    ) -> CaseEvidenceReference:
        return self._request(
            "POST",
            f"/cases/{case_id}/evidence",
            CaseEvidenceReference,
            json={
                "object_type": object_type,
                "object_id": object_id,
                "description": description,
                "actor": actor,
                "reason": reason,
            },
        )

    def feedback(
        self, *, limit: int | None = None, offset: int = 0
    ) -> AnalystFeedbackPage:
        return self._get(
            "/feedback",
            AnalystFeedbackPage,
            {"limit": limit or self._page_size, "offset": offset},
        )

    def close_case(
        self,
        case_id: str,
        *,
        closure_note: str,
        actor: str,
        reason: str,
    ) -> InvestigationCase:
        return self._request(
            "POST",
            f"/cases/{case_id}/close",
            InvestigationCase,
            json={
                "closure_note": closure_note,
                "actor": actor,
                "reason": reason,
                "confirm": True,
            },
        )

    def generate_case_report(
        self,
        case_id: str,
        *,
        version: str,
        actor: str,
        reason: str,
    ) -> ArtifactResult:
        return self._request(
            "POST",
            f"/cases/{case_id}/report",
            ArtifactResult,
            json={
                "version": version,
                "actor": actor,
                "reason": reason,
                "confirm": True,
            },
        )

    def download_case_report(self, case_id: str, version: str) -> bytes:
        return self._download(
            f"/cases/{case_id}/reports/{version}",
            artifact_type="case_report",
        )

    def _download(self, path: str, *, artifact_type: str) -> bytes:
        if artifact_type not in self._safe_download_types:
            raise ValueError(f"{artifact_type} downloads are disabled by configuration")
        try:
            response = self._client.get(path)
        except httpx.RequestError as exc:
            raise ApiClientError("AegisHunt API is unavailable") from exc
        if response.is_error:
            try:
                payload = response.json()
            except ValueError as exc:
                raise ApiClientError(
                    "AegisHunt API returned an invalid error response",
                    status_code=response.status_code,
                ) from exc
            raise ApiClientError(
                str(payload.get("message", "request could not be completed")),
                error_code=str(payload.get("error_code", "api_error")),
                request_id=(
                    str(payload["request_id"]) if payload.get("request_id") else None
                ),
                status_code=response.status_code,
            )
        return response.content

    def download_data_artifact(
        self,
        version: str,
        *,
        retraining_candidates: bool = False,
    ) -> bytes:
        artifact_type = (
            "retraining_candidate" if retraining_candidates else "feedback_export"
        )
        path = (
            f"/feedback/retraining-candidates/{version}/download"
            if retraining_candidates
            else f"/feedback/exports/{version}/download"
        )
        return self._download(path, artifact_type=artifact_type)

    def export_feedback(
        self,
        *,
        version: str,
        actor: str,
        reason: str,
        retraining_candidates: bool = False,
    ) -> ArtifactResult:
        path = (
            "/feedback/retraining-candidates"
            if retraining_candidates
            else "/feedback/export"
        )
        return self._request(
            "POST",
            path,
            ArtifactResult,
            json={
                "version": version,
                "actor": actor,
                "reason": reason,
                "confirm": True,
            },
        )

    def add_feedback(
        self,
        object_type: str,
        object_id: str,
        *,
        verdict: str,
        confidence: float,
        notes: str,
        actor: str,
        reason: str,
    ) -> AnalystFeedback:
        if object_type not in {"alerts", "cases"}:
            raise ValueError("feedback object type is not allowlisted")
        return self._request(
            "POST",
            f"/feedback/{object_type}/{object_id}",
            AnalystFeedback,
            json={
                "verdict": verdict,
                "confidence": confidence,
                "notes": notes,
                "actor": actor,
                "reason": reason,
            },
        )

    def models(self, *, limit: int | None = None, offset: int = 0) -> ModelPage:
        return self._get(
            "/models",
            ModelPage,
            {"limit": limit or self._page_size, "offset": offset},
        )

    def effective_models(self) -> EffectiveModelState:
        return self._get("/models/effective", EffectiveModelState)

    def model(self, model_id: str) -> ModelDescriptor:
        return self._get(f"/models/{model_id}", ModelDescriptor)

    def model_importance(
        self,
        model_id: str,
        *,
        kind: Literal["native", "permutation"] = "native",
    ) -> ModelImportance:
        return self._get(
            f"/models/{model_id}/importance",
            ModelImportance,
            {"kind": kind},
        )

    def activate_model(
        self,
        model_id: str,
        *,
        actor: str,
        reason: str,
        expected_active_version: str | None,
    ) -> ModelDescriptor:
        return self._request(
            "POST",
            f"/models/{model_id}/activate",
            ModelDescriptor,
            json={
                "actor": actor,
                "reason": reason,
                "confirm": True,
                "expected_active_version": expected_active_version,
            },
        )

    def train_model(
        self,
        *,
        engine: str,
        profile: str,
        new_version: str,
        approved_dataset_identity: str,
        actor: str,
        reason: str,
    ) -> ModelDescriptor:
        return self._request(
            "POST",
            "/models/train",
            ModelDescriptor,
            json={
                "engine": engine,
                "profile": profile,
                "new_version": new_version,
                "approved_dataset_identity": approved_dataset_identity,
                "actor": actor,
                "reason": reason,
                "confirm": True,
            },
        )

    def evaluations(
        self, *, limit: int | None = None, offset: int = 0
    ) -> EvaluationPage:
        return self._get(
            "/evaluation",
            EvaluationPage,
            {"limit": limit or self._page_size, "offset": offset},
        )

    def evaluation(self, run_id: str) -> EvaluationDescriptor:
        return self._get(f"/evaluation/{run_id}", EvaluationDescriptor)

    def evaluation_summary(self) -> EvaluationSummary:
        return self._get("/evaluation/summary", EvaluationSummary)

    def fusion_evaluation_status(self) -> FusionEvaluationDiscovery:
        return self._get("/evaluation/fusion-status", FusionEvaluationDiscovery)

    def demo_status(self) -> DemoStatus:
        return self._get("/demo/status", DemoStatus)

    def run_demo(
        self,
        sample_id: str,
        *,
        actor: str,
        reason: str,
        create_case: bool = False,
    ) -> DemoResult:
        return self._request(
            "POST",
            "/demo/sample",
            DemoResult,
            json={
                "sample_id": sample_id,
                "actor": actor,
                "reason": reason,
                "create_case": create_case,
                "confirm": True,
            },
        )
