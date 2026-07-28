"""Phase 12 API, sample demo, and persisted workflow E2E."""

from __future__ import annotations

import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import httpx
from fastapi.testclient import TestClient

from aegishunt.api.app import create_app
from aegishunt.cases.config import load_case_feedback_policy
from aegishunt.cases.service import InvestigationCaseService
from aegishunt.config import (
    AnomalySettings,
    ApplicationSection,
    ApplicationSettings,
    DatabaseSettings,
    DatasetSettings,
    IngestionSettings,
    SupervisedSettings,
    WebSettings,
)
from aegishunt.detection.config import load_risk_policy
from aegishunt.frontend.client import AegisHuntApiClient
from aegishunt.ml.fusion.config import FusionExperimentConfig
from aegishunt.ml.supervised.config import (
    PORTABLE_DEMO_SELECTION_POLICY_VERSION,
    SupervisedTrainingConfig,
)
from aegishunt.ml.supervised.contracts import ModelSelectionRecord
from aegishunt.runtime.config import load_runtime_policy
from aegishunt.schemas.enums import AnalystVerdict
from aegishunt.storage import Database
from tests.fixtures.cases import seed_reviewable_hypothesis
from tests.fixtures.hunting import alert

ROOT = Path(__file__).parents[2]


def _settings(tmp_path: Path, *, pcap_limit: int = 52_428_800) -> ApplicationSettings:
    return ApplicationSettings(
        application=ApplicationSection(environment="phase12-test"),
        database=DatabaseSettings(url=f"sqlite:///{tmp_path / 'phase12.db'}"),
        ingestion=IngestionSettings(
            storage_root=tmp_path / "raw",
            sample_root=ROOT / "data/sample",
        ),
        datasets=DatasetSettings(
            registry_path=ROOT / "configs/datasets/registry.yaml",
            label_mapping_root=ROOT / "configs/label_mappings",
            raw_root=tmp_path / "dataset-raw",
            interim_root=tmp_path / "dataset-interim",
            processed_root=tmp_path / "dataset-processed",
            reports_root=tmp_path / "dataset-reports",
        ),
        supervised=SupervisedSettings(
            training_config_path=ROOT / "configs/models/supervised.yaml",
            artifact_root=tmp_path / "models/supervised",
            reports_root=tmp_path / "reports/supervised",
        ),
        anomaly=AnomalySettings(
            training_config_path=ROOT / "configs/models/anomaly.yaml",
            artifact_root=tmp_path / "models/anomaly",
            reports_root=tmp_path / "reports/anomaly",
        ),
        web=WebSettings(
            maximum_pcap_upload_bytes=pcap_limit,
            demo_artifact_root=Path("tmp") / f"phase12-demo-{uuid4().hex}",
        ),
    )


def _seed_database(database: Database) -> str:
    now = datetime.now(UTC)
    source_alerts = [
        alert(1, destination_ip="198.51.100.10", seconds=0),
        alert(2, destination_ip="198.51.100.11", seconds=10),
        alert(3, destination_ip="198.51.100.12", seconds=20),
    ]
    source_alerts = [
        item.model_copy(
            update={
                "created_at": now - timedelta(hours=2),
                "updated_at": now - timedelta(hours=2),
            }
        )
        for item in source_alerts
    ]
    hypothesis = seed_reviewable_hypothesis(database, source_alerts=source_alerts)
    return str(hypothesis.hypothesis_id)


def test_phase12_api_workflow_is_persistent_and_truthful(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    database = Database(settings.database)
    database.initialize()
    hypothesis_id = _seed_database(database)

    with TestClient(create_app(settings, database)) as client:
        health = client.get("/system/status")
        assert health.status_code == 200
        assert health.json()["authentication"] == "not_implemented_local_single_user"

        summary = client.get("/flows/summary").json()
        assert summary["total"] == 3
        assert summary["total_packets"] > 0
        assert client.get("/flows", params={"protocol": "tcp"}).json()["total"] == 3

        alerts = client.get("/alerts").json()
        assert alerts["total"] == 3
        alert_id = alerts["items"][0]["alert_id"]
        detail = client.get(f"/alerts/{alert_id}").json()
        assert "risk score is not attack probability" in detail["limitations"]
        updated = client.patch(
            f"/alerts/{alert_id}",
            json={
                "actor": "phase12-analyst",
                "reason": "explicit API verdict",
                "analyst_verdict": "needs_more_information",
            },
        )
        assert updated.status_code == 200
        assert updated.json()["analyst_verdict"] == "needs_more_information"

        groups = client.get("/alert-groups").json()
        assert groups["total"] == 1
        group_detail = client.get(f"/alert-groups/{groups['items'][0]['group_id']}")
        assert group_detail.status_code == 200

        hypothesis = client.get(f"/hypotheses/{hypothesis_id}").json()
        assert hypothesis["case_id"] is None
        created = client.post(
            f"/hypotheses/{hypothesis_id}/create-case",
            json={
                "actor": "phase12-analyst",
                "reason": "explicit investigation",
                "confirm": True,
            },
        )
        assert created.status_code == 200
        case_id = created.json()["case_id"]
        note = client.post(
            f"/cases/{case_id}/notes",
            json={
                "actor": "phase12-analyst",
                "reason": "document evidence review",
                "body": "Review started from bounded API evidence.",
                "note_type": "investigation",
            },
        )
        assert note.status_code == 200
        verdict = client.patch(
            f"/cases/{case_id}",
            json={
                "actor": "phase12-analyst",
                "reason": "record bounded case judgment",
                "verdict": "needs_more_information",
                "verdict_confidence": 0.6,
            },
        )
        assert verdict.status_code == 200
        feedback = client.post(
            f"/feedback/cases/{case_id}",
            json={
                "actor": "phase12-analyst",
                "reason": "explicit human judgment",
                "verdict": "needs_more_information",
                "confidence": 0.6,
                "notes": "Human-supplied and potentially noisy.",
            },
        )
        assert feedback.status_code == 200
        case_detail = client.get(f"/cases/{case_id}").json()
        assert len(case_detail["notes"]) == 1
        assert len(case_detail["feedback"]) == 2

        model_page = client.get("/models").json()
        assert model_page["items"][0]["engine"] == "fusion"
        assert model_page["items"][0]["state"] == "unavailable"
        importance = client.get(
            f"/models/{model_page['items'][0]['model_id']}/importance"
        )
        assert importance.status_code == 200
        assert importance.json()["available"] is False
        denied_training = client.post(
            "/models/train",
            json={
                "actor": "phase12-analyst",
                "reason": "verify approved dataset gate",
                "confirm": True,
                "engine": "supervised",
                "profile": "supervised-default",
                "new_version": "1.0.0",
                "approved_dataset_identity": "unapproved:1.0.0",
            },
        )
        assert denied_training.status_code == 409
        assert denied_training.json()["error_code"] == "state_conflict"
        evaluations = client.get("/evaluation").json()
        assert evaluations["items"][0]["metrics"] is None
        assert evaluations["items"][0]["provenance"]["recommendation"] == "inconclusive"

    with TestClient(create_app(settings, database)) as restarted:
        persisted = restarted.get(f"/cases/{case_id}")
        assert persisted.status_code == 200
        assert persisted.json()["case"]["case_id"] == case_id
    database.dispose()


def test_sample_demo_runs_full_existing_pipeline_idempotently(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    database = Database(settings.database)
    with TestClient(create_app(settings, database)) as client:
        payload = {
            "actor": "demo-user",
            "reason": "explicit controlled demo",
            "confirm": True,
            "sample_id": "phase12-demo-pcap",
            "create_case": True,
        }
        first = client.post("/demo/sample", json=payload)
        second = client.post("/demo/sample", json=payload)
        assert first.status_code == 200, first.text
        assert second.status_code == 200, second.text
        assert first.json()["source_id"] == second.json()["source_id"]
        assert first.json()["flow_ids"] == second.json()["flow_ids"]
        assert first.json()["runtime_job_id"] == second.json()["runtime_job_id"]
        assert first.json()["alert_ids"] == second.json()["alert_ids"]
        assert first.json()["group_ids"] == second.json()["group_ids"]
        assert first.json()["hypothesis_ids"] == second.json()["hypothesis_ids"]
        assert first.json()["case_id"] == second.json()["case_id"]
        assert len(first.json()["flow_ids"]) == 2
        assert len(first.json()["alert_ids"]) == 2
        assert first.json()["group_ids"]
        assert first.json()["hypothesis_ids"]
        assert first.json()["case_id"] is not None
        assert first.json()["state"] == "completed"
        assert (
            client.get(f"/runtime/jobs/{first.json()['runtime_job_id']}").json()["job"][
                "status"
            ]
            == "completed"
        )
        assert client.get("/detections").json()["total"] == 2
        flow_detection = client.get(
            "/detections",
            params={"flow_id": first.json()["flow_ids"][0]},
        ).json()
        assert flow_detection["total"] == 1
        assert flow_detection["items"][0]["flow_id"] == first.json()["flow_ids"][0]
        assert client.get("/alerts").json()["total"] == 2
        assert client.get("/alert-groups").json()["total"] >= 1
        assert client.get("/hypotheses").json()["total"] >= 1
        case_id = first.json()["case_id"]
        assert case_id is not None
        assert client.get(f"/cases/{case_id}").status_code == 200
        verdict = client.patch(
            f"/cases/{case_id}",
            json={
                "actor": "demo-user",
                "reason": "record bounded demo judgment",
                "verdict": "needs_more_information",
                "verdict_confidence": 0.6,
            },
        )
        assert verdict.status_code == 200
        feedback = client.post(
            f"/feedback/cases/{case_id}",
            json={
                "actor": "demo-user",
                "reason": "explicit controlled demo feedback",
                "verdict": "needs_more_information",
                "confidence": 0.6,
                "notes": "Controlled synthetic evidence requires more information.",
            },
        )
        assert feedback.status_code == 200
        case_detail = client.get(f"/cases/{case_id}").json()
        assert case_detail["case"]["verdict"] == "needs_more_information"
        assert len(case_detail["feedback"]) == 2
        assert "controlled synthetic pipeline verification only" in first.json()["limitations"]

        def api_transport(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if request.url.query:
                path = f"{path}?{request.url.query.decode()}"
            response = client.request(
                request.method,
                path,
                content=request.content,
                headers=dict(request.headers),
            )
            return httpx.Response(
                response.status_code,
                content=response.content,
                headers=dict(response.headers),
                request=request,
            )

        with AegisHuntApiClient(
            "http://127.0.0.1:8000",
            transport=httpx.MockTransport(api_transport),
        ) as frontend:
            assert frontend.system_status().phase == "12"
            assert frontend.runtime_status().status.latest_jobs[0].status.value == "completed"
            assert frontend.flows().total == 2
            assert frontend.detections().total == 2
            assert frontend.alerts().total == 2
            assert frontend.groups().total >= 1
            assert frontend.hypotheses().total >= 1
            assert frontend.cases().total == 1
            assert frontend.case(case_id).case.verdict == "needs_more_information"
            assert frontend.feedback().total == 2
            assert frontend.models().items[0].engine == "fusion"
            assert frontend.evaluations().items[0].engine == "fusion"
            assert frontend.demo_status().previous_run is not None
    demo_root = (
        ROOT
        / settings.web.demo_artifact_root
        / f"{settings.web.demo_namespace}-{settings.web.demo_operation_version}"
    )
    assert demo_root.is_dir()
    assert not settings.supervised.artifact_root.exists()
    assert not settings.anomaly.artifact_root.exists()
    supervised_config = SupervisedTrainingConfig.load(
        demo_root / "configs/supervised.yaml"
    )
    selection = ModelSelectionRecord.model_validate_json(
        (
            demo_root
            / "reports/supervised/phase-12-controlled-demo-supervised"
            / "model_selection.json"
        ).read_text(encoding="utf-8")
    )
    fusion_config = FusionExperimentConfig.load(demo_root / "configs/fusion.yaml")
    risk = load_risk_policy(demo_root / "configs/detection.yaml").policy
    runtime = load_runtime_policy(demo_root / "configs/runtime.yaml").policy
    assert supervised_config.model_version == "12.0.0"
    assert (
        supervised_config.selection_policy_version
        == PORTABLE_DEMO_SELECTION_POLICY_VERSION
    )
    assert supervised_config.corrective_run is None
    assert selection.experiment_id == "phase-12-controlled-demo-supervised"
    assert selection.model_version == "12.0.0"
    assert selection.selection_policy_version == PORTABLE_DEMO_SELECTION_POLICY_VERSION
    assert selection.corrective_evidence is None
    assert selection.test_data_accessed is False
    assert selection.pipeline_verification_only is True
    assert selection.algorithm == fusion_config.supervised_algorithm
    assert selection.hyperparameters == fusion_config.supervised_hyperparameters
    assert selection.calibration_method == fusion_config.supervised_calibration
    assert selection.model_id == fusion_config.supervised_model_id
    assert selection.model_version == fusion_config.supervised_model_version
    assert risk.required_supervised_model_id == selection.model_id
    assert risk.required_supervised_model_version == selection.model_version
    assert risk.required_fusion_policy_id == fusion_config.policy_id
    assert risk.required_fusion_policy_version == fusion_config.policy_version
    assert runtime.supervised_model_version == selection.model_version
    assert runtime.fusion_policy_version == fusion_config.policy_version
    database.dispose()
    if demo_root.is_dir() and not demo_root.is_symlink():
        shutil.rmtree(demo_root)


def test_upload_limit_validation_error_and_request_id_are_sanitized(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path, pcap_limit=1)
    database = Database(settings.database)
    with TestClient(create_app(settings, database)) as client:
        response = client.post(
            "/ingestion/pcap",
            files={"file": ("sample.pcap", b"too large", "application/vnd.tcpdump.pcap")},
            data={
                "actor": "phase12-test",
                "reason": "verify bounded upload",
                "confirm": "true",
            },
            headers={"X-Request-ID": "phase12-upload"},
        )
        assert response.status_code == 413
        assert response.headers["X-Request-ID"] == "phase12-upload"
        assert response.json() == {
            "error_code": "upload_too_large",
            "message": "upload exceeds the configured limit",
            "request_id": "phase12-upload",
            "details": None,
            "retryable": False,
            "status_code": 413,
        }
        invalid = client.patch(
            "/alerts/not-a-uuid",
            json={"actor": "", "reason": "", "analyst_verdict": "invalid"},
        )
        assert invalid.status_code == 422
        assert "traceback" not in invalid.text.lower()
        assert str(tmp_path) not in invalid.text
    database.dispose()


def test_case_service_still_uses_existing_phase10_policy(tmp_path: Path) -> None:
    """Guard against a duplicate Phase 12 case workflow."""

    settings = _settings(tmp_path)
    database = Database(settings.database)
    database.initialize()
    hypothesis_id = _seed_database(database)
    with database.session() as session, session.begin():
        case = InvestigationCaseService(
            session,
            load_case_feedback_policy(settings.case_feedback.policy_path),
        ).create_from_hypothesis(
            UUID(hypothesis_id),
            actor="existing-service",
        )
        updated = InvestigationCaseService(
            session,
            load_case_feedback_policy(settings.case_feedback.policy_path),
        ).set_verdict(
            case.case_id,
            AnalystVerdict.NEEDS_MORE_INFORMATION,
            confidence=0.5,
            reason="existing Phase 10 mutation service",
            actor="existing-service",
        )
    assert updated.verdict is AnalystVerdict.NEEDS_MORE_INFORMATION
    database.dispose()
