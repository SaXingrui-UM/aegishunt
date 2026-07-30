"""Final PCAP-to-analyst-feedback delivery demonstration."""

from __future__ import annotations

import shutil
from pathlib import Path
from uuid import uuid4

import yaml
from fastapi.testclient import TestClient

from aegishunt.api.app import create_app
from aegishunt.config import (
    AnomalySettings,
    ApplicationSection,
    ApplicationSettings,
    CaseFeedbackSettings,
    DatabaseSettings,
    DatasetSettings,
    IngestionSettings,
    SupervisedSettings,
    WebSettings,
)
from aegishunt.storage import Database

ROOT = Path(__file__).parents[2]


def _settings(tmp_path: Path, artifact_root: Path) -> ApplicationSettings:
    policy = yaml.safe_load(
        (ROOT / "configs/case_feedback.yaml").read_text(encoding="utf-8")
    )
    policy["export_root"] = (artifact_root / "feedback").as_posix()
    policy["report_root"] = (artifact_root / "reports").as_posix()
    policy["candidate_root"] = (artifact_root / "candidates").as_posix()
    policy_path = tmp_path / "case-feedback.yaml"
    policy_path.write_text(yaml.safe_dump(policy, sort_keys=False), encoding="utf-8")
    return ApplicationSettings(
        application=ApplicationSection(environment="phase14-e2e"),
        database=DatabaseSettings(url=f"sqlite:///{tmp_path / 'phase14.db'}"),
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
        case_feedback=CaseFeedbackSettings(policy_path=policy_path),
        web=WebSettings(
            demo_artifact_root=artifact_root / "demo",
            demo_sample_ids=(
                "phase14-attack-like-pcap",
                "phase14-benign-like-pcap",
            ),
            demo_namespace="phase14-controlled-demo",
            demo_operation_version="1.0.0",
            demo_worker_id="phase14-e2e-worker",
        ),
    )


def test_phase14_uploaded_sample_full_chain_persists_across_restart(
    tmp_path: Path,
) -> None:
    artifact_root = Path("tmp") / f"phase14-e2e-{uuid4().hex}"
    settings = _settings(tmp_path, artifact_root)
    database = Database(settings.database)
    try:
        with TestClient(create_app(settings, database)) as client:
            status = client.get("/demo/status")
            assert status.status_code == 200
            assert status.json()["sample_ids"] == [
                "phase14-attack-like-pcap",
                "phase14-benign-like-pcap",
            ]

            request = {
                "actor": "phase14-analyst",
                "reason": "explicit final-delivery pipeline verification",
                "confirm": True,
                "sample_id": "phase14-attack-like-pcap",
                "create_case": True,
            }
            first = client.post("/demo/sample", json=request)
            repeated = client.post("/demo/sample", json=request)
            assert first.status_code == 200, first.text
            assert repeated.status_code == 200, repeated.text
            result = first.json()
            assert repeated.json()["source_id"] == result["source_id"]
            assert repeated.json()["runtime_job_id"] == result["runtime_job_id"]
            assert repeated.json()["flow_ids"] == result["flow_ids"]
            assert repeated.json()["alert_ids"] == result["alert_ids"]
            assert len(result["flow_ids"]) == 42
            assert result["alert_ids"]
            assert result["group_ids"]
            assert result["hypothesis_ids"]
            assert result["case_id"] is not None
            assert result["state"] == "completed"
            assert "not a public benchmark or production validation" in result["limitations"]

            case_id = result["case_id"]
            note = client.post(
                f"/cases/{case_id}/notes",
                json={
                    "actor": "phase14-analyst",
                    "reason": "explicit analyst note",
                    "body": "Review controlled sample evidence and limitations.",
                    "note_type": "investigation",
                },
            )
            assert note.status_code == 200
            verdict = client.patch(
                f"/cases/{case_id}",
                json={
                    "actor": "phase14-analyst",
                    "reason": "bounded demo assessment",
                    "verdict": "needs_more_information",
                    "verdict_confidence": 0.6,
                },
            )
            assert verdict.status_code == 200
            feedback = client.post(
                f"/cases/{case_id}/feedback",
                json={
                    "actor": "phase14-analyst",
                    "reason": "explicit bounded feedback",
                    "verdict": "needs_more_information",
                    "confidence": 0.6,
                    "notes": "Profile names are not ground-truth labels.",
                },
            )
            assert feedback.status_code == 200
            report = client.post(
                f"/cases/{case_id}/report",
                json={
                    "actor": "phase14-analyst",
                    "reason": "explicit final-delivery report",
                    "confirm": True,
                    "version": "phase14-e2e",
                },
            )
            assert report.status_code == 200, report.text
            download = client.get(f"/cases/{case_id}/reports/phase14-e2e")
            assert download.status_code == 200
            assert "# AegisHunt Investigation Case Report" in download.text
            assert client.get(f"/cases/{case_id}/audit-events").json()["total"] >= 5

            benign = client.post(
                "/demo/sample",
                json={
                    **request,
                    "sample_id": "phase14-benign-like-pcap",
                    "create_case": False,
                },
            )
            assert benign.status_code == 200, benign.text
            assert len(benign.json()["flow_ids"]) == 51
            assert benign.json()["state"] == "completed"

        database.dispose()
        restarted = Database(settings.database)
        with TestClient(create_app(settings, restarted)) as client:
            case = client.get(f"/cases/{case_id}")
            assert case.status_code == 200
            assert case.json()["case"]["verdict"] == "needs_more_information"
            assert case.json()["notes"]
            assert case.json()["feedback"]
            assert client.get("/runtime/jobs").json()["total"] == 2
            assert client.get("/flows/summary").json()["total"] == 93
            assert client.get("/demo/status").json()["previous_run"]["runtime_status"] == (
                "completed"
            )
        restarted.dispose()
    finally:
        database.dispose()
        shutil.rmtree(ROOT / artifact_root, ignore_errors=True)
