"""Final PCAP-to-analyst-feedback delivery demonstration."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import cast
from uuid import uuid4

import yaml
from fastapi.testclient import TestClient
from sqlalchemy import inspect as inspect_database
from sqlalchemy import text

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


def _database_counts(database: Database) -> dict[str, int]:
    tables = inspect_database(database.engine).get_table_names()
    with database.session() as session:
        return {
            table: int(
                session.execute(text(f'SELECT COUNT(*) FROM "{table}"')).scalar_one()
            )
            for table in tables
        }


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

            prepared_root = (
                ROOT
                / settings.web.demo_artifact_root
                / (
                    f"{settings.web.demo_namespace}-"
                    f"{settings.web.demo_operation_version}"
                )
            )
            file_state_before = {
                path.relative_to(prepared_root).as_posix(): path.stat().st_mtime_ns
                for path in prepared_root.rglob("*")
                if path.is_file() and not path.is_symlink()
            }
            database_counts_before = _database_counts(database)
            evaluation = client.get("/evaluation/summary")
            repeated_evaluation = client.get("/evaluation/summary")
            assert evaluation.status_code == 200, evaluation.text
            assert repeated_evaluation.json() == evaluation.json()
            summary = evaluation.json()
            assert summary["status"] == "available"
            assert summary["evidence_class"] == "controlled_synthetic_evaluation"
            assert summary["experiment_id"] == "phase-12-controlled-demo-fusion"
            assert summary["row_count"] == 144
            assert summary["group_count"] == 72
            assert summary["supervised_weight"] == 0.75
            assert summary["anomaly_weight"] == 0.25
            assert summary["selected_threshold"] == 0.7
            assert summary["recommendation"] == "inconclusive"
            known = {item["engine"]: item for item in summary["known_comparison"]}
            assert known["supervised"]["recall"] == 1.0
            assert known["anomaly"]["recall"] == 0.9333333333333333
            assert known["fusion"]["recall"] == 1.0
            assert known["fusion"]["false_positive_rate"] == 0.0
            assert summary["loao_aggregate"] == {
                "supervised_recall": 0.6,
                "anomaly_recall": 0.9333333333333333,
                "fusion_recall": 0.3333333333333333,
            }
            fusion_loao = {
                item["held_out_family"]: item["recall"]
                for item in summary["loao_comparison"]
                if item["engine"] == "fusion"
            }
            assert fusion_loao["exfiltration"] == 0.0
            assert fusion_loao["reconnaissance"] == 0.0
            assert (
                summary["provenance"]["loao_evidence_checksum"]
                == "57db0ddcf3f4984fdc9ced5443730e73196cc508203c419dd2ebf0fa0a056856"
            )
            effective = client.get("/models/effective").json()
            assert effective["global_active_models"] == []
            assert client.get("/models/active").json() == []
            assert (
                summary["provenance"]["policy_manifest_hash"]
                == effective["effective_fusion_policy"]["artifact_hash"]
            )
            assert {
                path.relative_to(prepared_root).as_posix(): path.stat().st_mtime_ns
                for path in prepared_root.rglob("*")
                if path.is_file() and not path.is_symlink()
            } == file_state_before
            assert _database_counts(database) == database_counts_before

            experiment = (
                prepared_root
                / "reports/fusion/phase-12-controlled-demo-fusion"
            )

            def failed_closed() -> dict[str, object]:
                response = client.get("/evaluation/summary")
                assert response.status_code == 200
                payload = cast(dict[str, object], response.json())
                assert payload["status"] in {"unavailable", "invalid"}
                assert str(tmp_path) not in response.text
                assert str(prepared_root) not in response.text
                return payload

            missing = experiment / "leave_one_family_out.csv"
            missing_bytes = missing.read_bytes()
            missing.unlink()
            failed_closed()
            missing.write_bytes(missing_bytes)

            loao_bytes = missing.read_bytes()
            loao_payload = loao_bytes.decode("utf-8").replace(
                ",0.3333333333333333,0.5,",
                ",0.9999,0.5,",
                1,
            )
            assert loao_payload.encode("utf-8") != loao_bytes
            missing.write_text(loao_payload, encoding="utf-8")
            assert failed_closed()["status"] == "invalid"
            missing.write_bytes(loao_bytes)

            extra = experiment / "unexpected-evidence.json"
            extra.write_text("{}\n", encoding="utf-8")
            assert failed_closed()["status"] == "invalid"
            extra.unlink()

            known_path = experiment / "known_attack_metrics.csv"
            known_bytes = known_path.read_bytes()
            known_path.write_text("corrupt,evidence\n", encoding="utf-8")
            assert failed_closed()["status"] == "invalid"
            known_path.write_bytes(known_bytes)

            external = tmp_path / "external-known.csv"
            external.write_bytes(known_bytes)
            known_path.unlink()
            known_path.symlink_to(external)
            failed_closed()
            known_path.unlink()
            known_path.write_bytes(known_bytes)

            checksum_bytes = known_path.read_bytes()
            known_path.write_bytes(checksum_bytes + b"\n")
            assert failed_closed()["status"] == "invalid"
            known_path.write_bytes(checksum_bytes)

            fusion_config = experiment / "fusion_config.json"
            fusion_config_bytes = fusion_config.read_bytes()
            fusion_payload = yaml.safe_load(fusion_config_bytes)
            fusion_payload["experiment_id"] = "mismatched-experiment"
            fusion_config.write_text(
                json.dumps(fusion_payload),
                encoding="utf-8",
            )
            assert failed_closed()["status"] == "invalid"
            fusion_config.write_bytes(fusion_config_bytes)
            assert client.get("/evaluation/summary").json()["status"] == "available"
            assert client.get("/models/active").json() == []

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
