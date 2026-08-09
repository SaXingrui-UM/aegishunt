"""Phase 10 strict policy, schema, and artifact-boundary tests."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from aegishunt.artifact_io import (
    configured_artifact_root,
    verify_data_artifact,
    write_data_artifact,
)
from aegishunt.cases.config import load_case_feedback_policy
from aegishunt.cases.errors import CasePolicyError
from aegishunt.errors import DataArtifactError
from aegishunt.feedback.contracts import CandidateRow
from aegishunt.flows.registry import FEATURE_SCHEMA_VERSION, feature_names
from tests.fixtures.cases import CASE_CREATED_AT, case_policy


def _policy_payload() -> dict[str, object]:
    source = Path(__file__).parents[2] / "configs" / "case_feedback.yaml"
    payload = yaml.safe_load(source.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def _write_policy(tmp_path: Path, payload: dict[str, object]) -> Path:
    path = tmp_path / "case-feedback.yaml"
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return path


def test_policy_is_complete_checksummed_and_has_no_hidden_critical_defaults() -> None:
    first = case_policy()
    second = case_policy()
    assert first == second
    assert len(first.configuration_checksum) == 64
    assert first.policy.feedback_confidence_minimum == 0.7
    assert first.policy.allowed_case_status_transitions
    assert first.policy.excluded_provenance_partitions
    assert first.policy.candidate_dataset_inventory[-1] == "exclusions.json"


def test_docker_policy_only_redirects_artifacts_to_direct_runtime_mounts() -> None:
    root = Path(__file__).parents[2]
    default_payload = _policy_payload()
    docker_path = root / "configs" / "case_feedback.docker.yaml"
    docker_payload = yaml.safe_load(docker_path.read_text(encoding="utf-8"))
    assert isinstance(docker_payload, dict)

    root_fields = ("export_root", "report_root", "candidate_root")
    assert {field: docker_payload.pop(field) for field in root_fields} == {
        "export_root": "runtime/artifacts/feedback",
        "report_root": "runtime/reports/cases",
        "candidate_root": "runtime/artifacts/retraining_candidates",
    }
    for field in root_fields:
        default_payload.pop(field)
    assert docker_payload == default_payload

    loaded = load_case_feedback_policy(docker_path)
    assert configured_artifact_root(root, loaded.policy.report_root) == (
        root / "runtime" / "reports" / "cases"
    )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda data: data.pop("final_verdicts"), "could not be validated"),
        (
            lambda data: data["allowed_case_status_transitions"].update(
                {"closed": ["open"]}
            ),
            "could not be validated",
        ),
        (lambda data: data.update({"export_root": "/tmp/escape"}), "could not be validated"),
        (
            lambda data: data.update({"feedback_confidence_minimum": float("nan")}),
            "could not be validated",
        ),
    ],
)
def test_policy_rejects_missing_or_unsafe_critical_values(
    tmp_path: Path,
    mutation: object,
    message: str,
) -> None:
    payload = _policy_payload()
    assert callable(mutation)
    mutation(payload)
    with pytest.raises(CasePolicyError, match=message):
        load_case_feedback_policy(_write_policy(tmp_path, payload))


def test_candidate_contract_rejects_nonfinite_or_reordered_features() -> None:
    names = feature_names()
    base = {
        "candidate_id": "candidate",
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "feature_names": names,
        "feature_values": tuple(0.0 for _ in names),
        "candidate_label": "malicious",
        "label_mapping_version": "1.0.0",
        "source_flow_id": "flow",
        "source_detection_id": "detection",
        "source_alert_id": "alert",
        "supporting_feedback_ids": ("feedback",),
        "confidence": 0.8,
        "provenance": {"partition": "runtime"},
        "created_at": CASE_CREATED_AT,
    }
    CandidateRow.model_validate(base)
    with pytest.raises(ValidationError, match="finite"):
        CandidateRow.model_validate(
            {**base, "feature_values": (float("inf"), *base["feature_values"][1:])}
        )
    with pytest.raises(ValidationError, match="order"):
        CandidateRow.model_validate(
            {**base, "feature_names": tuple(reversed(names))}
        )


def test_data_artifact_rejects_escape_collision_corruption_and_extra_files(
    tmp_path: Path,
) -> None:
    root = configured_artifact_root(tmp_path, Path("artifacts/feedback"))
    inventory = ("checksums.json", "payload.json")
    path = write_data_artifact(
        root=root,
        version="1.0.0",
        payloads={"payload.json": b"{}\n"},
        exact_inventory=inventory,
    )
    assert verify_data_artifact(path, root=root, exact_inventory=inventory)[
        "payload.json"
    ] == b"{}\n"
    with pytest.raises(DataArtifactError, match="already exists"):
        write_data_artifact(
            root=root,
            version="1.0.0",
            payloads={"payload.json": b"{}\n"},
            exact_inventory=inventory,
        )
    (path / "payload.json").write_text("corrupt", encoding="utf-8")
    with pytest.raises(DataArtifactError, match="checksum"):
        verify_data_artifact(path, root=root, exact_inventory=inventory)
    (path / "extra").write_text("extra", encoding="utf-8")
    with pytest.raises(DataArtifactError, match="inventory"):
        verify_data_artifact(path, root=root, exact_inventory=inventory)
    with pytest.raises(DataArtifactError, match="project-relative"):
        configured_artifact_root(tmp_path, Path("/tmp/escape"))


def test_artifact_root_rejects_symlink_component(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / "artifacts").symlink_to(outside, target_is_directory=True)
    with pytest.raises(DataArtifactError, match="symlink"):
        configured_artifact_root(tmp_path, Path("artifacts/feedback"))
