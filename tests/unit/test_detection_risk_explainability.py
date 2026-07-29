"""Phase 8 risk, severity, reference, importance, reason, and artifact tests."""

from __future__ import annotations

import math
import shutil
from pathlib import Path

import numpy as np
import pytest
from pydantic import ValidationError
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier

from aegishunt.detection.contracts import RiskPolicy, VerifiedScores
from aegishunt.detection.errors import DetectionArtifactError, DetectionContractError
from aegishunt.detection.risk import evaluate_risk
from aegishunt.detection.severity import map_severity
from aegishunt.explainability.artifacts import (
    CATALOG_FILENAME,
    load_explanation_artifact,
    save_explanation_artifact,
)
from aegishunt.explainability.global_importance import (
    fixed_validation_permutation_importance,
    native_tree_importance,
)
from aegishunt.explainability.local_contributions import compute_local_contributions
from aegishunt.explainability.reason_codes import generate_reason_evidence
from aegishunt.explainability.reference_profile import build_reference_profile
from aegishunt.schemas.enums import Severity
from tests.fixtures.detection import (
    NOW,
    DeterministicScorer,
    explanation_artifact,
    reference_profile,
    risk_policy,
    verified_scores,
)


def test_risk_policy_maps_declared_source_without_fallback() -> None:
    loaded = risk_policy()
    scores = verified_scores(fusion_score=0.7)
    decision = evaluate_risk(scores, loaded)

    assert decision.risk_score == 0.7
    assert decision.score_source == "fusion_score"
    assert decision.alert_required is True
    assert decision.severity is Severity.HIGH
    assert "not attack probability" in decision.semantics

    for source, expected in (
        ("supervised_probability", scores.supervised_probability),
        ("normalized_anomaly_score", scores.normalized_anomaly_score),
    ):
        changed = loaded.model_copy(
            update={"policy": loaded.policy.model_copy(update={"score_source": source})}
        )
        assert evaluate_risk(scores, changed).risk_score == expected


def test_score_and_policy_contracts_fail_closed() -> None:
    scores = verified_scores()
    mismatched = scores.model_copy(update={"fusion_policy_version": "unexpected"})
    with pytest.raises(DetectionContractError, match="identities"):
        evaluate_risk(mismatched, risk_policy())

    payload = scores.model_dump()
    for field, value in (
        ("fusion_score", math.nan),
        ("supervised_probability", math.inf),
        ("normalized_anomaly_score", -0.01),
        ("anomaly_raw_score", -math.inf),
    ):
        with pytest.raises(ValidationError):
            VerifiedScores.model_validate({**payload, field: value})

    policy_payload = risk_policy().policy.model_dump()
    with pytest.raises(ValidationError, match="start at zero"):
        RiskPolicy.model_validate(
            {**policy_payload, "severity_bands": tuple(reversed(policy_payload["severity_bands"]))}
        )


def test_severity_exact_boundaries_and_invalid_values() -> None:
    bands = risk_policy().policy.severity_bands
    assert [map_severity(value, bands) for value in (0.0, 0.2, 0.4, 0.7, 0.9, 1.0)] == [
        Severity.INFORMATIONAL,
        Severity.LOW,
        Severity.MEDIUM,
        Severity.HIGH,
        Severity.CRITICAL,
        Severity.CRITICAL,
    ]
    for invalid in (-0.1, 1.1, math.nan, math.inf, -math.inf):
        with pytest.raises(DetectionContractError):
            map_severity(invalid, bands)


def test_reference_profile_is_train_benign_only_and_deterministic() -> None:
    profile = reference_profile()
    assert profile.source_partition == "train"
    assert profile.benign_only is True
    assert profile.test_data_used is False
    assert profile.features[0].median == 0.2
    assert profile == reference_profile()

    arguments = {
        "profile_id": "invalid",
        "profile_version": "1",
        "dataset_id": "data",
        "dataset_version": "1",
        "dataset_checksum": "a" * 64,
        "split_checksum": "b" * 64,
        "feature_schema_version": "1.0.0",
        "feature_names": ("value",),
        "rows": ((1.0,),),
        "labels": (0,),
        "group_ids": ("g1",),
        "source_partition": "test",
        "git_commit_sha": None,
        "created_at": NOW,
    }
    with pytest.raises(DetectionContractError, match="training"):
        build_reference_profile(**arguments)
    with pytest.raises(DetectionContractError, match="attack"):
        build_reference_profile(**{**arguments, "source_partition": "train", "labels": (1,)})
    with pytest.raises(DetectionContractError, match="finite"):
        build_reference_profile(
            **{**arguments, "source_partition": "train", "rows": ((math.nan,),)}
        )


def test_native_and_permutation_importance_are_noncausal_and_ordered() -> None:
    rows = ((0.0, 0.0), (0.0, 1.0), (1.0, 0.0), (1.0, 1.0))
    labels = (0, 0, 1, 1)
    tree = DecisionTreeClassifier(random_state=7).fit(np.asarray(rows), np.asarray(labels))
    native = native_tree_importance(
        tree,
        report_id="native",
        model_id="model",
        model_version="1",
        feature_schema_version="test",
        feature_names=("a", "b"),
        created_at=NOW,
    )
    assert native.status == "available"
    assert tuple(item.feature_name for item in native.entries) == ("a", "b")
    assert "not causation" in native.semantics

    unavailable = native_tree_importance(
        LogisticRegression(),
        report_id="native-na",
        model_id="model",
        model_version="1",
        feature_schema_version="test",
        feature_names=("a", "b"),
        created_at=NOW,
    )
    assert unavailable.status == "not_applicable"

    report = fixed_validation_permutation_importance(
        tree,
        report_id="permutation",
        model_id="model",
        model_version="1",
        feature_schema_version="test",
        feature_names=("a", "b"),
        rows=rows,
        labels=labels,
        group_ids=("g1", "g1", "g2", "g2"),
        source_partition="validation",
        scoring_metric="balanced_accuracy",
        random_seed=9,
        repeats=3,
        created_at=NOW,
    )
    assert report.test_data_used is False
    assert report.source_partition == "validation"
    assert tuple(item.feature_name for item in report.entries) == ("a", "b")
    with pytest.raises(DetectionContractError, match="validation"):
        fixed_validation_permutation_importance(
            tree,
            report_id="invalid",
            model_id="model",
            model_version="1",
            feature_schema_version="test",
            feature_names=("a", "b"),
            rows=rows,
            labels=labels,
            group_ids=("g1", "g1", "g2", "g2"),
            source_partition="test",
            scoring_metric="balanced_accuracy",
            random_seed=9,
            repeats=3,
        )


def test_local_contributions_and_reason_codes_use_only_evidence() -> None:
    profile = reference_profile()
    features = tuple(8.0 if index == 0 else 0.0 for index in range(len(profile.feature_names)))
    scorer = DeterministicScorer()
    contributions = compute_local_contributions(
        features,
        feature_names=profile.feature_names,
        profile=profile,
        scorer=scorer,
        risk_policy=risk_policy(),
        top_k=3,
        max_features=len(features),
    )
    assert contributions[0].feature_name == "total_packets"
    assert contributions[0].effect_delta == pytest.approx(0.78)
    assert contributions[0].effect_direction == "increases_suspicion"
    assert all("not causation" in item.limitations[0] for item in contributions)

    scores = scorer.score(features)
    risk = evaluate_risk(scores, risk_policy())
    artifact = explanation_artifact()
    reasons = generate_reason_evidence(
        dict(zip(profile.feature_names, features, strict=True)),
        profile=profile,
        scores=scores,
        risk=risk,
        catalog=artifact.reason_catalog,
    )
    codes = tuple(item.code for item in reasons)
    assert "RISK_SCORE_ABOVE_ALERT_THRESHOLD" in codes
    assert "MULTI_ENGINE_SUPPORT" in codes
    assert "MULTIPLE_CORRELATED_ALERTS" not in codes
    assert "REPEATED_DESTINATION_ACTIVITY" not in codes


def test_every_enabled_reason_code_requires_matching_evidence() -> None:
    artifact = explanation_artifact()
    profile = artifact.reference_profile
    features = {name: 0.9 for name in profile.feature_names}
    features["std_inter_arrival_time"] = 0.01
    features["mean_inter_arrival_time"] = 0.5
    scores = verified_scores(fusion_score=0.8)
    reasons = generate_reason_evidence(
        features,
        profile=profile,
        scores=scores,
        risk=evaluate_risk(scores, risk_policy()),
        catalog=artifact.reason_catalog,
    )
    emitted = {item.code for item in reasons}
    enabled = {
        item.code for item in artifact.reason_catalog.entries if item.enabled_in_phase_8
    }
    assert emitted == enabled

    within_reference = {name: 0.2 for name in profile.feature_names}
    within_reference["mean_inter_arrival_time"] = 0.0
    low_scores = verified_scores(fusion_score=0.1).model_copy(
        update={
            "supervised_probability": 0.1,
            "normalized_anomaly_score": 0.1,
        }
    )
    assert generate_reason_evidence(
        within_reference,
        profile=profile,
        scores=low_scores,
        risk=evaluate_risk(low_scores, risk_policy()),
        catalog=artifact.reason_catalog,
    ) == ()


def test_disabled_catalog_entry_cannot_be_emitted_by_a_matching_trigger() -> None:
    artifact = explanation_artifact()
    profile = artifact.reference_profile
    entries = tuple(
        item.model_copy(update={"enabled_in_phase_8": False})
        if item.code == "RISK_SCORE_ABOVE_ALERT_THRESHOLD"
        else item
        for item in artifact.reason_catalog.entries
    )
    catalog = artifact.reason_catalog.model_copy(update={"entries": entries})
    scores = verified_scores(fusion_score=0.8)

    reasons = generate_reason_evidence(
        {name: 0.2 for name in profile.feature_names},
        profile=profile,
        scores=scores,
        risk=evaluate_risk(scores, risk_policy()),
        catalog=catalog,
    )

    assert "RISK_SCORE_ABOVE_ALERT_THRESHOLD" not in {
        reason.code for reason in reasons
    }


def test_explanation_artifact_round_trip_and_integrity_rejections(tmp_path: Path) -> None:
    artifact = explanation_artifact()
    saved = save_explanation_artifact(
        root=tmp_path,
        manifest=artifact.manifest,
        reference_profile=artifact.reference_profile,
        native_importance=artifact.native_importance,
        permutation_importance=artifact.permutation_importance,
        reason_catalog=artifact.reason_catalog,
        protocol=artifact.protocol,
    )
    assert load_explanation_artifact(saved, root=tmp_path) == artifact
    with pytest.raises(DetectionArtifactError, match="already exists"):
        save_explanation_artifact(
            root=tmp_path,
            manifest=artifact.manifest,
            reference_profile=artifact.reference_profile,
            native_importance=artifact.native_importance,
            permutation_importance=artifact.permutation_importance,
            reason_catalog=artifact.reason_catalog,
            protocol=artifact.protocol,
        )

    (saved / CATALOG_FILENAME).write_text("{}", encoding="utf-8")
    with pytest.raises(DetectionArtifactError, match="checksum"):
        load_explanation_artifact(saved, root=tmp_path)

    outside = tmp_path.parent / "outside-phase-08"
    outside.mkdir(exist_ok=True)
    with pytest.raises(DetectionArtifactError, match="outside"):
        load_explanation_artifact(outside, root=tmp_path)


def test_explanation_artifact_rejects_missing_extra_and_symlink(tmp_path: Path) -> None:
    artifact = explanation_artifact()
    original = save_explanation_artifact(
        root=tmp_path / "original",
        manifest=artifact.manifest,
        reference_profile=artifact.reference_profile,
        native_importance=artifact.native_importance,
        permutation_importance=artifact.permutation_importance,
        reason_catalog=artifact.reason_catalog,
        protocol=artifact.protocol,
    )

    missing = tmp_path / "missing" / "1.0.0"
    shutil.copytree(original, missing)
    (missing / "explanation_protocol.md").unlink()
    with pytest.raises(DetectionArtifactError, match="inventory"):
        load_explanation_artifact(missing, root=tmp_path / "missing")

    extra = tmp_path / "extra" / "1.0.0"
    shutil.copytree(original, extra)
    (extra / "unexpected.json").write_text("{}", encoding="utf-8")
    with pytest.raises(DetectionArtifactError, match="inventory"):
        load_explanation_artifact(extra, root=tmp_path / "extra")

    linked = tmp_path / "linked" / "1.0.0"
    shutil.copytree(original, linked)
    protocol = linked / "explanation_protocol.md"
    protocol.unlink()
    protocol.symlink_to(original / "explanation_protocol.md")
    with pytest.raises(DetectionArtifactError, match="regular files"):
        load_explanation_artifact(linked, root=tmp_path / "linked")

    real_root = tmp_path / "real-root"
    real_root.mkdir()
    linked_root = tmp_path / "linked-root"
    linked_root.symlink_to(real_root, target_is_directory=True)
    with pytest.raises(DetectionArtifactError, match="root cannot be a symlink"):
        save_explanation_artifact(
            root=linked_root,
            manifest=artifact.manifest,
            reference_profile=artifact.reference_profile,
            native_importance=artifact.native_importance,
            permutation_importance=artifact.permutation_importance,
            reason_catalog=artifact.reason_catalog,
            protocol=artifact.protocol,
        )
    with pytest.raises(DetectionArtifactError, match="root cannot be a symlink"):
        load_explanation_artifact(original, root=linked_root)
