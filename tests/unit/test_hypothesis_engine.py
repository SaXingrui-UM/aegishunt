"""Deterministic hypothesis templates, gates, uncertainty, and safety tests."""

from __future__ import annotations

import math

import pytest
from pydantic import ValidationError

from aegishunt.hunting.errors import HypothesisGateError
from aegishunt.hunting.generator import generate_hypothesis
from aegishunt.schemas import AlertGroup, InvestigationQuery, PossibleMitreMapping, ThreatHypothesis
from aegishunt.schemas.enums import HypothesisStatus
from tests.fixtures.hunting import correlation_policy, group


def test_recon_hypothesis_is_deterministic_cautious_and_structured() -> None:
    loaded = correlation_policy()
    alert_group = group()
    first = generate_hypothesis(alert_group, loaded)
    second = generate_hypothesis(alert_group, loaded)

    assert first == second
    assert first.primary_template_id == "possible_network_reconnaissance"
    assert first.status is HypothesisStatus.PROPOSED
    assert math.isfinite(first.confidence) and 0.0 <= first.confidence <= 1.0
    assert "not a confirmed attack" in first.description
    assert isinstance(first.possible_mitre_mappings[0], PossibleMitreMapping)
    assert first.possible_mitre_mappings[0].attack_catalog_version == "ATT&CK v19.1"
    assert first.possible_mitre_mappings[0].confidence == "low"
    assert isinstance(first.recommended_queries[0], InvestigationQuery)
    assert first.recommended_queries[0].execution == "not_executed"
    assert first.observed_facts and first.derived_inferences
    assert first.assumptions and first.alternative_explanations
    assert first.source_group_snapshot["group_id"] == str(alert_group.group_id)


@pytest.mark.parametrize(
    ("rules", "codes", "expected"),
    [
        (("repeated_source_destination_failures",), ("AUTH_FAILED",), "possible_credential_abuse"),
        (
            ("repeated_source_destination_failures",),
            ("CONNECTION_FAILED",),
            "possible_brute_force_activity",
        ),
        (("periodic_beacon_like_activity",), (), "possible_beaconing_behavior"),
        (
            ("periodic_beacon_like_activity", "multi_engine_evidence"),
            (),
            "possible_command_and_control_pattern",
        ),
        (("destination_fan_in",), (), "possible_denial_of_service_behavior"),
        (("multi_alert_accumulation",), ("EXFIL_VOLUME",), "possible_data_exfiltration_pattern"),
        (("multi_alert_accumulation",), (), "unclassified_behavioral_anomaly"),
    ],
)
def test_template_selection_is_rule_based_with_stable_priority(
    rules: tuple[str, ...],
    codes: tuple[str, ...],
    expected: str,
) -> None:
    hypothesis = generate_hypothesis(
        group(rules=rules, reason_codes=codes),
        correlation_policy(),
    )
    assert hypothesis.primary_template_id == expected
    assert hypothesis.candidate_template_ids
    assert hypothesis.template_catalog_version == "1.0.0"
    if expected == "unclassified_behavioral_anomaly":
        assert hypothesis.possible_mitre_mappings == []


def test_generation_gate_rejects_low_score_and_legacy_group() -> None:
    loaded = correlation_policy()
    with pytest.raises(HypothesisGateError, match="below"):
        generate_hypothesis(group(score=0.49), loaded)
    with pytest.raises(HypothesisGateError, match="Phase 9"):
        generate_hypothesis(
            group().model_copy(update={"group_schema_version": None}),
            loaded,
        )


def test_group_and_hypothesis_components_reject_non_finite_values() -> None:
    group_payload = group().model_dump()
    group_payload["score_components"]["risk"] = float("nan")
    with pytest.raises(ValidationError, match="finite values"):
        AlertGroup.model_validate(group_payload)

    hypothesis_payload = generate_hypothesis(group(), correlation_policy()).model_dump()
    hypothesis_payload["confidence_components"]["correlation"] = float("inf")
    with pytest.raises(ValidationError, match="finite values"):
        ThreatHypothesis.model_validate(hypothesis_payload)
