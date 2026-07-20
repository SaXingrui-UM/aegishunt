"""Small deterministic Phase 8 fixtures with no model or network dependency."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from aegishunt.detection.config import load_risk_policy
from aegishunt.detection.contracts import LoadedRiskPolicy, VerifiedScores
from aegishunt.explainability.artifacts import ARTIFACT_FILES
from aegishunt.explainability.contracts import (
    ExplanationArtifactManifest,
    GlobalImportanceReport,
    LoadedExplanationArtifact,
    PermutationImportanceReport,
    ReferenceProfile,
)
from aegishunt.explainability.reason_codes import default_reason_catalog
from aegishunt.explainability.reference_profile import build_reference_profile
from aegishunt.flows.registry import FEATURE_SCHEMA_VERSION, feature_names
from aegishunt.schemas import NetworkFlow
from aegishunt.schemas.enums import NetworkProtocol

NOW = datetime(2026, 7, 20, 12, 0, tzinfo=UTC)
CHECKSUM = "a" * 64
FUSION_CHECKSUM = "808bd05e2e5a648324fe6052e65a6602f04c15f24e39f2a043a72b73ca3b29c7"


def risk_policy() -> LoadedRiskPolicy:
    root = Path(__file__).parents[2]
    return load_risk_policy(root / "configs" / "models" / "detection.yaml")


def verified_scores(*, fusion_score: float = 0.8) -> VerifiedScores:
    return VerifiedScores(
        supervised_label=1,
        supervised_probability=0.8,
        supervised_threshold=0.5,
        anomaly_raw_score=-0.2,
        normalized_anomaly_score=0.75,
        anomaly_threshold=0.6,
        fusion_score=fusion_score,
        fusion_threshold=0.5,
        supervised_model_id="aegishunt-supervised-1.0.1",
        supervised_model_version="1.0.1",
        anomaly_model_id="aegishunt-anomaly-1.1.0-candidate",
        anomaly_model_version="1.1.0-candidate",
        fusion_policy_id="aegishunt-fusion-controlled",
        fusion_policy_version="1.0.0",
        fusion_policy_checksum=FUSION_CHECKSUM,
        fusion_recommendation="inconclusive",
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        scored_at=NOW,
    )


class DeterministicScorer:
    """Risk varies only with total_packets, making replacement evidence auditable."""

    def score(self, features: tuple[float, ...]) -> VerifiedScores:
        return verified_scores(fusion_score=max(0.0, min(1.0, features[0] / 10.0)))


def reference_profile() -> ReferenceProfile:
    names = feature_names()
    rows = tuple(tuple(float(value) for _ in names) for value in (0.1, 0.2, 0.3))
    return build_reference_profile(
        profile_id="phase-08-benign-reference",
        profile_version="1.0.0",
        dataset_id="controlled-demo",
        dataset_version="1.0.0",
        dataset_checksum=CHECKSUM,
        split_checksum="b" * 64,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        feature_names=names,
        rows=rows,
        labels=(0, 0, 0),
        group_ids=("g1", "g2", "g3"),
        source_partition="train",
        git_commit_sha=None,
        created_at=NOW,
    )


def explanation_artifact() -> LoadedExplanationArtifact:
    profile = reference_profile()
    native = GlobalImportanceReport(
        report_schema_version="1.0.0",
        report_id="native-1",
        method="native_tree_importance",
        status="not_applicable",
        model_id="aegishunt-supervised-1.0.1",
        model_version="1.0.1",
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        feature_names=profile.feature_names,
        entries=(),
        semantics="model association or sensitivity; not causation",
        created_at=NOW,
    )
    permutation = PermutationImportanceReport(
        report_schema_version="1.0.0",
        report_id="permutation-1",
        method="permutation_importance",
        model_id="aegishunt-supervised-1.0.1",
        model_version="1.0.1",
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        feature_names=profile.feature_names,
        source_partition="validation",
        test_data_used=False,
        scoring_metric="balanced_accuracy",
        random_seed=42,
        repeats=5,
        row_count=10,
        group_count=2,
        entries=tuple(
            {
                "feature_name": name,
                "mean": 0.0,
                "standard_deviation": 0.0,
            }
            for name in profile.feature_names
        ),
        semantics="model sensitivity to feature permutation; not causation",
        created_at=NOW,
    )
    manifest = ExplanationArtifactManifest(
        manifest_schema_version="1.0.0",
        artifact_id="phase-08-explanation",
        artifact_version="1.0.0",
        file_inventory=tuple(sorted(ARTIFACT_FILES)),
        reference_profile_id=profile.profile_id,
        reference_profile_version=profile.profile_version,
        native_importance_report_id=native.report_id,
        permutation_importance_report_id=permutation.report_id,
        reason_catalog_id="aegishunt-phase-08-reason-codes",
        reason_catalog_version="1.0.0",
        supervised_model_id="aegishunt-supervised-1.0.1",
        supervised_model_version="1.0.1",
        anomaly_model_id="aegishunt-anomaly-1.1.0-candidate",
        anomaly_model_version="1.1.0-candidate",
        fusion_policy_id="aegishunt-fusion-controlled",
        fusion_policy_version="1.0.0",
        risk_policy_id="aegishunt-risk-controlled",
        risk_policy_version="1.0.0",
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        pipeline_verification_only=True,
        public_benchmark=False,
        created_at=NOW,
    )
    return LoadedExplanationArtifact(
        manifest=manifest,
        reference_profile=profile,
        native_importance=native,
        permutation_importance=permutation,
        reason_catalog=default_reason_catalog(),
        protocol="Non-causal controlled-pipeline explanation protocol.\n",
    )


def canonical_flow() -> NetworkFlow:
    values = {name: 0.0 for name in feature_names()}
    values.update(
        {
            "total_packets": 8.0,
            "total_bytes": 480.0,
            "forward_packets": 5.0,
            "backward_packets": 3.0,
            "forward_bytes": 300.0,
            "backward_bytes": 180.0,
            "packets_per_second": 8.0,
            "bytes_per_second": 480.0,
            "mean_packet_size": 60.0,
            "min_packet_size": 60.0,
            "max_packet_size": 60.0,
            "median_packet_size": 60.0,
            "packet_size_q25": 60.0,
            "packet_size_q75": 60.0,
            "forward_mean_packet_size": 60.0,
            "backward_mean_packet_size": 60.0,
            "flow_duration": 1.0,
            "syn_ratio": 0.25,
            "ack_ratio": 0.75,
            "asymmetry_score": 0.25,
            "connection_burst_score": 1.0,
        }
    )
    return NetworkFlow(
        flow_id=UUID(int=801),
        source_id=UUID(int=701),
        capture_session_id="phase-08-controlled",
        first_seen=NOW,
        last_seen=NOW.replace(second=1),
        duration=1.0,
        source_ip="192.0.2.10",
        destination_ip="198.51.100.20",
        source_port=12345,
        destination_port=443,
        protocol=NetworkProtocol.TCP,
        forward_packet_count=5,
        backward_packet_count=3,
        forward_bytes=300,
        backward_bytes=180,
        behavioral_features=values,
        ground_truth_label="ignored-by-phase-8",
        attack_family="ignored-by-phase-8",
    )
