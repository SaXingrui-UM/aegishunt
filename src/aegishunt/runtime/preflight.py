"""Fail-closed source, artifact, policy, and schema verification before replay."""

from __future__ import annotations

import hashlib
import json
import subprocess
from collections.abc import Generator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import cast

from aegishunt.config import ApplicationSettings
from aegishunt.correlation.config import LoadedCorrelationPolicy, load_correlation_policy
from aegishunt.detection.adapters import ModelBundleScoreAdapter
from aegishunt.detection.config import load_risk_policy
from aegishunt.detection.contracts import LoadedRiskPolicy
from aegishunt.explainability.artifacts import load_explanation_artifact
from aegishunt.explainability.contracts import LoadedExplanationArtifact
from aegishunt.flows.errors import FlowProcessingError
from aegishunt.flows.pcap_reader import CapturedPacket, PcapPacketReader
from aegishunt.flows.registry import FEATURE_SCHEMA_VERSION, feature_names
from aegishunt.ml.anomaly.bundle import LoadedAnomalyModel
from aegishunt.ml.anomaly.bundle import load_bundle as load_anomaly_bundle
from aegishunt.ml.fusion.artifacts import (
    POLICY_MANIFEST_FILENAME,
    load_policy,
    sha256_file,
)
from aegishunt.ml.fusion.contracts import PolicyManifest
from aegishunt.ml.supervised.bundle import LoadedModel
from aegishunt.ml.supervised.bundle import load_bundle as load_supervised_bundle
from aegishunt.runtime.config import LoadedRuntimePolicy
from aegishunt.runtime.contracts import RuntimeArtifactIdentity, RuntimePipelineSnapshot
from aegishunt.runtime.errors import RuntimePreflightError
from aegishunt.schemas.enums import LifecycleStatus, SourceType
from aegishunt.schemas.telemetry import TelemetrySource
from aegishunt.storage.schema_version import CURRENT_SCHEMA_VERSION


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            while chunk := source.read(65_536):
                digest.update(chunk)
    except OSError as exc:
        raise RuntimePreflightError("runtime evidence could not be read") from exc
    return digest.hexdigest()


def _file_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError as exc:
        raise RuntimePreflightError("runtime evidence could not be inspected") from exc


def _safe_child(root: Path, name: str) -> Path:
    if Path(name).name != name or "/" in name or "\\" in name or name in {"", ".", ".."}:
        raise RuntimePreflightError("runtime evidence uses an unsafe logical filename")
    resolved_root = root.resolve()
    candidate = root / name
    if candidate.is_symlink():
        raise RuntimePreflightError("runtime source must be a regular stored file")
    resolved = candidate.resolve()
    if not resolved.is_relative_to(resolved_root):
        raise RuntimePreflightError("runtime evidence escapes configured storage")
    if not resolved.is_file() or resolved.is_symlink():
        raise RuntimePreflightError("runtime source must be a regular stored file")
    return resolved


def _flow_checksum(settings: ApplicationSettings) -> str:
    payload = json.dumps(
        settings.flows.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def _git_commit(project_root: Path) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=project_root,
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    value = completed.stdout.strip().lower()
    return value if value and len(value) <= 64 else None


@dataclass(frozen=True, slots=True)
class LoadedRuntimePipeline:
    """Verified inference and downstream policy objects pinned to one job."""

    source_path: Path
    snapshot: RuntimePipelineSnapshot
    supervised_model: LoadedModel
    anomaly_model: LoadedAnomalyModel
    fusion_policy: PolicyManifest
    fusion_policy_checksum: str
    risk_policy: LoadedRiskPolicy
    explanation_artifact: LoadedExplanationArtifact
    correlation_policy: LoadedCorrelationPolicy

    def scorer(self, *, scored_at: datetime) -> ModelBundleScoreAdapter:
        return ModelBundleScoreAdapter(
            supervised_model=self.supervised_model,
            anomaly_model=self.anomaly_model,
            fusion_policy=self.fusion_policy,
            fusion_policy_checksum=self.fusion_policy_checksum,
            scored_at=scored_at,
        )


class RuntimePreflightVerifier:
    """Load exact configured artifacts and reject every identity mismatch."""

    def __init__(
        self,
        *,
        settings: ApplicationSettings,
        runtime_policy: LoadedRuntimePolicy,
        project_root: Path,
    ) -> None:
        self._settings = settings
        self._runtime = runtime_policy
        self._project_root = project_root.resolve()

    def verify(
        self,
        source: TelemetrySource,
        *,
        expected_snapshot: RuntimePipelineSnapshot | None = None,
    ) -> LoadedRuntimePipeline:
        policy = self._runtime.policy
        source_path = self._verify_source(source)
        self._verify_parser_initialization(source_path)
        supervised = load_supervised_bundle(
            self._settings.supervised.artifact_root / policy.supervised_model_version,
            artifact_root=self._settings.supervised.artifact_root,
        )
        anomaly = load_anomaly_bundle(
            self._settings.anomaly.artifact_root / policy.anomaly_model_version,
            artifact_root=self._settings.anomaly.artifact_root,
        )
        fusion_dir = self._settings.runtime.fusion_policy_root / policy.fusion_policy_version
        fusion = load_policy(fusion_dir, root=self._settings.runtime.fusion_policy_root)
        fusion_checksum = sha256_file(fusion_dir / POLICY_MANIFEST_FILENAME)
        risk = load_risk_policy(self._settings.detection.risk_policy_path)
        explanation_dir = (
            self._settings.detection.explanation_artifact_root
            / policy.explanation_artifact_version
        )
        explanation = load_explanation_artifact(
            explanation_dir,
            root=self._settings.detection.explanation_artifact_root,
        )
        correlation = load_correlation_policy(self._settings.correlation.policy_path)
        self._verify_identities(
            supervised=supervised,
            anomaly=anomaly,
            fusion=fusion,
            fusion_checksum=fusion_checksum,
            risk=risk,
            explanation=explanation,
        )
        snapshot = self._snapshot(
            source=source,
            source_path=source_path,
            supervised=supervised,
            anomaly=anomaly,
            fusion=fusion,
            fusion_checksum=fusion_checksum,
            risk=risk,
            explanation=explanation,
            correlation=correlation,
        )
        if expected_snapshot is not None and snapshot != expected_snapshot:
            raise RuntimePreflightError(
                "runtime source or pipeline identity differs from the pinned job snapshot"
            )
        return LoadedRuntimePipeline(
            source_path=source_path,
            snapshot=snapshot,
            supervised_model=supervised,
            anomaly_model=anomaly,
            fusion_policy=fusion,
            fusion_policy_checksum=fusion_checksum,
            risk_policy=risk,
            explanation_artifact=explanation,
            correlation_policy=correlation,
        )

    def _verify_source(self, source: TelemetrySource) -> Path:
        if source.status is not LifecycleStatus.COMPLETED or source.checksum is None:
            raise RuntimePreflightError("runtime replay requires a completed checksummed source")
        is_pcap = source.source_type is SourceType.PCAP or (
            source.source_type is SourceType.SAMPLE
            and source.source_metadata.get("validated_source_type") == SourceType.PCAP.value
        )
        if not is_pcap:
            raise RuntimePreflightError("runtime replay accepts only a stored PCAP source")
        stored_name = source.source_metadata.get("stored_filename")
        if not isinstance(stored_name, str):
            raise RuntimePreflightError("telemetry source does not retain a stored filename")
        source_path = _safe_child(self._settings.ingestion.storage_root, stored_name)
        if _hash_file(source_path) != source.checksum:
            raise RuntimePreflightError("stored PCAP checksum differs from source evidence")
        size = _file_size(source_path)
        if size <= 0 or size > self._settings.ingestion.max_upload_bytes:
            raise RuntimePreflightError("stored PCAP size is outside configured bounds")
        return source_path

    def _verify_parser_initialization(self, source_path: Path) -> None:
        reader = PcapPacketReader(
            max_records=self._settings.ingestion.max_records,
            max_packet_bytes=self._settings.flows.max_packet_bytes,
        )
        packets = cast(
            Generator[CapturedPacket, None, None],
            reader.packets(source_path),
        )
        try:
            next(packets)
        except StopIteration as exc:
            raise RuntimePreflightError("runtime replay requires a non-empty PCAP") from exc
        except FlowProcessingError as exc:
            raise RuntimePreflightError("stored PCAP parser initialization failed") from exc
        finally:
            packets.close()

    def _verify_identities(
        self,
        *,
        supervised: LoadedModel,
        anomaly: LoadedAnomalyModel,
        fusion: PolicyManifest,
        fusion_checksum: str,
        risk: LoadedRiskPolicy,
        explanation: LoadedExplanationArtifact,
    ) -> None:
        s = supervised.manifest
        a = anomaly.manifest
        r = risk.policy
        e = explanation.manifest
        names = feature_names()
        if (
            s.feature_names != names
            or a.feature_names != names
            or s.feature_schema_version != FEATURE_SCHEMA_VERSION
            or a.feature_schema_version != FEATURE_SCHEMA_VERSION
            or self._runtime.policy.feature_schema_version != FEATURE_SCHEMA_VERSION
        ):
            raise RuntimePreflightError("runtime model feature contract is inconsistent")
        actual = (
            s.model_id,
            s.model_version,
            a.model_id,
            a.model_version,
            fusion.policy_id,
            fusion.policy_version,
            fusion_checksum,
            r.policy_id,
            r.policy_version,
            e.artifact_version,
        )
        expected = (
            fusion.supervised_model_id,
            fusion.supervised_model_version,
            fusion.anomaly_model_id,
            fusion.anomaly_model_version,
            r.required_fusion_policy_id,
            r.required_fusion_policy_version,
            r.required_fusion_policy_checksum,
            e.risk_policy_id,
            e.risk_policy_version,
            self._runtime.policy.explanation_artifact_version,
        )
        if actual != expected:
            raise RuntimePreflightError("runtime model and policy identities do not align")
        explanation_identity = (
            e.supervised_model_id,
            e.supervised_model_version,
            e.anomaly_model_id,
            e.anomaly_model_version,
            e.fusion_policy_id,
            e.fusion_policy_version,
            e.feature_schema_version,
        )
        if explanation_identity != (
            s.model_id,
            s.model_version,
            a.model_id,
            a.model_version,
            fusion.policy_id,
            fusion.policy_version,
            FEATURE_SCHEMA_VERSION,
        ):
            raise RuntimePreflightError("runtime explanation identities do not align")

    def _snapshot(
        self,
        *,
        source: TelemetrySource,
        source_path: Path,
        supervised: LoadedModel,
        anomaly: LoadedAnomalyModel,
        fusion: PolicyManifest,
        fusion_checksum: str,
        risk: LoadedRiskPolicy,
        explanation: LoadedExplanationArtifact,
        correlation: LoadedCorrelationPolicy,
    ) -> RuntimePipelineSnapshot:
        stored_name = source.source_metadata["stored_filename"]
        assert isinstance(stored_name, str)
        explanation_checksum = _hash_file(
            self._settings.detection.explanation_artifact_root
            / explanation.manifest.artifact_version
            / "checksums.json"
        )
        artifacts = (
            RuntimeArtifactIdentity(
                artifact_type="supervised_model",
                artifact_id=supervised.manifest.model_id,
                version=supervised.manifest.model_version,
                checksum=supervised.manifest.artifact_checksum,
            ),
            RuntimeArtifactIdentity(
                artifact_type="anomaly_model",
                artifact_id=anomaly.manifest.model_id,
                version=anomaly.manifest.model_version,
                checksum=anomaly.manifest.artifact_checksum,
            ),
            RuntimeArtifactIdentity(
                artifact_type="fusion_policy",
                artifact_id=fusion.policy_id,
                version=fusion.policy_version,
                checksum=fusion_checksum,
            ),
            RuntimeArtifactIdentity(
                artifact_type="risk_policy",
                artifact_id=risk.policy.policy_id,
                version=risk.policy.policy_version,
                checksum=risk.configuration_checksum,
            ),
            RuntimeArtifactIdentity(
                artifact_type="explanation_artifact",
                artifact_id=explanation.manifest.artifact_id,
                version=explanation.manifest.artifact_version,
                checksum=explanation_checksum,
            ),
            RuntimeArtifactIdentity(
                artifact_type="correlation_policy",
                artifact_id=correlation.policy.policy_id,
                version=correlation.policy.policy_version,
                checksum=correlation.configuration_checksum,
            ),
            RuntimeArtifactIdentity(
                artifact_type="flow_configuration",
                artifact_id="aegishunt-flow-settings",
                version=FEATURE_SCHEMA_VERSION,
                checksum=_flow_checksum(self._settings),
            ),
        )
        return RuntimePipelineSnapshot(
            source_id=source.source_id,
            source_checksum=source.checksum or "",
            source_type=source.source_type,
            stored_filename=stored_name,
            source_size_bytes=_file_size(source_path),
            verified_packet_count=(
                source.records_processed if source.records_processed > 0 else None
            ),
            capture_session_id=f"pcap:{source.source_id}",
            feature_schema_version=FEATURE_SCHEMA_VERSION,
            artifacts=artifacts,
            runtime_policy_id=self._runtime.policy.policy_id,
            runtime_policy_version=self._runtime.policy.policy_version,
            runtime_policy_checksum=self._runtime.configuration_checksum,
            git_commit_sha=_git_commit(self._project_root),
            database_schema_version=CURRENT_SCHEMA_VERSION,
        )
