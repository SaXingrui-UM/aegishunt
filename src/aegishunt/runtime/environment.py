"""Resolve one verified artifact environment for replay creation and execution."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from aegishunt.config import ApplicationSettings
from aegishunt.demo import DemoArtifactManager
from aegishunt.runtime.config import LoadedRuntimePolicy, load_runtime_policy
from aegishunt.runtime.contracts import RuntimePipelineSnapshot


@dataclass(frozen=True, slots=True)
class ResolvedRuntimeEnvironment:
    """Settings and policy that must be used together for one runtime operation."""

    settings: ApplicationSettings
    runtime_policy: LoadedRuntimePolicy
    source: str


def _environment(
    settings: ApplicationSettings,
    *,
    source: str,
) -> ResolvedRuntimeEnvironment:
    return ResolvedRuntimeEnvironment(
        settings=settings,
        runtime_policy=load_runtime_policy(settings.runtime.policy_path),
        source=source,
    )


def resolve_replay_creation_environment(
    settings: ApplicationSettings,
    *,
    project_root: Path,
) -> ResolvedRuntimeEnvironment:
    """Prefer the current prepared demo pipeline without preparing or copying it.

    The local delivery does not ship a production-qualified model pipeline. Once the
    explicit controlled environment has been prepared, uploaded PCAPs must therefore
    use that environment as one unit instead of mixing its artifacts with base policy
    files or stale files retained in a Docker volume.
    """

    if settings.web.sample_mode_enabled:
        prepared = DemoArtifactManager(
            settings,
            project_root=project_root,
        ).read()
        if prepared is not None:
            return _environment(prepared.settings, source="prepared_demo")
    return _environment(settings, source="configured")


def resolve_job_execution_environment(
    settings: ApplicationSettings,
    snapshot: RuntimePipelineSnapshot,
    *,
    project_root: Path,
) -> ResolvedRuntimeEnvironment:
    """Resolve the exact environment named by an immutable replay snapshot."""

    configured = _environment(settings, source="configured")
    if _runtime_policy_matches(configured.runtime_policy, snapshot):
        return configured

    fusion = next(
        artifact
        for artifact in snapshot.artifacts
        if artifact.artifact_type == "fusion_policy"
    )
    if settings.web.sample_mode_enabled:
        prepared = DemoArtifactManager(
            settings,
            project_root=project_root,
        ).read_for_fusion_policy(
            policy_id=fusion.artifact_id,
            policy_version=fusion.version,
            policy_checksum=fusion.checksum,
        )
        if prepared is not None:
            historical = _environment(
                prepared.settings,
                source="runtime_snapshot_demo",
            )
            if _runtime_policy_matches(historical.runtime_policy, snapshot):
                return historical

    # The normal runner still performs complete source, artifact, policy, and
    # snapshot verification. Returning the configured environment preserves that
    # fail-closed error path when a pinned historical environment is unavailable.
    return configured


def _runtime_policy_matches(
    runtime_policy: LoadedRuntimePolicy,
    snapshot: RuntimePipelineSnapshot,
) -> bool:
    return (
        runtime_policy.policy.policy_id == snapshot.runtime_policy_id
        and runtime_policy.policy.policy_version == snapshot.runtime_policy_version
        and runtime_policy.configuration_checksum == snapshot.runtime_policy_checksum
    )
