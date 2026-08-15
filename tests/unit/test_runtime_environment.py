"""Runtime artifact-environment selection regressions."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import yaml

from aegishunt.api import dependencies
from aegishunt.config import ApplicationSettings
from aegishunt.demo import DemoArtifactEnvironment, DemoArtifactManager
from aegishunt.runtime.config import load_runtime_policy
from aegishunt.runtime.environment import (
    ResolvedRuntimeEnvironment,
    resolve_job_execution_environment,
    resolve_replay_creation_environment,
)
from tests.fixtures.runtime import PROJECT_ROOT, runtime_snapshot


def _settings_with_runtime_policy(
    tmp_path: Path,
    *,
    policy_id: str,
) -> tuple[ApplicationSettings, Path]:
    payload = yaml.safe_load(
        (PROJECT_ROOT / "configs/runtime.yaml").read_text(encoding="utf-8")
    )
    assert isinstance(payload, dict)
    payload["policy_id"] = policy_id
    policy_path = tmp_path / f"{policy_id}.yaml"
    policy_path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    base = ApplicationSettings()
    settings = base.model_copy(
        update={
            "runtime": base.runtime.model_copy(
                update={"policy_path": policy_path}
            )
        }
    )
    return settings, policy_path


def test_replay_creation_uses_current_prepared_environment_as_one_unit(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    configured = ApplicationSettings()
    prepared_settings, policy_path = _settings_with_runtime_policy(
        tmp_path,
        policy_id="prepared-demo-runtime",
    )
    prepared = DemoArtifactEnvironment(
        settings=prepared_settings,
        root=tmp_path / "prepared-demo",
        reused=True,
    )
    monkeypatch.setattr(DemoArtifactManager, "read", lambda self: prepared)

    resolved = resolve_replay_creation_environment(
        configured,
        project_root=tmp_path,
    )

    assert resolved.source == "prepared_demo"
    assert resolved.settings is prepared_settings
    assert resolved.runtime_policy == load_runtime_policy(policy_path)


def test_worker_resolves_historical_demo_by_pinned_fusion_identity(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    configured = ApplicationSettings()
    historical_settings, policy_path = _settings_with_runtime_policy(
        tmp_path,
        policy_id="historical-demo-runtime",
    )
    historical_policy = load_runtime_policy(policy_path)
    snapshot = runtime_snapshot().model_copy(
        update={
            "runtime_policy_id": historical_policy.policy.policy_id,
            "runtime_policy_version": historical_policy.policy.policy_version,
            "runtime_policy_checksum": historical_policy.configuration_checksum,
        }
    )
    fusion = next(
        item for item in snapshot.artifacts if item.artifact_type == "fusion_policy"
    )
    observed: dict[str, str] = {}

    def read_for_fusion_policy(
        self: DemoArtifactManager,
        *,
        policy_id: str,
        policy_version: str,
        policy_checksum: str,
    ) -> DemoArtifactEnvironment:
        del self
        observed.update(
            {
                "policy_id": policy_id,
                "policy_version": policy_version,
                "policy_checksum": policy_checksum,
            }
        )
        return DemoArtifactEnvironment(
            settings=historical_settings,
            root=tmp_path / "historical-demo",
            reused=True,
        )

    monkeypatch.setattr(
        DemoArtifactManager,
        "read_for_fusion_policy",
        read_for_fusion_policy,
    )

    resolved = resolve_job_execution_environment(
        configured,
        snapshot,
        project_root=tmp_path,
    )

    assert resolved.source == "runtime_snapshot_demo"
    assert resolved.settings is historical_settings
    assert resolved.runtime_policy == historical_policy
    assert observed == {
        "policy_id": fusion.artifact_id,
        "policy_version": fusion.version,
        "policy_checksum": fusion.checksum,
    }


def test_api_resolves_demo_only_for_replay_creation(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    configured = ApplicationSettings()
    prepared_settings, policy_path = _settings_with_runtime_policy(
        tmp_path,
        policy_id="api-prepared-demo-runtime",
    )
    prepared_policy = load_runtime_policy(policy_path)
    request = SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(settings=configured, database=object())
        )
    )
    calls: list[dict[str, object]] = []

    def service(database: object, **kwargs: object) -> object:
        calls.append({"database": database, **kwargs})
        return object()

    def resolve(
        settings: ApplicationSettings,
        *,
        project_root: Path,
    ) -> ResolvedRuntimeEnvironment:
        assert settings is configured
        assert project_root == Path.cwd()
        return ResolvedRuntimeEnvironment(
            settings=prepared_settings,
            runtime_policy=prepared_policy,
            source="prepared_demo",
        )

    monkeypatch.setattr(dependencies, "RuntimeJobService", service)
    monkeypatch.setattr(
        dependencies,
        "resolve_replay_creation_environment",
        resolve,
    )

    dependencies.get_runtime_service(request)
    dependencies.get_replay_creation_service(request)

    assert calls[0]["settings"] is configured
    assert calls[0]["runtime_policy"] == load_runtime_policy(
        configured.runtime.policy_path
    )
    assert calls[1]["settings"] is prepared_settings
    assert calls[1]["runtime_policy"] is prepared_policy
