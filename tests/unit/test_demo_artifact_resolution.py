"""Bounded, fail-closed resolution of historical controlled-demo evidence."""

from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace
from typing import Protocol

import pytest

from aegishunt.config import ApplicationSettings, WebSettings
from aegishunt.demo.artifacts import DemoArtifactManager
from aegishunt.errors import DataArtifactError


class _Paths(Protocol):
    fusion_models: Path


def _manager(tmp_path: Path) -> DemoArtifactManager:
    settings = ApplicationSettings(
        web=WebSettings(
            demo_artifact_root=Path("demo"),
            demo_namespace="phase14-controlled-demo",
            demo_operation_version="1.0.2",
        )
    )
    return DemoArtifactManager(settings, project_root=tmp_path)


def _policy_manifest(tmp_path: Path, operation_version: str, payload: bytes) -> Path:
    path = (
        tmp_path
        / "demo"
        / f"phase14-controlled-demo-{operation_version}"
        / "models/fusion/1.0.0/fusion_policy_manifest.json"
    )
    path.parent.mkdir(parents=True)
    path.write_bytes(payload)
    return path


def _stub_full_verification(
    monkeypatch: pytest.MonkeyPatch,
    *,
    policy_id: str = "phase14-controlled-demo-fusion",
) -> None:
    def verified_settings(
        manager: DemoArtifactManager,
        paths: _Paths,
        *,
        enforce_current_correlation_capacity: bool = True,
    ) -> ApplicationSettings:
        assert enforce_current_correlation_capacity is False
        return manager._settings.model_copy(  # noqa: SLF001 - focused boundary test
            update={
                "runtime": manager._settings.runtime.model_copy(  # noqa: SLF001
                    update={"fusion_policy_root": paths.fusion_models}
                )
            }
        )

    monkeypatch.setattr(DemoArtifactManager, "_verify", verified_settings)
    monkeypatch.setattr(
        "aegishunt.demo.artifacts.load_policy",
        lambda *_args, **_kwargs: SimpleNamespace(
            policy_id=policy_id,
            policy_version="1.0.0",
        ),
    )


def test_historical_demo_environment_is_selected_only_by_exact_policy_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _policy_manifest(tmp_path, "1.0.0", b"old immutable policy\n")
    checksum = hashlib.sha256(manifest.read_bytes()).hexdigest()
    _policy_manifest(tmp_path, "1.0.1", b"new current policy\n")
    _stub_full_verification(monkeypatch)

    manager = _manager(tmp_path)
    resolved = manager.read_for_fusion_policy(
        policy_id="phase14-controlled-demo-fusion",
        policy_version="1.0.0",
        policy_checksum=checksum,
    )

    assert resolved is not None
    assert resolved.root.name == "phase14-controlled-demo-1.0.0"
    assert resolved.reused is True
    assert (
        manager.read_for_fusion_policy(
            policy_id="phase14-controlled-demo-fusion",
            policy_version="1.0.0",
            policy_checksum="f" * 64,
        )
        is None
    )


def test_duplicate_policy_identity_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"duplicated policy\n"
    manifest = _policy_manifest(tmp_path, "1.0.0", payload)
    _policy_manifest(tmp_path, "1.0.1", payload)
    checksum = hashlib.sha256(manifest.read_bytes()).hexdigest()
    _stub_full_verification(monkeypatch)

    with pytest.raises(DataArtifactError, match="ambiguous"):
        _manager(tmp_path).read_for_fusion_policy(
            policy_id="phase14-controlled-demo-fusion",
            policy_version="1.0.0",
            policy_checksum=checksum,
        )


def test_matching_demo_symlink_and_oversized_history_are_rejected(
    tmp_path: Path,
) -> None:
    base = tmp_path / "demo"
    base.mkdir()
    external = tmp_path / "external"
    external.mkdir()
    (base / "phase14-controlled-demo-1.0.0").symlink_to(
        external,
        target_is_directory=True,
    )
    manager = _manager(tmp_path)
    with pytest.raises(DataArtifactError, match="environment is invalid"):
        manager.read_for_fusion_policy(
            policy_id="phase14-controlled-demo-fusion",
            policy_version="1.0.0",
            policy_checksum="a" * 64,
        )

    (base / "phase14-controlled-demo-1.0.0").unlink()
    for index in range(101):
        (base / f"unrelated-{index}").mkdir()
    with pytest.raises(DataArtifactError, match="safe scan limit"):
        manager.read_for_fusion_policy(
            policy_id="phase14-controlled-demo-fusion",
            policy_version="1.0.0",
            policy_checksum="a" * 64,
        )
