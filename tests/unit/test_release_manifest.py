"""Exact-inventory release-manifest regression tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegishunt.delivery.release_manifest import (
    ReleaseManifestError,
    build_release_manifest,
    verify_release_bundle,
    write_release_manifest,
)


def _bundle(tmp_path: Path) -> Path:
    root = tmp_path / "release"
    (root / "project").mkdir(parents=True)
    (root / "project/README.md").write_text("reviewed\n", encoding="utf-8")
    manifest = build_release_manifest(
        root,
        git_commit="a" * 40,
        generated_at="2026-07-30T00:00:00+00:00",
        database_schema=5,
        demo_models=(),
    )
    write_release_manifest(root, manifest)
    return root


def test_release_manifest_verifies_exact_inventory(tmp_path: Path) -> None:
    root = _bundle(tmp_path)
    payload = verify_release_bundle(root)

    assert payload["application_version"] == "1.0.0"
    assert payload["artifact_inventory"][0]["path"] == "project/README.md"


@pytest.mark.parametrize("mutation", ["corrupt", "missing", "extra"])
def test_release_manifest_rejects_inventory_mutation(
    tmp_path: Path,
    mutation: str,
) -> None:
    root = _bundle(tmp_path)
    if mutation == "corrupt":
        (root / "project/README.md").write_text("changed\n", encoding="utf-8")
    elif mutation == "missing":
        (root / "project/README.md").unlink()
    else:
        (root / "unexpected.txt").write_text("unexpected\n", encoding="utf-8")

    with pytest.raises(ReleaseManifestError):
        verify_release_bundle(root)


def test_release_manifest_rejects_unsafe_or_duplicate_declared_paths(
    tmp_path: Path,
) -> None:
    root = _bundle(tmp_path)
    path = root / "release-manifest.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["artifact_inventory"][0]["path"] = "../outside"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ReleaseManifestError, match="unsafe or duplicated"):
        verify_release_bundle(root)


def test_release_manifest_rejects_symlink(tmp_path: Path) -> None:
    root = _bundle(tmp_path)
    target = tmp_path / "outside"
    target.write_text("outside\n", encoding="utf-8")
    (root / "linked").symlink_to(target)

    with pytest.raises(ReleaseManifestError, match="symlink"):
        verify_release_bundle(root)


def test_release_manifest_refuses_manifest_overwrite(tmp_path: Path) -> None:
    root = _bundle(tmp_path)
    with pytest.raises(ReleaseManifestError, match="already exists"):
        write_release_manifest(root, {})
