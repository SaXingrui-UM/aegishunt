"""Boundary and fail-closed coverage for shared data-only artifact I/O."""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import pytest

from aegishunt.artifact_io import (
    CHECKSUMS_FILENAME,
    configured_artifact_root,
    verified_data_artifact_zip,
    verify_data_artifact,
    write_data_artifact,
)
from aegishunt.errors import DataArtifactError

INVENTORY = (CHECKSUMS_FILENAME, "payload.json")


def _write(root: Path, *, version: str = "1.0.0") -> Path:
    return write_data_artifact(
        root=root,
        version=version,
        payloads={"payload.json": b"{}\n"},
        exact_inventory=INVENTORY,
    )


def test_configured_root_and_writer_reject_unsafe_boundaries(tmp_path: Path) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    (tmp_path / "outside-link").symlink_to(outside, target_is_directory=True)
    inside = tmp_path / "inside"
    inside.mkdir()
    (tmp_path / "inside-link").symlink_to(inside, target_is_directory=True)

    with pytest.raises(DataArtifactError, match="escapes"):
        configured_artifact_root(tmp_path, Path("outside-link/artifacts"))
    with pytest.raises(DataArtifactError, match="symlink"):
        configured_artifact_root(tmp_path, Path("inside-link/artifacts"))
    with pytest.raises(DataArtifactError, match="safe identifier"):
        _write(tmp_path / "artifacts", version="../escape")
    with pytest.raises(DataArtifactError, match="inventory declaration"):
        write_data_artifact(
            root=tmp_path / "artifacts",
            version="1.0.0",
            payloads={"payload.json": b"{}"},
            exact_inventory=(CHECKSUMS_FILENAME, "payload.json", "payload.json"),
        )

    symlink_root = tmp_path / "artifact-link"
    symlink_root.symlink_to(outside, target_is_directory=True)
    with pytest.raises(DataArtifactError, match="root cannot be a symlink"):
        _write(symlink_root)


def test_writer_rejects_staging_collision_and_unsafe_name(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    root.mkdir()
    staging = root / f".1.0.0.tmp-{__import__('os').getpid()}"
    staging.mkdir()
    with pytest.raises(DataArtifactError, match="staging path already exists"):
        _write(root)
    staging.rmdir()

    with pytest.raises(DataArtifactError, match="filename is unsafe"):
        write_data_artifact(
            root=root,
            version="1.0.1",
            payloads={"../escape": b"unsafe"},
            exact_inventory=(CHECKSUMS_FILENAME, "../escape"),
        )
    assert not (root / f".1.0.1.tmp-{__import__('os').getpid()}").exists()


def test_writer_wraps_root_and_file_io_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "artifacts"
    original_mkdir = Path.mkdir

    def unavailable_mkdir(path: Path, *args: object, **kwargs: object) -> None:
        if path == root:
            raise OSError("unavailable")
        original_mkdir(path, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", unavailable_mkdir)
    with pytest.raises(DataArtifactError, match="root is unavailable"):
        _write(root)
    monkeypatch.setattr(Path, "mkdir", original_mkdir)

    original_write = Path.write_bytes

    def unavailable_write(path: Path, payload: bytes) -> int:
        if path.name == "payload.json":
            raise OSError("unavailable")
        return original_write(path, payload)

    monkeypatch.setattr(Path, "write_bytes", unavailable_write)
    with pytest.raises(DataArtifactError, match="could not be written atomically"):
        _write(root)
    assert not any(root.glob(".*.tmp-*"))


def test_verifier_rejects_escape_symlink_and_nonregular_inventory(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    path = _write(root)
    with pytest.raises(DataArtifactError, match="outside configured storage"):
        verify_data_artifact(tmp_path / "missing", root=root, exact_inventory=INVENTORY)

    outside = tmp_path / "outside"
    outside.mkdir()
    symlink_root = tmp_path / "root-link"
    symlink_root.symlink_to(root, target_is_directory=True)
    with pytest.raises(DataArtifactError, match="root cannot be a symlink"):
        verify_data_artifact(path, root=symlink_root, exact_inventory=INVENTORY)

    (path / "payload.json").unlink()
    (path / "payload.json").symlink_to(outside, target_is_directory=True)
    with pytest.raises(DataArtifactError, match="regular files"):
        verify_data_artifact(path, root=root, exact_inventory=INVENTORY)


def test_verified_zip_is_deterministic_and_preserves_exact_inventory(
    tmp_path: Path,
) -> None:
    root = tmp_path / "artifacts"
    path = _write(root)

    first = verified_data_artifact_zip(
        path,
        root=root,
        exact_inventory=INVENTORY,
    )
    second = verified_data_artifact_zip(
        path,
        root=root,
        exact_inventory=INVENTORY,
    )
    assert first == second
    with zipfile.ZipFile(io.BytesIO(first)) as archive:
        assert archive.namelist() == sorted(INVENTORY)
        assert archive.read("payload.json") == b"{}\n"
        checksums = json.loads(archive.read(CHECKSUMS_FILENAME))
        assert set(checksums["checksums"]) == {"payload.json"}

    (path / "payload.json").write_bytes(b"corrupt")
    with pytest.raises(DataArtifactError, match="checksum verification failed"):
        verified_data_artifact_zip(path, root=root, exact_inventory=INVENTORY)


@pytest.mark.parametrize(
    ("checksums", "message"),
    [
        (b"not-json", "content is invalid"),
        (
            json.dumps({"checksum_schema_version": "9.9.9", "checksums": {}}).encode(),
            "checksum schema is invalid",
        ),
        (
            json.dumps(
                {
                    "checksum_schema_version": "1.0.0",
                    "checksums": {"unexpected.json": "0" * 64},
                }
            ).encode(),
            "checksum inventory is invalid",
        ),
    ],
)
def test_verifier_rejects_malformed_checksum_contract(
    tmp_path: Path,
    checksums: bytes,
    message: str,
) -> None:
    root = tmp_path / "artifacts"
    path = _write(root)
    (path / CHECKSUMS_FILENAME).write_bytes(checksums)

    with pytest.raises(DataArtifactError, match=message):
        verify_data_artifact(path, root=root, exact_inventory=INVENTORY)
