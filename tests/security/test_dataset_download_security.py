"""Checksum, overwrite, archive traversal, and manual-license acquisition tests."""

from __future__ import annotations

import hashlib
import io
import tarfile
import urllib.error
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import IO

import pytest

from aegishunt.datasets.download import download_dataset_file, extract_archive
from aegishunt.datasets.errors import DatasetAcquisitionError, ManualDownloadRequiredError
from aegishunt.datasets.registry import DatasetRegistry
from aegishunt.datasets.schemas import DatasetDefinition
from tests.fixtures.datasets import REGISTRY_PATH


def _automatic_definition(checksum: str | None = None) -> DatasetDefinition:
    return DatasetDefinition.model_validate(
        {
            "dataset_id": "automatic-test-data",
            "name": "Automatic test data",
            "version": "1",
            "dataset_type": "public_benchmark",
            "source_url": "https://example.invalid/data.bin",
            "official_page": "https://example.invalid/official",
            "provider": "Test provider",
            "license_name": "Test academic license",
            "license_url": "https://example.invalid/license",
            "academic_use_status": "permitted",
            "expected_format": ["archive"],
            "expected_files": [
                {"filename": "data.bin", "checksum_sha256": checksum, "required": True}
            ],
            "expected_checksum": None,
            "locally_computed_checksum": None,
            "raw_schema_reference": "test schema",
            "canonical_schema_version": "1.0.0",
            "feature_schema_version": "1.0.0",
            "label_schema": "mapping.yaml",
            "group_fields": ["source_file"],
            "download_status": "automatic",
            "conversion_status": "supported",
            "known_limitations": [],
            "citation": "Test citation",
            "created_at": datetime(2026, 1, 1, tzinfo=UTC),
            "updated_at": datetime(2026, 1, 1, tzinfo=UTC),
        }
    )


def _opener(payload: bytes) -> object:
    @contextmanager
    def open_response(url: str) -> Iterator[IO[bytes]]:
        assert "example.invalid" in url
        with io.BytesIO(payload) as response:
            yield response

    return open_response


def test_download_verifies_checksum_and_reuses_without_overwrite(tmp_path: Path) -> None:
    payload = b"reviewed dataset bytes"
    checksum = hashlib.sha256(payload).hexdigest()
    definition = _automatic_definition(checksum)
    opener = _opener(payload)

    path, computed = download_dataset_file(
        definition,
        tmp_path,
        max_bytes=1024,
        opener=opener,  # type: ignore[arg-type]
    )
    second, second_checksum = download_dataset_file(
        definition,
        tmp_path,
        max_bytes=1024,
        opener=_opener(b"must not overwrite"),  # type: ignore[arg-type]
    )

    assert path == second
    assert path.read_bytes() == payload
    assert computed == second_checksum == checksum


def test_download_rejects_checksum_mismatch_size_and_transport_failure(tmp_path: Path) -> None:
    mismatch = _automatic_definition("0" * 64)
    with pytest.raises(DatasetAcquisitionError, match="checksum does not match"):
        download_dataset_file(
            mismatch,
            tmp_path / "mismatch",
            max_bytes=1024,
            opener=_opener(b"different"),  # type: ignore[arg-type]
        )

    definition = _automatic_definition()
    with pytest.raises(DatasetAcquisitionError, match="exceeds"):
        download_dataset_file(
            definition,
            tmp_path / "large",
            max_bytes=2,
            opener=_opener(b"too large"),  # type: ignore[arg-type]
        )

    @contextmanager
    def failing(url: str) -> Iterator[IO[bytes]]:
        del url
        raise urllib.error.URLError("credentials?secret=not-shown")
        yield io.BytesIO()  # pragma: no cover

    with pytest.raises(DatasetAcquisitionError, match="download failed") as failure:
        download_dataset_file(
            definition,
            tmp_path / "failed",
            max_bytes=1024,
            opener=failing,
        )
    assert "secret" not in str(failure.value)


def test_existing_checksum_mismatch_is_not_overwritten(tmp_path: Path) -> None:
    definition = _automatic_definition(hashlib.sha256(b"expected").hexdigest())
    target = tmp_path / definition.dataset_id / definition.version / "data.bin"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"existing")

    with pytest.raises(DatasetAcquisitionError, match="existing.*checksum"):
        download_dataset_file(
            definition,
            tmp_path,
            max_bytes=1024,
            opener=_opener(b"expected"),  # type: ignore[arg-type]
        )
    assert target.read_bytes() == b"existing"


def test_manual_dataset_never_contacts_network(tmp_path: Path) -> None:
    definition = DatasetRegistry.load(REGISTRY_PATH).describe("cse-cic-ids2018")
    contacted = False

    @contextmanager
    def opener(url: str) -> Iterator[IO[bytes]]:
        nonlocal contacted
        contacted = True
        del url
        yield io.BytesIO()

    with pytest.raises(ManualDownloadRequiredError, match="manual acquisition"):
        download_dataset_file(definition, tmp_path, max_bytes=1024, opener=opener)
    assert contacted is False


def _write_zip(path: Path, members: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        for name, payload in members.items():
            archive.writestr(name, payload)
    return path


def test_safe_zip_extraction_and_limits(tmp_path: Path) -> None:
    archive = _write_zip(tmp_path / "safe.zip", {"nested/data.csv": b"a,b\n1,2\n"})
    destination = tmp_path / "extracted"

    extracted = extract_archive(
        archive,
        destination,
        allowed_root=tmp_path,
        max_members=2,
        max_extracted_bytes=100,
    )

    assert extracted == (destination / "nested" / "data.csv",)
    assert extracted[0].read_bytes() == b"a,b\n1,2\n"

    too_many = _write_zip(tmp_path / "many.zip", {"a": b"1", "b": b"2"})
    with pytest.raises(DatasetAcquisitionError, match="too many"):
        extract_archive(
            too_many,
            tmp_path / "many",
            allowed_root=tmp_path,
            max_members=1,
            max_extracted_bytes=10,
        )

    too_large = _write_zip(tmp_path / "large.zip", {"large": b"12345"})
    with pytest.raises(DatasetAcquisitionError, match="expands beyond"):
        extract_archive(
            too_large,
            tmp_path / "large",
            allowed_root=tmp_path,
            max_members=1,
            max_extracted_bytes=4,
        )


@pytest.mark.parametrize("member", ["../outside.csv", "/absolute.csv"])
def test_archive_traversal_and_absolute_paths_are_rejected(tmp_path: Path, member: str) -> None:
    archive = _write_zip(tmp_path / "unsafe.zip", {member: b"no"})
    outside = tmp_path / "outside.csv"

    with pytest.raises(DatasetAcquisitionError, match="unsafe member"):
        extract_archive(
            archive,
            tmp_path / "unsafe-output",
            allowed_root=tmp_path,
            max_members=10,
            max_extracted_bytes=100,
        )

    assert not outside.exists()


def test_tar_links_and_malformed_archives_are_rejected(tmp_path: Path) -> None:
    archive = tmp_path / "link.tar"
    with tarfile.open(archive, "w") as container:
        link = tarfile.TarInfo("link")
        link.type = tarfile.SYMTYPE
        link.linkname = "../outside"
        container.addfile(link)
    with pytest.raises(DatasetAcquisitionError, match="non-regular"):
        extract_archive(
            archive,
            tmp_path / "tar-output",
            allowed_root=tmp_path,
            max_members=10,
            max_extracted_bytes=100,
        )


def test_archive_destination_must_remain_under_configured_root(tmp_path: Path) -> None:
    archive = _write_zip(tmp_path / "safe.zip", {"data.csv": b"ok"})
    with pytest.raises(DatasetAcquisitionError, match="outside the configured root"):
        extract_archive(
            archive,
            tmp_path.parent / "outside-dataset-root",
            allowed_root=tmp_path,
            max_members=10,
            max_extracted_bytes=100,
        )

    malformed = tmp_path / "malformed.archive"
    malformed.write_bytes(b"not an archive")
    with pytest.raises(DatasetAcquisitionError, match="malformed"):
        extract_archive(
            malformed,
            tmp_path / "bad-output",
            allowed_root=tmp_path,
            max_members=10,
            max_extracted_bytes=100,
        )
