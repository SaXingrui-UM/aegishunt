"""Explicit, bounded, checksum-aware dataset acquisition and extraction."""

from __future__ import annotations

import hashlib
import shutil
import tarfile
import urllib.error
import urllib.request
import zipfile
from collections.abc import Callable
from contextlib import AbstractContextManager, suppress
from pathlib import Path, PurePosixPath
from typing import IO
from urllib.parse import urlsplit

from aegishunt.datasets.errors import (
    DatasetAcquisitionError,
    ManualDownloadRequiredError,
)
from aegishunt.datasets.io import sha256_file
from aegishunt.datasets.schemas import DatasetDefinition

OpenResponse = Callable[[str], AbstractContextManager[IO[bytes]]]


def _safe_basename(url: str) -> str:
    name = PurePosixPath(urlsplit(url).path).name
    if not name or name in {".", ".."}:
        raise DatasetAcquisitionError("dataset URL does not identify a safe filename")
    return name


def _expected_checksum(definition: DatasetDefinition, filename: str) -> str | None:
    for expected in definition.expected_files:
        if expected.filename == filename and expected.checksum_sha256 is not None:
            return expected.checksum_sha256
    return definition.expected_checksum


def download_dataset_file(
    definition: DatasetDefinition,
    raw_root: Path,
    *,
    max_bytes: int,
    opener: OpenResponse = urllib.request.urlopen,
) -> tuple[Path, str]:
    """Acquire one automatic file without overwrite or unverified reuse."""

    if definition.download_status != "automatic" or definition.source_url is None:
        raise ManualDownloadRequiredError(
            "dataset requires the provider's documented manual acquisition workflow"
        )
    url = str(definition.source_url)
    filename = (
        definition.expected_files[0].filename
        if len(definition.expected_files) == 1
        else _safe_basename(url)
    )
    target_root = raw_root / definition.dataset_id / definition.version
    target = target_root / filename
    expected_checksum = _expected_checksum(definition, filename)
    if target.exists():
        existing = sha256_file(target)
        if expected_checksum is not None and existing != expected_checksum:
            raise DatasetAcquisitionError("existing dataset file checksum does not match")
        return target, existing

    temporary = target.with_name(f".{target.name}.download")
    if temporary.exists():
        raise DatasetAcquisitionError("incomplete dataset download already exists")
    digest = hashlib.sha256()
    total = 0
    try:
        target_root.mkdir(parents=True, exist_ok=True)
        with opener(url) as response, temporary.open("xb") as destination:
            while chunk := response.read(65_536):
                total += len(chunk)
                if total > max_bytes:
                    raise DatasetAcquisitionError("dataset download exceeds the configured limit")
                destination.write(chunk)
                digest.update(chunk)
        computed = digest.hexdigest()
        if expected_checksum is not None and computed != expected_checksum:
            raise DatasetAcquisitionError("downloaded dataset checksum does not match")
        temporary.replace(target)
    except (OSError, urllib.error.URLError, urllib.error.HTTPError) as exc:
        raise DatasetAcquisitionError("dataset download failed") from exc
    finally:
        with suppress(OSError):
            temporary.unlink(missing_ok=True)
    return target, computed


def _safe_member_path(name: str) -> Path:
    normalized = PurePosixPath(name)
    if normalized.is_absolute() or ".." in normalized.parts or not normalized.parts:
        raise DatasetAcquisitionError("archive contains an unsafe member path")
    return Path(*normalized.parts)


def _copy_member(source: IO[bytes], target: Path, *, maximum: int) -> int:
    written = 0
    with target.open("xb") as destination:
        while chunk := source.read(65_536):
            written += len(chunk)
            if written > maximum:
                raise DatasetAcquisitionError("archive member exceeds the configured limit")
            destination.write(chunk)
    return written


def extract_archive(
    archive: Path,
    destination: Path,
    *,
    allowed_root: Path,
    max_members: int,
    max_extracted_bytes: int,
) -> tuple[Path, ...]:
    """Extract ZIP/TAR regular files while preventing traversal and bombs."""

    try:
        destination.resolve().relative_to(allowed_root.resolve())
    except ValueError as exc:
        raise DatasetAcquisitionError("archive destination is outside the configured root") from exc
    if destination.exists():
        raise DatasetAcquisitionError("archive destination already exists")
    temporary = destination.with_name(f".{destination.name}.extracting")
    extracted: list[Path] = []
    total = 0
    try:
        temporary.mkdir(parents=True)
        if zipfile.is_zipfile(archive):
            with zipfile.ZipFile(archive) as container:
                zip_members = container.infolist()
                if len(zip_members) > max_members:
                    raise DatasetAcquisitionError("archive contains too many members")
                for zip_member in zip_members:
                    if zip_member.is_dir():
                        continue
                    relative = _safe_member_path(zip_member.filename)
                    if zip_member.external_attr >> 16 & 0o170000 == 0o120000:
                        raise DatasetAcquisitionError("archive symbolic links are not allowed")
                    total += zip_member.file_size
                    if total > max_extracted_bytes:
                        raise DatasetAcquisitionError("archive expands beyond the configured limit")
                    target = temporary / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with container.open(zip_member) as zip_source:
                        _copy_member(zip_source, target, maximum=zip_member.file_size)
                    extracted.append(destination / relative)
        elif tarfile.is_tarfile(archive):
            with tarfile.open(archive, mode="r:*") as container:
                tar_members = container.getmembers()
                if len(tar_members) > max_members:
                    raise DatasetAcquisitionError("archive contains too many members")
                for tar_member in tar_members:
                    if tar_member.isdir():
                        continue
                    if not tar_member.isfile():
                        raise DatasetAcquisitionError("archive contains a non-regular member")
                    relative = _safe_member_path(tar_member.name)
                    total += tar_member.size
                    if total > max_extracted_bytes:
                        raise DatasetAcquisitionError("archive expands beyond the configured limit")
                    tar_source = container.extractfile(tar_member)
                    if tar_source is None:
                        raise DatasetAcquisitionError("archive member cannot be read")
                    target = temporary / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with tar_source:
                        _copy_member(tar_source, target, maximum=tar_member.size)
                    extracted.append(destination / relative)
        else:
            raise DatasetAcquisitionError("unsupported or malformed archive")
        temporary.replace(destination)
    except (OSError, tarfile.TarError, zipfile.BadZipFile) as exc:
        raise DatasetAcquisitionError("archive extraction failed") from exc
    finally:
        try:
            shutil.rmtree(temporary)
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise DatasetAcquisitionError("archive cleanup failed") from exc
    return tuple(sorted(extracted))
