"""Checksum-verified registry for controlled Phase 2 demonstration samples."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from aegishunt.ingestion.errors import SampleDataError
from aegishunt.ingestion.schemas import SampleDescriptor
from aegishunt.schemas.enums import SourceType


class _SampleEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    sample_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    filename: str = Field(min_length=1, max_length=255)
    source_type: SourceType
    content_type: str = Field(min_length=1, max_length=255)
    checksum: str = Field(pattern=r"^[0-9a-f]{64}$")
    description: str = Field(min_length=1, max_length=512)
    synthetic: bool

    @field_validator("source_type")
    @classmethod
    def validate_source_type(cls, value: SourceType) -> SourceType:
        if value not in {SourceType.PCAP, SourceType.FLOW_CSV, SourceType.JSON_EVENT}:
            raise ValueError("sample source type must be a supported file telemetry type")
        return value


class _SampleManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: int = Field(ge=1, le=1)
    samples: tuple[_SampleEntry, ...] = Field(min_length=1)


@dataclass(frozen=True, slots=True)
class ResolvedSample:
    """Internal verified sample reference used by the ingestion service."""

    descriptor: SampleDescriptor
    path: Path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(65_536):
                digest.update(chunk)
    except OSError as exc:
        raise SampleDataError("unable to read configured sample data") from exc
    return digest.hexdigest()


class SampleDataRegistry:
    """Read a reviewed manifest and verify every selected file before use."""

    def __init__(self, root: Path) -> None:
        self._root = root.expanduser().resolve()
        self._manifest_path = self._root / "manifest.yaml"

    def _load(self) -> tuple[_SampleEntry, ...]:
        try:
            raw = yaml.safe_load(self._manifest_path.read_text(encoding="utf-8"))
            manifest = _SampleManifest.model_validate(raw)
        except OSError as exc:
            raise SampleDataError("sample manifest is unavailable") from exc
        except yaml.YAMLError as exc:
            raise SampleDataError("sample manifest contains invalid YAML") from exc
        except ValidationError as exc:
            raise SampleDataError("sample manifest failed validation") from exc
        identifiers = [entry.sample_id for entry in manifest.samples]
        if len(identifiers) != len(set(identifiers)):
            raise SampleDataError("sample manifest contains duplicate identifiers")
        return manifest.samples

    def _path_for(self, entry: _SampleEntry) -> Path:
        candidate = (self._root / entry.filename).resolve()
        if not candidate.is_relative_to(self._root) or candidate == self._root:
            raise SampleDataError("sample manifest contains an unsafe file path")
        if not candidate.is_file():
            raise SampleDataError("configured sample file is unavailable")
        return candidate

    def list(self) -> list[SampleDescriptor]:
        """List declared sample metadata without claiming detection outcomes."""

        return [SampleDescriptor.model_validate(entry.model_dump()) for entry in self._load()]

    def resolve(self, sample_id: str) -> ResolvedSample:
        """Resolve and checksum-verify one allowlisted sample."""

        entry = next((item for item in self._load() if item.sample_id == sample_id), None)
        if entry is None:
            raise SampleDataError("unknown sample identifier")
        path = self._path_for(entry)
        if _sha256(path) != entry.checksum:
            raise SampleDataError("sample checksum verification failed")
        return ResolvedSample(
            descriptor=SampleDescriptor.model_validate(entry.model_dump()),
            path=path,
        )
