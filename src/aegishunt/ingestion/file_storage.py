"""Bounded staging and atomic storage for untrusted telemetry files."""

from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path
from typing import BinaryIO

from aegishunt.ingestion.base import FilePolicy
from aegishunt.ingestion.errors import FilePolicyError, FileStorageError
from aegishunt.ingestion.schemas import StagedFile, StoredFile


class SafeFileStorage:
    """Store uploads below a configured root without trusting client paths."""

    def __init__(self, root: Path, *, max_bytes: int, chunk_size: int) -> None:
        self._root = root.expanduser()
        self._max_bytes = max_bytes
        self._chunk_size = chunk_size

    @staticmethod
    def validate_filename(filename: str, policy: FilePolicy) -> str:
        """Reject traversal, separators, blank names, and unsupported suffixes."""

        if (
            not filename
            or filename in {".", ".."}
            or "\x00" in filename
            or "/" in filename
            or "\\" in filename
            or Path(filename).name != filename
        ):
            raise FilePolicyError("upload filename is unsafe")
        extension = Path(filename).suffix.lower()
        if extension not in policy.extensions:
            raise FilePolicyError(f"unsupported file extension: {extension or '<none>'}")
        return extension

    @staticmethod
    def validate_content_type(content_type: str | None, policy: FilePolicy) -> str | None:
        """Validate a declared media type when an API client supplies one."""

        if content_type is None or not content_type.strip():
            return None
        normalized = content_type.split(";", maxsplit=1)[0].strip().lower()
        if normalized not in policy.content_types:
            raise FilePolicyError(f"unsupported content type: {normalized}")
        return normalized

    def stage(
        self,
        stream: BinaryIO,
        *,
        filename: str,
        content_type: str | None,
        policy: FilePolicy,
    ) -> StagedFile:
        """Write a bounded upload to a private temporary file while hashing it."""

        extension = self.validate_filename(filename, policy)
        normalized_content_type = self.validate_content_type(content_type, policy)
        try:
            self._root.mkdir(parents=True, exist_ok=True, mode=0o750)
            descriptor, temporary_name = tempfile.mkstemp(prefix=".upload-", dir=self._root)
        except OSError as exc:
            raise FileStorageError("unable to create controlled upload staging file") from exc

        temporary_path = Path(temporary_name)
        digest = hashlib.sha256()
        byte_size = 0
        try:
            with os.fdopen(descriptor, "wb") as destination:
                while True:
                    chunk = stream.read(self._chunk_size)
                    if not chunk:
                        break
                    if not isinstance(chunk, bytes):
                        raise FileStorageError("upload stream must provide bytes")
                    byte_size += len(chunk)
                    if byte_size > self._max_bytes:
                        raise FilePolicyError(
                            f"upload exceeds configured limit of {self._max_bytes} bytes"
                        )
                    digest.update(chunk)
                    destination.write(chunk)
                destination.flush()
                os.fsync(destination.fileno())
            if byte_size == 0:
                raise FilePolicyError("upload file is empty")
        except (FilePolicyError, FileStorageError):
            temporary_path.unlink(missing_ok=True)
            raise
        except OSError as exc:
            temporary_path.unlink(missing_ok=True)
            raise FileStorageError("unable to write controlled upload staging file") from exc

        return StagedFile(
            path=str(temporary_path),
            original_filename=filename,
            safe_extension=extension,
            checksum=digest.hexdigest(),
            byte_size=byte_size,
            content_type=normalized_content_type,
        )

    def commit(self, staged: StagedFile) -> StoredFile:
        """Atomically move a validated staged file to a checksum-derived name."""

        staged_path = Path(staged.path)
        final_name = f"{staged.checksum}{staged.safe_extension}"
        final_path = self._root / final_name
        try:
            if final_path.exists():
                if final_path.is_symlink() or not final_path.is_file():
                    raise FileStorageError("stored checksum path is not a regular file")
                if final_path.stat().st_size != staged.byte_size:
                    raise FileStorageError("stored checksum collision has an unexpected size")
                digest = hashlib.sha256()
                with final_path.open("rb") as existing:
                    while chunk := existing.read(self._chunk_size):
                        digest.update(chunk)
                if digest.hexdigest() != staged.checksum:
                    raise FileStorageError(
                        "existing checksum-addressed file failed integrity check"
                    )
                staged_path.unlink(missing_ok=True)
            else:
                os.replace(staged_path, final_path)
        except FileStorageError:
            staged_path.unlink(missing_ok=True)
            raise
        except OSError as exc:
            staged_path.unlink(missing_ok=True)
            raise FileStorageError("unable to atomically store validated upload") from exc
        return StoredFile(
            stored_filename=final_name,
            checksum=staged.checksum,
            byte_size=staged.byte_size,
        )

    @staticmethod
    def discard(staged: StagedFile | None) -> None:
        """Remove a staging file after validation failure."""

        if staged is not None:
            Path(staged.path).unlink(missing_ok=True)
