"""Unit tests for bounded, traversal-resistant telemetry file storage."""

from io import BytesIO
from pathlib import Path

import pytest

from aegishunt.ingestion.errors import FilePolicyError, FileStorageError
from aegishunt.ingestion.file_storage import SafeFileStorage
from aegishunt.ingestion.pcap import PcapIngestor


def storage_for(root: Path, *, max_bytes: int = 32) -> SafeFileStorage:
    return SafeFileStorage(root, max_bytes=max_bytes, chunk_size=4)


@pytest.mark.parametrize("filename", ["", "../capture.pcap", "folder/capture.pcap", "x.txt"])
def test_storage_rejects_unsafe_or_unsupported_names(tmp_path: Path, filename: str) -> None:
    with pytest.raises(FilePolicyError):
        storage_for(tmp_path).stage(
            BytesIO(b"payload"),
            filename=filename,
            content_type="application/vnd.tcpdump.pcap",
            policy=PcapIngestor.policy,
        )


def test_storage_enforces_size_and_removes_staging_file(tmp_path: Path) -> None:
    with pytest.raises(FilePolicyError, match="limit"):
        storage_for(tmp_path, max_bytes=4).stage(
            BytesIO(b"12345"),
            filename="capture.pcap",
            content_type="application/vnd.tcpdump.pcap",
            policy=PcapIngestor.policy,
        )
    assert list(tmp_path.iterdir()) == []


def test_storage_hashes_atomically_and_deduplicates(tmp_path: Path) -> None:
    storage = storage_for(tmp_path)
    first = storage.stage(
        BytesIO(b"same-content"),
        filename="first.pcap",
        content_type="application/vnd.tcpdump.pcap; charset=binary",
        policy=PcapIngestor.policy,
    )
    first_stored = storage.commit(first)
    second = storage.stage(
        BytesIO(b"same-content"),
        filename="second.pcap",
        content_type="application/octet-stream",
        policy=PcapIngestor.policy,
    )
    second_stored = storage.commit(second)

    assert first_stored == second_stored
    assert (tmp_path / first_stored.stored_filename).read_bytes() == b"same-content"
    assert len(list(tmp_path.iterdir())) == 1


def test_storage_rejects_corrupt_existing_checksum_file(tmp_path: Path) -> None:
    storage = storage_for(tmp_path)
    staged = storage.stage(
        BytesIO(b"trusted-bytes"),
        filename="capture.pcap",
        content_type="application/octet-stream",
        policy=PcapIngestor.policy,
    )
    final_path = tmp_path / f"{staged.checksum}.pcap"
    final_path.write_bytes(b"X" * staged.byte_size)

    with pytest.raises(FileStorageError, match="integrity"):
        storage.commit(staged)

    assert final_path.read_bytes() == b"X" * staged.byte_size
    assert not Path(staged.path).exists()
