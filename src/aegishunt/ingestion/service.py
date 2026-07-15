"""Application service for safe telemetry ingestion job lifecycles."""

from __future__ import annotations

from pathlib import Path
from typing import BinaryIO
from uuid import UUID

from aegishunt.config import FlowSettings, IngestionSettings
from aegishunt.flows.errors import FlowProcessingError
from aegishunt.flows.registry import FEATURE_SCHEMA_VERSION
from aegishunt.flows.service import PcapFlowProcessor
from aegishunt.ingestion.base import IngestorRegistry
from aegishunt.ingestion.errors import (
    FileStorageError,
    IngestionError,
    IngestionJobFailedError,
    IngestionJobNotFoundError,
    TelemetryFormatError,
)
from aegishunt.ingestion.file_storage import SafeFileStorage
from aegishunt.ingestion.flow_csv import FlowCsvIngestor
from aegishunt.ingestion.json_events import JsonEventIngestor
from aegishunt.ingestion.pcap import PcapIngestor
from aegishunt.ingestion.samples import SampleDataRegistry
from aegishunt.ingestion.schemas import (
    IngestionJob,
    IngestionJobPage,
    SampleDescriptor,
    StagedFile,
)
from aegishunt.schemas.base import JsonObject, utc_now
from aegishunt.schemas.enums import IngestionMode, LifecycleStatus, SourceType
from aegishunt.schemas.telemetry import NetworkFlow, TelemetrySource
from aegishunt.storage import Database
from aegishunt.storage.repositories import (
    AuditLogRepository,
    NetworkFlowRepository,
    TelemetrySourceRepository,
)


def default_registry() -> IngestorRegistry:
    """Build the Phase 2 file-ingestor registry."""

    return IngestorRegistry((PcapIngestor(), FlowCsvIngestor(), JsonEventIngestor()))


def _updated(source: TelemetrySource, **changes: object) -> TelemetrySource:
    payload = source.model_dump(mode="python")
    payload.update(changes)
    return TelemetrySource.model_validate(payload)


class IngestionService:
    """Coordinate safe storage, bounded validation, persistence, and audit."""

    def __init__(
        self,
        database: Database,
        settings: IngestionSettings,
        *,
        flow_settings: FlowSettings | None = None,
        registry: IngestorRegistry | None = None,
    ) -> None:
        self._database = database
        self._settings = settings
        self._flow_settings = flow_settings or FlowSettings()
        self._registry = registry or default_registry()
        self._storage = SafeFileStorage(
            settings.storage_root,
            max_bytes=settings.max_upload_bytes,
            chunk_size=settings.chunk_size_bytes,
        )
        self._samples = SampleDataRegistry(settings.sample_root)
        self._pcap_flows = PcapFlowProcessor(
            self._flow_settings,
            max_records=settings.max_records,
        )

    def _add(self, source: TelemetrySource, *, actor: str) -> TelemetrySource:
        with self._database.session() as session, session.begin():
            audit = AuditLogRepository(session)
            return TelemetrySourceRepository(session, audit).add(source, actor=actor)

    def _update(self, source: TelemetrySource, *, actor: str) -> TelemetrySource:
        with self._database.session() as session, session.begin():
            audit = AuditLogRepository(session)
            return TelemetrySourceRepository(session, audit).update(source, actor=actor)

    def _complete(
        self,
        source: TelemetrySource,
        flows: tuple[NetworkFlow, ...],
        *,
        actor: str,
    ) -> TelemetrySource:
        """Commit all derived flows and the completed source in one transaction."""

        with self._database.session() as session, session.begin():
            audit = AuditLogRepository(session)
            flow_repository = NetworkFlowRepository(session, audit)
            for flow in flows:
                flow_repository.add(flow, actor=actor)
            return TelemetrySourceRepository(session, audit).update(source, actor=actor)

    def _mark_failed(
        self,
        source: TelemetrySource,
        error: IngestionError,
        *,
        actor: str,
    ) -> IngestionJob:
        metadata: JsonObject = {
            **source.source_metadata,
            "error_code": error.code,
            "error_message": str(error),
        }
        failed = _updated(
            source,
            status=LifecycleStatus.FAILED,
            completed_at=utc_now(),
            source_metadata=metadata,
        )
        return IngestionJob.from_source(self._update(failed, actor=actor))

    def ingest_stream(
        self,
        stream: BinaryIO,
        *,
        filename: str,
        content_type: str | None,
        source_type: SourceType,
        actor: str = "operator",
        recorded_source_type: SourceType | None = None,
        extra_metadata: JsonObject | None = None,
    ) -> IngestionJob:
        """Run one synchronous, durable file-ingestion job."""

        ingestor = self._registry.get(source_type)
        SafeFileStorage.validate_filename(filename, ingestor.policy)
        normalized_content_type = SafeFileStorage.validate_content_type(
            content_type, ingestor.policy
        )
        metadata: JsonObject = {
            "progress": 0.0,
            "content_type": normalized_content_type,
            **(extra_metadata or {}),
        }
        source = self._add(
            TelemetrySource(
                source_type=recorded_source_type or source_type,
                filename_or_interface=filename,
                ingestion_mode=IngestionMode.IMPORT,
                source_metadata=metadata,
            ),
            actor=actor,
        )
        source = self._update(
            _updated(
                source,
                status=LifecycleStatus.RUNNING,
                started_at=utc_now(),
                source_metadata={**source.source_metadata, "progress": 0.1},
            ),
            actor=actor,
        )
        staged: StagedFile | None = None
        try:
            staged = self._storage.stage(
                stream,
                filename=filename,
                content_type=normalized_content_type,
                policy=ingestor.policy,
            )
            source = self._update(
                _updated(
                    source,
                    checksum=staged.checksum,
                    source_metadata={
                        **source.source_metadata,
                        "progress": 0.5,
                        "byte_size": staged.byte_size,
                    },
                ),
                actor=actor,
            )
            inspection = ingestor.inspect(
                Path(staged.path),
                max_records=self._settings.max_records,
            )
            flow_metadata: JsonObject = {}
            flows: tuple[NetworkFlow, ...] = ()
            if source_type is SourceType.PCAP:
                flow_result = self._pcap_flows.process(
                    Path(staged.path),
                    source_id=source.source_id,
                    capture_session_id=f"pcap:{source.source_id}",
                )
                if flow_result.captured_packets != inspection.records_processed:
                    raise FlowProcessingError(
                        "packet decoding count does not match validated capture framing"
                    )
                flows = flow_result.flows
                flow_metadata = {
                    "flow_count": len(flows),
                    "decoded_packet_count": flow_result.decoded_packets,
                    "skipped_packet_count": flow_result.skipped_packets,
                    "feature_schema_version": FEATURE_SCHEMA_VERSION,
                }
            stored = self._storage.commit(staged)
            staged = None
            completed = _updated(
                source,
                status=LifecycleStatus.COMPLETED,
                completed_at=utc_now(),
                records_processed=inspection.records_processed,
                checksum=stored.checksum,
                source_metadata={
                    **source.source_metadata,
                    "progress": 1.0,
                    "stored_filename": stored.stored_filename,
                    "byte_size": stored.byte_size,
                    "format_metadata": {**inspection.metadata, **flow_metadata},
                },
            )
            return IngestionJob.from_source(self._complete(completed, flows, actor=actor))
        except IngestionError as exc:
            failed_job = self._mark_failed(source, exc, actor=actor)
            raise IngestionJobFailedError(failed_job.job_id, exc) from exc
        except FlowProcessingError as exc:
            safe_error = TelemetryFormatError(str(exc))
            failed_job = self._mark_failed(source, safe_error, actor=actor)
            raise IngestionJobFailedError(failed_job.job_id, safe_error) from exc
        finally:
            self._storage.discard(staged)

    def ingest_path(
        self,
        path: Path,
        *,
        source_type: SourceType,
        content_type: str | None = None,
        actor: str = "cli",
    ) -> IngestionJob:
        """Import an explicitly supplied local path for the CLI."""

        try:
            with path.expanduser().open("rb") as stream:
                return self.ingest_stream(
                    stream,
                    filename=path.name,
                    content_type=content_type,
                    source_type=source_type,
                    actor=actor,
                )
        except OSError as exc:
            raise FileStorageError("unable to open the selected telemetry file") from exc

    def ingest_sample(self, sample_id: str, *, actor: str = "operator") -> IngestionJob:
        """Ingest one checksum-verified, allowlisted demonstration sample."""

        resolved = self._samples.resolve(sample_id)
        try:
            with resolved.path.open("rb") as stream:
                return self.ingest_stream(
                    stream,
                    filename=resolved.descriptor.filename,
                    content_type=resolved.descriptor.content_type,
                    source_type=resolved.descriptor.source_type,
                    recorded_source_type=SourceType.SAMPLE,
                    extra_metadata={
                        "sample_id": resolved.descriptor.sample_id,
                        "validated_source_type": resolved.descriptor.source_type.value,
                        "synthetic": resolved.descriptor.synthetic,
                    },
                    actor=actor,
                )
        except OSError as exc:
            raise FileStorageError("unable to open the verified sample file") from exc

    def list_samples(self) -> list[SampleDescriptor]:
        """Return reviewed sample descriptors."""

        return self._samples.list()

    def get_job(self, job_id: UUID) -> IngestionJob:
        """Return a durable job or an explicit not-found error."""

        with self._database.session() as session:
            source = TelemetrySourceRepository(session).get(job_id)
        if source is None:
            raise IngestionJobNotFoundError("ingestion job was not found")
        return IngestionJob.from_source(source)

    def list_jobs(self, *, limit: int, offset: int) -> IngestionJobPage:
        """Return a validated page of durable jobs."""

        with self._database.session() as session:
            sources, total = TelemetrySourceRepository(session).list_page(
                limit=limit,
                offset=offset,
            )
        return IngestionJobPage(
            items=[IngestionJob.from_source(source) for source in sources],
            total=total,
            limit=limit,
            offset=offset,
        )
