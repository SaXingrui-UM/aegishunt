"""Generic typed repository mechanics shared by core entities."""

from __future__ import annotations

from typing import Generic, TypeVar
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from aegishunt.schemas.base import CoreSchema
from aegishunt.storage.base import Base
from aegishunt.storage.repositories.audit import AuditLogRepository

SchemaT = TypeVar("SchemaT", bound=CoreSchema)
RecordT = TypeVar("RecordT", bound=Base)


class SqlAlchemyRepository(Generic[SchemaT, RecordT]):
    """CRUD foundation that keeps SQLAlchemy out of application services."""

    def __init__(
        self,
        session: Session,
        *,
        schema_type: type[SchemaT],
        record_type: type[RecordT],
        id_attribute: str,
        audit_log: AuditLogRepository | None = None,
    ) -> None:
        self._session = session
        self._schema_type = schema_type
        self._record_type = record_type
        self._id_attribute = id_attribute
        self._audit_log = audit_log

    def add(self, entity: SchemaT, *, actor: str = "system") -> SchemaT:
        """Add one validated entity and audit it in the same transaction."""

        row = self._record_type(**entity.model_dump(mode="python"))
        self._session.add(row)
        self._session.flush()
        identifier = str(getattr(row, self._id_attribute))
        if self._audit_log is not None:
            self._audit_log.record(
                actor=actor,
                action="create",
                object_type=self._record_type.__tablename__,
                object_id=identifier,
            )
        return self._schema_type.model_validate(row)

    def get(self, identifier: UUID) -> SchemaT | None:
        """Return one entity by primary key without raising on absence."""

        row = self._session.get(self._record_type, identifier)
        return None if row is None else self._schema_type.model_validate(row)

    def list(self) -> list[SchemaT]:
        """Return entities in stable primary-key order."""

        id_column = getattr(self._record_type, self._id_attribute)
        rows = self._session.scalars(select(self._record_type).order_by(id_column)).all()
        return [self._schema_type.model_validate(row) for row in rows]
