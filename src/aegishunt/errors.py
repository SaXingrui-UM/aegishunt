"""Explicit exception hierarchy for expected AegisHunt failures."""


class AegisHuntError(Exception):
    """Base class for failures safe to present to an operator."""


class ConfigurationError(AegisHuntError):
    """Raised when configuration cannot be loaded or validated."""


class DatabaseError(AegisHuntError):
    """Raised when database setup or access cannot be completed safely."""


class DatabaseInitializationError(DatabaseError):
    """Raised when the database schema cannot be initialized."""


class SchemaVersionError(DatabaseError):
    """Raised when the on-disk schema is incompatible with this application."""


class RepositoryRecordNotFoundError(DatabaseError):
    """Raised when an update targets a record that no longer exists."""
