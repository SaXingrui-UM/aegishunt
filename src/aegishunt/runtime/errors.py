"""Explicit Phase 11 runtime failures."""

from aegishunt.errors import AegisHuntError


class RuntimeError(AegisHuntError):
    """Base runtime workflow failure."""


class RuntimeConfigurationError(RuntimeError):
    """Runtime policy is missing or invalid."""


class RuntimeStateError(RuntimeError):
    """A requested lifecycle transition is invalid."""


class RuntimeClaimError(RuntimeError):
    """A worker cannot claim or retain a job."""


class RuntimePreflightError(RuntimeError):
    """Pinned source or pipeline evidence failed verification."""


class RuntimeReplayError(RuntimeError):
    """Offline replay could not safely continue."""


class ReplayInterrupted(RuntimeReplayError):
    """Cooperative shutdown stopped replay before an unsafe partial flush."""


class RuntimePersistenceError(RuntimeError):
    """A transactional output batch failed closed."""
