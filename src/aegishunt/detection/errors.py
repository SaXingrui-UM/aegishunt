"""Explicit Phase 8 detection and alert failures."""

from aegishunt.errors import AegisHuntError


class DetectionContractError(AegisHuntError):
    """A score, identity, policy, or explanation violates the detection contract."""


class DetectionArtifactError(AegisHuntError):
    """A data-only explanation artifact is unsafe, corrupt, or incompatible."""


class DetectionPersistenceError(AegisHuntError):
    """A detection or alert transaction cannot be completed safely."""
