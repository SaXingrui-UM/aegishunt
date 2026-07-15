"""Explicit failures for bounded packet and flow processing."""

from aegishunt.errors import AegisHuntError


class FlowProcessingError(AegisHuntError):
    """Base class for safe packet-to-flow failures."""


class CaptureFormatError(FlowProcessingError):
    """Raised when an accepted capture cannot be decoded safely."""


class PacketParseError(FlowProcessingError):
    """Raised when a captured packet is structurally malformed or truncated."""


class FlowStateError(FlowProcessingError):
    """Raised when a packet violates an active flow-state invariant."""


class FlowLimitError(FlowProcessingError):
    """Raised when configured flow memory bounds would be exceeded."""


class FeatureCalculationError(FlowProcessingError):
    """Raised when a feature vector violates the declared schema."""
