"""Explicit failures for dataset acquisition and quality workflows."""

from aegishunt.errors import AegisHuntError


class DatasetError(AegisHuntError):
    """Base class for operator-safe Phase 4 failures."""


class DatasetRegistryError(DatasetError):
    """A dataset definition or registry document is invalid."""


class DatasetNotFoundError(DatasetError):
    """A stable dataset identifier is not registered."""


class DatasetAcquisitionError(DatasetError):
    """A dataset cannot be safely acquired or verified."""


class ManualDownloadRequiredError(DatasetAcquisitionError):
    """The provider requires an operator-controlled download step."""


class DatasetConversionError(DatasetError):
    """Raw data cannot be represented by the canonical contract."""


class DatasetQualityError(DatasetError):
    """Dataset quality or leakage gates reject the data."""


class DatasetSplitError(DatasetError):
    """Group-exclusive train/validation/test splitting cannot proceed."""
