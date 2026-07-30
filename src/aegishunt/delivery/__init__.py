"""Final-delivery artifact contracts for the local research prototype."""

from aegishunt.delivery.release_manifest import (
    RELEASE_MANIFEST_FILENAME,
    ReleaseManifestError,
    build_release_manifest,
    verify_release_bundle,
)

__all__ = [
    "RELEASE_MANIFEST_FILENAME",
    "ReleaseManifestError",
    "build_release_manifest",
    "verify_release_bundle",
]
