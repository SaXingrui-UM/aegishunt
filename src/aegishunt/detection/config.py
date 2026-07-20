"""Safe loading for the versioned Phase 8 risk policy."""

from __future__ import annotations

import hashlib
from pathlib import Path

import yaml
from pydantic import ValidationError

from aegishunt.detection.contracts import LoadedRiskPolicy, RiskPolicy
from aegishunt.detection.errors import DetectionContractError


def load_risk_policy(path: Path) -> LoadedRiskPolicy:
    """Load one immutable YAML policy and bind it to its exact bytes."""

    if not path.is_file() or path.is_symlink():
        raise DetectionContractError("risk policy must be a regular file")
    try:
        payload_bytes = path.read_bytes()
        payload = yaml.safe_load(payload_bytes)
        if not isinstance(payload, dict):
            raise DetectionContractError("risk policy root must be a mapping")
        policy = RiskPolicy.model_validate(payload)
    except DetectionContractError:
        raise
    except (OSError, ValidationError, yaml.YAMLError) as exc:
        raise DetectionContractError("risk policy is invalid") from exc
    return LoadedRiskPolicy(
        policy=policy,
        configuration_checksum=hashlib.sha256(payload_bytes).hexdigest(),
    )
