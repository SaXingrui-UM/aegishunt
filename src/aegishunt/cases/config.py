"""Strict checksummed Phase 10 case and feedback policy."""

from __future__ import annotations

import hashlib
from pathlib import Path, PurePosixPath
from typing import Literal, Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from aegishunt.cases.errors import CasePolicyError
from aegishunt.schemas.enums import AnalystVerdict, CasePriority, CaseStatus, Severity


class CaseFeedbackPolicy(BaseModel):
    """Complete policy: critical workflow rules never receive hidden defaults."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    policy_schema_version: Literal["1.0.0"]
    policy_id: str = Field(min_length=1, max_length=255)
    policy_version: str = Field(min_length=1, max_length=64)
    default_case_priority: CasePriority
    hypothesis_severity_to_priority: dict[Severity, CasePriority]
    allowed_case_status_transitions: dict[CaseStatus, tuple[CaseStatus, ...]]
    eligible_hypothesis_statuses: tuple[str, ...]
    final_verdicts: tuple[AnalystVerdict, ...]
    maximum_notes_per_case: int = Field(ge=1, le=10_000)
    maximum_note_length: int = Field(ge=1, le=100_000)
    maximum_evidence_references: int = Field(ge=1, le=10_000)
    maximum_reference_description_length: int = Field(ge=1, le=10_000)
    maximum_cases_per_query: int = Field(ge=1, le=10_000)
    maximum_feedback_per_query: int = Field(ge=1, le=10_000)
    feedback_confidence_minimum: float = Field(ge=0.0, le=1.0, allow_inf_nan=False)
    feedback_export_schema_version: Literal["1.0.0"]
    candidate_dataset_schema_version: Literal["1.0.0"]
    candidate_label_mapping_version: Literal["1.0.0"]
    candidate_dataset_minimum_records: int = Field(ge=1, le=1_000_000)
    excluded_provenance_partitions: tuple[str, ...]
    eligible_provenance_partitions: tuple[str, ...]
    eligible_provenance_types: tuple[str, ...]
    confidence_aggregation: Literal["minimum"]
    export_root: Path
    report_root: Path
    candidate_root: Path
    feedback_export_inventory: tuple[str, ...]
    candidate_dataset_inventory: tuple[str, ...]
    case_report_inventory: tuple[str, ...]

    @field_validator("export_root", "report_root", "candidate_root")
    @classmethod
    def validate_safe_relative_root(cls, value: Path) -> Path:
        posix = PurePosixPath(value.as_posix())
        if posix.is_absolute() or ".." in posix.parts or not posix.parts:
            raise ValueError("artifact roots must be safe project-relative paths")
        return value

    @model_validator(mode="after")
    def validate_complete_policy(self) -> Self:
        if set(self.hypothesis_severity_to_priority) != set(Severity):
            raise ValueError("severity-to-priority mapping must cover every severity")
        if set(self.allowed_case_status_transitions) != set(CaseStatus):
            raise ValueError("case transition policy must cover every status")
        if self.allowed_case_status_transitions[CaseStatus.CLOSED]:
            raise ValueError("closed cases are terminal")
        if set(self.final_verdicts) != {
            AnalystVerdict.TRUE_POSITIVE,
            AnalystVerdict.FALSE_POSITIVE,
            AnalystVerdict.BENIGN_EXPECTED,
        }:
            raise ValueError("final verdict policy is incomplete")
        lists = (
            self.eligible_hypothesis_statuses,
            self.excluded_provenance_partitions,
            self.eligible_provenance_partitions,
            self.eligible_provenance_types,
            self.feedback_export_inventory,
            self.candidate_dataset_inventory,
            self.case_report_inventory,
        )
        if any(not values or len(values) != len(set(values)) for values in lists):
            raise ValueError("policy lists must be non-empty and distinct")
        if set(self.excluded_provenance_partitions) & set(
            self.eligible_provenance_partitions
        ):
            raise ValueError("eligible and excluded provenance partitions overlap")
        return self


class LoadedCaseFeedbackPolicy(BaseModel):
    """Validated policy together with the checksum of its exact YAML bytes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    policy: CaseFeedbackPolicy
    configuration_checksum: str = Field(pattern=r"^[0-9a-f]{64}$")


def load_case_feedback_policy(path: Path) -> LoadedCaseFeedbackPolicy:
    """Load one strict local YAML policy without network access or fallback."""

    if not path.is_file() or path.is_symlink():
        raise CasePolicyError("case/feedback policy must be a regular local file")
    try:
        payload = path.read_bytes()
        raw = yaml.safe_load(payload)
        if not isinstance(raw, dict):
            raise CasePolicyError("case/feedback policy root must be a mapping")
        policy = CaseFeedbackPolicy.model_validate(raw)
    except CasePolicyError:
        raise
    except (OSError, UnicodeError, yaml.YAMLError, ValidationError) as exc:
        raise CasePolicyError("case/feedback policy could not be validated") from exc
    return LoadedCaseFeedbackPolicy(
        policy=policy,
        configuration_checksum=hashlib.sha256(payload).hexdigest(),
    )
