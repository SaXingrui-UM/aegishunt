"""Versioned label normalization with fail-closed unknown handling."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from aegishunt.datasets.errors import DatasetConversionError
from aegishunt.datasets.schemas import CanonicalLabels, LabelMappingDocument


class LabelMapper:
    """Normalize provider labels without inspecting feature values."""

    def __init__(self, document: LabelMappingDocument) -> None:
        self._document = document
        self._rules = {
            alias: rule
            for rule in document.rules
            for alias in rule.aliases
        }

    @property
    def version(self) -> str:
        return self._document.mapping_version

    @property
    def dataset_id(self) -> str:
        return self._document.dataset_id

    @classmethod
    def load(cls, path: Path) -> LabelMapper:
        try:
            payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise DatasetConversionError("unable to read label mapping") from exc
        except yaml.YAMLError as exc:
            raise DatasetConversionError("label mapping YAML is invalid") from exc
        try:
            document = LabelMappingDocument.model_validate(payload)
        except ValidationError as exc:
            errors = exc.errors(include_input=False, include_url=False)
            raise DatasetConversionError(f"label mapping validation failed: {errors}") from exc
        return cls(document)

    def map(self, original_label: str) -> CanonicalLabels:
        """Map a normalized alias or reject/mark the value under declared policy."""

        normalized = original_label.strip().casefold()
        rule = self._rules.get(normalized)
        if rule is None:
            if self._document.unknown_label_policy == "unmapped" and normalized:
                return CanonicalLabels(
                    ground_truth_label="unmapped",
                    binary_label=None,
                    attack_family="unmapped",
                    original_label=original_label,
                    label_mapping_version=self.version,
                )
            raise DatasetConversionError("raw row contains an unmapped label")
        return CanonicalLabels(
            ground_truth_label=rule.ground_truth_label,
            binary_label=rule.binary_label,
            attack_family=rule.attack_family,
            original_label=original_label,
            label_mapping_version=self.version,
        )
