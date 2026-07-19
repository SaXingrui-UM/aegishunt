"""Non-overwriting experiment evidence and exact-inventory policy storage."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ValidationError

from aegishunt.ml.fusion.config import FusionExperimentConfig
from aegishunt.ml.fusion.contracts import (
    CandidateEvaluation,
    ComparisonResult,
    PolicyChecksums,
    PolicyManifest,
)
from aegishunt.ml.fusion.dataset import ControlledExperimentDataset
from aegishunt.ml.fusion.errors import FusionArtifactError
from aegishunt.ml.fusion.experiments import FusionExperimentRun

POLICY_MANIFEST_FILENAME = "fusion_policy_manifest.json"
POLICY_CHECKSUMS_FILENAME = "fusion_policy_checksums.json"
POLICY_CARD_FILENAME = "fusion_policy_card.md"
_POLICY_FILES = frozenset(
    {POLICY_MANIFEST_FILENAME, POLICY_CHECKSUMS_FILENAME, POLICY_CARD_FILENAME}
)


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path) -> str:
    try:
        return sha256_bytes(path.read_bytes())
    except OSError as exc:
        raise FusionArtifactError("unable to hash fusion evidence") from exc


@dataclass(frozen=True, slots=True)
class FusionExperimentStore:
    """One exclusive generated experiment directory."""

    directory: Path

    @classmethod
    def create(cls, root: Path, experiment_id: str) -> FusionExperimentStore:
        directory = root / experiment_id
        try:
            directory.mkdir(parents=True, exist_ok=False, mode=0o750)
        except FileExistsError as exc:
            raise FusionArtifactError("fusion experiment already exists") from exc
        except OSError as exc:
            raise FusionArtifactError("unable to create fusion experiment directory") from exc
        return cls(directory)

    def path(self, filename: str) -> Path:
        candidate = Path(filename)
        if candidate.is_absolute() or len(candidate.parts) != 1 or ".." in candidate.parts:
            raise FusionArtifactError("fusion artifact filename is unsafe")
        return self.directory / candidate

    def write_bytes(self, filename: str, payload: bytes) -> Path:
        path = self.path(filename)
        try:
            with path.open("xb") as destination:
                destination.write(payload)
        except FileExistsError as exc:
            raise FusionArtifactError("fusion artifact already exists") from exc
        except OSError as exc:
            raise FusionArtifactError("unable to write fusion artifact") from exc
        return path

    def write_text(self, filename: str, payload: str) -> Path:
        return self.write_bytes(filename, payload.encode())

    def write_json(self, filename: str, payload: BaseModel | dict[str, Any] | list[Any]) -> Path:
        content = (
            payload.model_dump(mode="json") if isinstance(payload, BaseModel) else payload
        )
        serialized = json.dumps(content, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        return self.write_text(filename, serialized)

    def write_csv(self, filename: str, rows: list[dict[str, object]]) -> Path:
        if not rows:
            raise FusionArtifactError("fusion CSV evidence cannot be empty")
        fieldnames = tuple(rows[0])
        if any(tuple(row) != fieldnames for row in rows):
            raise FusionArtifactError("fusion CSV evidence columns are inconsistent")
        buffer = io.StringIO(newline="")
        writer = csv.DictWriter(buffer, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
        return self.write_text(filename, buffer.getvalue())


def _metric_row(
    result: ComparisonResult,
    candidate: CandidateEvaluation,
) -> dict[str, object]:
    metrics = candidate.metrics
    return {
        "experiment_kind": result.experiment_kind,
        "scenario_id": result.scenario_id,
        "held_out_family": result.held_out_family or "",
        "shift_axis": result.shift_axis or "",
        "mode": candidate.mode,
        "row_count": result.row_count,
        "group_count": len(result.groups),
        "threshold": candidate.threshold,
        "accuracy": metrics.accuracy,
        "precision": metrics.precision,
        "recall": metrics.recall,
        "f1": metrics.f1,
        "macro_f1": metrics.macro_f1,
        "weighted_f1": metrics.weighted_f1,
        "balanced_accuracy": metrics.balanced_accuracy,
        "mcc": metrics.mcc,
        "roc_auc": metrics.roc_auc if metrics.roc_auc is not None else "",
        "pr_auc": metrics.pr_auc if metrics.pr_auc is not None else "",
        "specificity": metrics.specificity,
        "false_positive_rate": metrics.benign_false_positive_rate,
        "false_negative_rate": metrics.anomaly_false_negative_rate,
        "tn": metrics.confusion_matrix[0][0],
        "fp": metrics.confusion_matrix[0][1],
        "fn": metrics.confusion_matrix[1][0],
        "tp": metrics.confusion_matrix[1][1],
        "fpr_ceiling_satisfied": candidate.satisfies_fpr_ceiling,
    }


def _comparison_rows(results: tuple[ComparisonResult, ...]) -> list[dict[str, object]]:
    return [
        _metric_row(result, candidate)
        for result in results
        for candidate in (result.supervised, result.anomaly, result.fusion)
    ]


def _delta_rows(results: tuple[ComparisonResult, ...]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for result in results:
        for baseline, deltas in (
            ("supervised_only", result.fusion_minus_supervised),
            ("anomaly_only", result.fusion_minus_anomaly),
        ):
            rows.append(
                {
                    "experiment_kind": result.experiment_kind,
                    "scenario_id": result.scenario_id,
                    "baseline": baseline,
                    **deltas,
                }
            )
    return rows


def write_experiment_evidence(
    root: Path,
    *,
    config: FusionExperimentConfig,
    dataset: ControlledExperimentDataset,
    run: FusionExperimentRun,
) -> FusionExperimentStore:
    """Write source-backed evidence needed before the final policy manifest."""

    store = FusionExperimentStore.create(root, config.experiment_id)
    store.write_json("phase_07_experiment_protocol.json", config)
    store.write_json("phase_07_dataset_manifest.json", dataset.manifest)
    store.write_json("phase_07_split_manifest.json", dataset.split_manifest)
    store.write_json("fusion_config.json", config)
    store.write_json("fusion_selection.json", run.selection)
    candidate_rows: list[dict[str, object]] = [
        {
            "candidate_id": candidate.candidate_id,
            "supervised_weight": (
                candidate.weights.supervised_weight if candidate.weights is not None else ""
            ),
            "anomaly_weight": (
                candidate.weights.anomaly_weight if candidate.weights is not None else ""
            ),
            "threshold": candidate.threshold,
            "macro_f1": candidate.metrics.macro_f1,
            "recall": candidate.metrics.recall,
            "pr_auc": (
                candidate.metrics.pr_auc if candidate.metrics.pr_auc is not None else ""
            ),
            "false_positive_rate": candidate.metrics.benign_false_positive_rate,
            "satisfies_fpr_ceiling": candidate.satisfies_fpr_ceiling,
            "selected": candidate.candidate_id == run.selection.selected_candidate_id,
        }
        for candidate in run.selection.candidates
    ]
    store.write_csv("fusion_weight_results.csv", candidate_rows)
    store.write_csv("fusion_threshold_results.csv", candidate_rows)
    known_rows = _comparison_rows((run.known,))
    unseen_rows = _comparison_rows(run.leave_one_family_out)
    temporal_rows = _comparison_rows((run.temporal,))
    shift_rows = _comparison_rows(run.parameter_shifts)
    store.write_csv("known_attack_metrics.csv", known_rows)
    store.write_csv("unseen_attack_metrics.csv", unseen_rows)
    store.write_csv("leave_one_family_out.csv", unseen_rows)
    store.write_csv("temporal_holdout.csv", temporal_rows)
    store.write_csv("parameter_shift.csv", shift_rows)
    all_results = (
        run.known,
        *run.leave_one_family_out,
        run.temporal,
        *run.parameter_shifts,
    )
    store.write_csv("fusion_comparison.csv", _comparison_rows(all_results))
    store.write_csv("metric_deltas.csv", _delta_rows(all_results))
    store.write_json(
        "confidence_intervals.json",
        [
            {
                "experiment_kind": result.experiment_kind,
                "scenario_id": result.scenario_id,
                "metric_intervals": {
                    name: interval.model_dump(mode="json")
                    for name, interval in result.confidence_intervals.items()
                },
                "delta_intervals": {
                    name: interval.model_dump(mode="json")
                    for name, interval in result.delta_confidence_intervals.items()
                },
            }
            for result in all_results
        ],
    )
    return store


def write_final_experiment_evidence(
    store: FusionExperimentStore,
    *,
    run: FusionExperimentRun,
    policy_artifact_size_bytes: int,
) -> None:
    latency: dict[str, object] = {
        **run.latency,
        "fusion_policy_artifact_size_bytes": policy_artifact_size_bytes,
    }
    store.write_csv("latency_results.csv", [latency])
    known = run.known
    summary = "\n".join(
        (
            "# Phase 7 Controlled Fusion Experiment Summary",
            "",
            "Controlled synthetic pipeline verification only; not a public benchmark.",
            "Fusion score is not probability, risk, severity, or attack confirmation.",
            "",
            f"- Recommendation: `{run.selection.recommendation_status}`",
            f"- Selected candidate: `{run.selection.selected_candidate_id}`",
            f"- Known supervised Macro F1: `{known.supervised.metrics.macro_f1:.6f}`",
            f"- Known anomaly Macro F1: `{known.anomaly.metrics.macro_f1:.6f}`",
            f"- Known fusion Macro F1: `{known.fusion.metrics.macro_f1:.6f}`",
            f"- LOAO families evaluated: `{len(run.leave_one_family_out)}`",
            "- Negative and inconclusive results are retained without additional search.",
            "",
        )
    )
    store.write_text("experiment_summary.md", summary)


def _within(path: Path, root: Path) -> Path:
    resolved_root = root.resolve()
    resolved = path.resolve()
    if not resolved.is_relative_to(resolved_root):
        raise FusionArtifactError("fusion policy path is outside configured storage")
    return resolved


def save_policy(root: Path, manifest: PolicyManifest, policy_card: str) -> Path:
    """Atomically save one JSON-only policy and reject every version collision."""

    try:
        root.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise FusionArtifactError("fusion policy storage is unavailable") from exc
    destination = root / manifest.policy_version
    if destination.exists() or destination.is_symlink():
        raise FusionArtifactError("fusion policy version already exists")
    temporary = root / f".{manifest.policy_version}.tmp-{os.getpid()}"
    if temporary.exists():
        raise FusionArtifactError("fusion policy staging path already exists")
    try:
        temporary.mkdir(mode=0o750)
        manifest_payload = (
            json.dumps(
                manifest.model_dump(mode="json"),
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
            )
            + "\n"
        ).encode()
        card_payload = policy_card.encode()
        checksums = PolicyChecksums(
            checksum_schema_version="1.0.0",
            manifest_checksum=sha256_bytes(manifest_payload),
            policy_card_checksum=sha256_bytes(card_payload),
        )
        (temporary / POLICY_MANIFEST_FILENAME).write_bytes(manifest_payload)
        (temporary / POLICY_CARD_FILENAME).write_bytes(card_payload)
        (temporary / POLICY_CHECKSUMS_FILENAME).write_text(
            checksums.model_dump_json(indent=2) + "\n", encoding="utf-8"
        )
        temporary.rename(destination)
    except (OSError, FusionArtifactError) as exc:
        for child in temporary.iterdir() if temporary.exists() else ():
            child.unlink(missing_ok=True)
        temporary.rmdir() if temporary.exists() else None
        if isinstance(exc, FusionArtifactError):
            raise
        raise FusionArtifactError("unable to save fusion policy") from exc
    return destination


def load_policy(policy_dir: Path, *, root: Path) -> PolicyManifest:
    """Verify exact inventory and checksums before loading policy JSON."""

    resolved = _within(policy_dir, root)
    if resolved.suffix in {".pkl", ".pickle", ".joblib", ".skops"} or not resolved.is_dir():
        raise FusionArtifactError("fusion policy must be a system-generated directory")
    if {path.name for path in resolved.iterdir()} != _POLICY_FILES:
        raise FusionArtifactError("fusion policy file inventory is invalid")
    try:
        manifest_payload = (resolved / POLICY_MANIFEST_FILENAME).read_bytes()
        card_payload = (resolved / POLICY_CARD_FILENAME).read_bytes()
        checksums = PolicyChecksums.model_validate_json(
            (resolved / POLICY_CHECKSUMS_FILENAME).read_text(encoding="utf-8")
        )
        if checksums.manifest_checksum != sha256_bytes(manifest_payload):
            raise FusionArtifactError("fusion policy manifest checksum failed")
        if checksums.policy_card_checksum != sha256_bytes(card_payload):
            raise FusionArtifactError("fusion policy card checksum failed")
        manifest = PolicyManifest.model_validate_json(manifest_payload)
    except FusionArtifactError:
        raise
    except (OSError, ValidationError) as exc:
        raise FusionArtifactError("fusion policy is invalid") from exc
    if resolved.name != manifest.policy_version:
        raise FusionArtifactError("fusion policy directory differs from its version")
    return manifest


def policy_size_bytes(policy_dir: Path) -> int:
    try:
        return sum(path.stat().st_size for path in policy_dir.iterdir())
    except OSError as exc:
        raise FusionArtifactError("unable to measure fusion policy artifact") from exc
