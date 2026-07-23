# Retraining Candidate Dataset Contract

## Status

Phase 10 can explicitly build a `retraining_candidate` data-only artifact. It is not
approved, training-ready, final, benchmark, production, or activated data. The command
does not import training services, fit a model, change an active model, modify a
threshold, or alter historical evidence. Manual review, Phase 4-equivalent quality
checks, and a new group-aware split are required before any separately authorized
training task.

## Row eligibility

Only alert-level feedback that uniquely resolves
`SecurityAlert → DetectionResult → NetworkFlow` can create a row. The flow must contain
the complete finite Phase 3 feature vector in registry order. Label mapping `1.0.0` is:

| Analyst verdict | Candidate label |
| --- | --- |
| `true_positive` | `malicious` |
| `false_positive` | `benign` |
| `benign_expected` | `benign` |
| `needs_more_information` | excluded |

Case-level feedback is exportable but never propagated to all related flows. Low
confidence, missing objects, incomplete features, and unknown provenance fail closed
with an explicit exclusion reason.

Each eligible source must explicitly record provenance partition/type, dataset
ID/version, capture session, scenario, and group. Allowed partitions/types are
configured. Test, frozen-test, evaluation, holdout, benchmark-test, LOAO, temporal or
parameter-shift evaluation, independent holdout, corrective frozen-test, and all
unknown provenance are excluded. This preserves historical evaluation isolation rather
than trying to maximize candidate count.

## Conflicts and deduplication

Consistent judgments mapping to the same flow create one row with all sorted supporting
feedback IDs. Configured confidence aggregation is the minimum—no value is fabricated.
If malicious and benign judgments map to the same flow, the flow is excluded and
reported in `conflicts.json`; there is no latest-wins or higher-confidence-wins rule.

Candidate IDs are deterministic from flow identity, label mapping, and feature schema.
Metadata (source/detection/alert/feedback IDs and provenance) is separate from the
feature tuple. Actor, notes, filenames, paths, attack family, ground-truth label, and
identifiers are never model features.

## Artifact contract

The exact inventory is:

- `candidates.jsonl`
- `candidate_manifest.json`
- `candidate_schema.json`
- `exclusions.json`
- `conflicts.json`
- `checksums.json`

The artifact is project-root-contained, atomic, non-overwriting, exact-inventory, and
SHA-256 verified. The manifest records `requires_manual_review` (or `empty` when no
eligible rows, or `insufficient_records` below the configured minimum), fixed
feature/label schema identities, all source feedback IDs, counts, Git/database
identity, and explicit no-training/no-activation requirements. Missing,
extra, corrupt, escaped, symlinked, or colliding artifacts are rejected.
