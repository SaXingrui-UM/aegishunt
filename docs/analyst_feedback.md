# Analyst Feedback Contract

## Trust boundary

`AnalystFeedback` reuses the Phase 1 entity and records an explicit human judgment for
a `SecurityAlert` or `InvestigationCase`. Feedback is potentially noisy, inconsistent,
and revisable. It is not verified ground truth, a benchmark label, production truth, or
permission to retrain. Every Phase 10 record retains actor, source, confidence, notes,
created/updated UTC time, object reference, schema version, provenance, and optional
Case association/correction reason.

Supported verdicts are `true_positive`, `false_positive`, `benign_expected`, and
`needs_more_information`. Confidence must be finite in `[0,1]`. Exact duplicate
identity/content is idempotent. Changing content requires an explicit update and
correction reason with a strictly later clock; history remains visible through audit.

## Alert consistency and transactions

The Phase 8 alert verdict remains the current alert-level value. Recording alert
feedback resolves the alert and, in one caller transaction, writes/updates feedback,
synchronizes the alert verdict, and appends audit events. A conflicting existing value
fails closed unless the user explicitly selects the update operation. Core alert
evidence, explanation, reason codes, score, identities, and timestamps other than the
verdict lifecycle update remain unchanged.

Case verdict workflow writes the Case judgment and corresponding Case feedback in one
transaction. A Case judgment never propagates to all member alerts or flows.

## Query and export

Feedback queries support stable ordering, get/list, bounded pagination, and typed
filters for object type/ID, verdict, actor, and UTC date range. Repositories construct
the query; callers cannot inject SQL.

The explicit export contains exactly:

- `feedback.jsonl`
- `manifest.json`
- `schema.json`
- `checksums.json`

The manifest records version/ID, filters, counts, source feedback IDs, schema/database
versions, Git identity when available, generation time, inventory, and limitations.
Records use deterministic creation-time/UUID ordering. The writer is atomic,
non-overwriting, project-root-contained, and rejects symlink roots, path escape,
missing/extra files, and checksum corruption. An export is still only a feedback data
artifact—not a training dataset.

## Control boundary

Creating, updating, querying, or exporting feedback never calls supervised/anomaly
training, changes thresholds/fusion, activates a model, replaces a bundle, or updates a
benign baseline. Any future retraining remains a separate user-authorized workflow with
a new immutable version and existing validation/frozen-test rules.
