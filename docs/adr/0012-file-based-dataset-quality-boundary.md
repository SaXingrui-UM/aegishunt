# ADR 0012: File-based dataset quality boundary

- Status: Accepted

## Context

Phase 4 must evaluate public sources, preserve provenance, transform rows into
the Phase 3 feature contract, prevent leakage, and freeze group-aware splits.
Public captures are too large and license-sensitive to commit, and a database
migration would add no integrity beyond immutable manifests at this phase.

## Decision

Use a typed file-based dataset subsystem under configured raw, interim,
processed, and report roots. Static provider/license definitions live in a
versioned YAML registry; machine-local acquisition state is a separate schema.
Canonical rows seal metadata, ordered features, and labels into distinct strict
sections. Only the Phase 3 feature tuple is model-eligible.

Select CSE-CIC-IDS2018 as the conditional primary public benchmark, with manual
acquisition and provisional conversion until raw checksums and label joins are
audited. Keep an offline controlled demo that uses the Phase 3 feature engine to
exercise the pipeline without claiming benchmark or operational validity.

Split by whole `group_id` using a deterministic seeded hash. Reject source-file,
capture-session, or scenario identities shared by different groups and never
fall back to row-level random splitting. Run quality and leakage gates before
writing a passing manifest. Test is frozen for later one-time evaluation.

Downloads do not accept licenses. Reuse requires checksum verification;
archives enforce destination roots, safe member paths, regular files, member
count, and expanded-byte limits.

## Alternatives considered

- Persist datasets and splits in SQLite: rejected because large tables and raw
  artifacts belong outside the transactional operational database.
- Reuse provider flow columns by name: rejected because similar names do not
  prove identical Phase 3 semantics.
- Random row split: rejected because related flows would cross partitions.
- Automatically download every benchmark: rejected for size, terms, checksum,
  and reproducibility reasons.
- Fabricate missing public features or labels: rejected as research-invalid.

## Consequences

Phase 4 is reproducible offline and does not change schema version `1` or the
Phase 3 feature schema. Manifests/checksums make each materialized dataset
auditable. Public benchmark readiness remains conditional until an operator
performs the documented acquisition and label-join validation.

## Risks

- File manifests rely on disciplined immutable storage outside Git.
- Provider labels and local flow timeouts may not join cleanly.
- Group isolation may yield imperfect class coverage or balance.
- Large captures require explicit subsets and resource measurement.
- The controlled demo is structurally useful but cannot estimate real-world
  performance.
