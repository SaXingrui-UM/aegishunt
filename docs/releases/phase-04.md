# Phase 4: Dataset Registry, Transformation and Quality Control

## Objective

Provide evidence-based public dataset selection, safe acquisition boundaries,
an exact Phase 3 canonical conversion contract, versioned labels, a reproducible
offline demo, formal quality/leakage gates, group-exclusive frozen splits, and
machine-readable manifests without implementing any model.

## Implementation status

Implementation and local verification are complete on
`phase/04-dataset-quality`; the phase is awaiting final diff review, push, CI,
and pull-request review. It is not `Phase complete` until the PR is merged and a
later user-authorized checkpoint tag is created.

## Completed scope

- Strict versioned dataset registry with stable IDs, official source/license
  evidence, expected formats/files/checksums, schema/label/group contracts,
  acquisition and conversion states, limitations, citations, and timestamps.
- Static definitions separated from typed machine-local status and generated
  manifests.
- Conditional primary selection of CSE-CIC-IDS2018 based only on official
  evidence; manual acquisition and provisional label joining remain explicit.
- Bounded non-overwriting download and manual-file verification, SHA-256,
  sanitized failures, and traversal/bomb/symlink-resistant ZIP/TAR extraction.
- Strict canonical JSONL sections for provenance metadata, the unchanged 43-field
  Phase 3 feature vector, and versioned labels.
- Public provenance manifests retain raw filenames, checksums, and explicit
  source access dates; registry dataset/version/conversion gates fail closed.
- Exact feature-CSV adapter that refuses missing/reordered features, unknown
  labels, NaN, Infinity, invalid types/ranges, and unsafe source identifiers.
- Fixed-seed offline controlled demo covering browsing, DNS, file transfer,
  scanning, brute-force-like attempts, beaconing, asymmetric transfer, and
  restricted connection-flood behavior without traffic generation or targets.
- Missingness, exact/feature/provenance duplicates, conflicting labels,
  quantized near duplicates, class imbalance, constant/range, and finite-value
  reports.
- Formal group/source/session/scenario, exact/near duplicate, label-derived,
  metadata, filename, timestamp, ID, and correlation-risk leakage checks.
- Deterministic whole-group train/validation/test splitting with no row fallback,
  identity exclusivity, saved assignments, class/family distributions, and a
  frozen test policy.
- Required dataset/split manifests, quality/leakage JSON, class distribution CSV,
  and feature statistics CSV.
- Typer `dataset` commands for list, describe, download/manual verify, validate,
  convert, build-demo, quality, split, and manifest inspection.
- Output-free EDA notebook that calls tested library functions and clearly
  distinguishes controlled demo data from a public benchmark.

## Architecture decisions

ADR 0012 selects configured file roots and immutable manifests rather than a
database migration. Metadata/features/labels remain sealed sections, and only
the exact Phase 3 ordered tuple is model-eligible. Public feature columns are not
accepted by name alone. Quality and leakage gates run before a passing final
manifest is written. Group isolation takes precedence over class coverage.

## Benchmark dataset decision

CSE-CIC-IDS2018 is the conditional primary benchmark because its official page
provides raw PCAP, labels/scenario evidence, a reproducible AWS source, and an
explicit citation-based redistribution license. It is not locally downloaded or
approved for later model work: official file checksums are absent, the collection
is large, and the Phase 3 flow-to-schedule label join still requires operator
validation. CIC-IDS2017, UNSW-NB15, and TON_IoT remain documented alternatives.

## Controlled dataset quality results

The manual offline workflow with seed `4204` produced 48 rows across 24 groups:

- quality status: pass;
- leakage status: pass;
- binary distribution: 18 benign / 30 malicious;
- families: 18 benign plus 6 each for reconnaissance, brute force,
  command-and-control, exfiltration, and denial of service;
- exact, feature-only, conflicting-label, and near duplicates: zero;
- constant/all-zero features: `fin_count`, `urg_count`, reported but not removed;
- split rows: 28 train / 10 validation / 10 test;
- split groups: 14 train / 5 validation / 5 test;
- actual ratios: 58.33% / 20.83% / 20.83%;
- no group, source-file, capture-session, scenario, exact-duplicate, or
  near-duplicate overlap;
- test marked frozen; no model or threshold selection occurred.

These results describe only a controlled synthetic pipeline fixture and are not
classification metrics or operational-performance claims.

## Major files

- `src/aegishunt/datasets/`
- `configs/datasets/registry.yaml`
- `configs/label_mappings/`
- `docs/dataset_selection.md`
- `docs/dataset_schema.md`
- `docs/dataset_dictionary.md`
- `docs/adr/0012-file-based-dataset-quality-boundary.md`
- `notebooks/01_exploratory_analysis.ipynb`
- Phase 4 unit, security, integration, and E2E tests under `tests/`

## Tests

Pre-review local verification on 2026-07-16:

- `ruff check .`: pass.
- `mypy src`: pass across 73 source files.
- `pytest`: 168 passed, 0 failed, 0 skipped, 0 xfailed.
- Branch-aware coverage: 88.01% (project threshold: 85%).
- Focused Phase 4 registry/conversion/quality/leakage/split/download/workflow/CLI
  tests: 60 passed.
- Offline build, validate, quality, deterministic restart, group resplit,
  manifest validation, manual raw-file verification, and archive safety tests:
  pass.
- Two fixed-seed builds were byte-identical and produced canonical SHA-256
  `75c584dbee56cf985864fabeb3d01a0975122276a31c2acbb45b0323c4f885ad`.
- On this Codex/macOS host, the bundled Python marks virtual-environment `.pth`
  files hidden and its `site.py` skips them, so the standalone editable console
  script required `PYTHONPATH=src`. This environment-specific limitation was
  recorded as a workaround, not counted as a standard-install pass; direct
  imports, Typer CLI tests, and the full offline workflow passed.

The first read-only review found provenance, registry-gate, mapping-integrity,
strict-type, duplicate-ID, checksum, non-overwrite, and partial-output gaps.
Commit `9b0bdef` added the corresponding fail-closed guards and regression tests.

## Generated artifacts

Manual verification generated canonical/split JSONL and the six required reports
under a temporary ignored directory only. The reviewed canonical checksum was
`75c584dbee56cf985864fabeb3d01a0975122276a31c2acbb45b0323c4f885ad`.
All runtime datasets and machine reports are ignored and are not committed.

## Security considerations

- No tests or demo commands contact a public network, require root, capture a
  live interface, or identify an external target.
- No archive can write outside an explicit allowed root; absolute, traversal,
  symlink, non-regular, excessive-member, and excessive-expanded-size inputs fail.
- No command accepts a provider license for the user or prints a sensitive URL,
  local absolute path, traceback, label-derived feature, secret, or credential.
- Raw inputs are never overwritten and completed outputs use exclusive creation.

## Known limitations

- CSE-CIC-IDS2018 acquisition, local checksum inventory, Phase 3 extraction, and
  official schedule label join are not materialized; registry conversion status
  remains provisional.
- Provider archives without official hashes can only gain locally computed
  integrity evidence after manual acquisition.
- The generic CSV converter accepts only a complete exact Phase 3 export; it
  intentionally rejects CICFlowMeter/Argus/Zeek columns with missing semantics.
- Quantized near-duplicate detection is deterministic and configurable but is not
  a universal semantic similarity measure.
- Canonical quality and split analysis currently loads the selected rows into
  memory. Full public collections require an explicitly reviewed subset and
  resource measurement; Phase 4 does not claim whole-corpus laptop processing.
- Output names are preflighted and individual files use exclusive creation, but
  an unexpected I/O failure after a multi-file bundle starts can leave a partial
  bundle. Such a bundle lacks a complete manifest and must not be consumed.
- Controlled-demo manifests use the fixed generator epoch as their creation
  timestamp to preserve byte reproducibility; it is generation-contract
  metadata, not a wall-clock claim.
- Group isolation may leave a split without a rare family; no row split or
  resampling is used to force balance.
- The demo is small and synthetic and cannot measure real-world generalization.
- DEF-004 remains open and non-blocking: a total database outage cannot persist
  its own failure to that same database. Phase 4 introduces no alternate broker.
- The current Codex/macOS runtime skips hidden editable `.pth` files; standalone
  console-script verification required `PYTHONPATH=src`. This does not change
  the declared src-layout packaging but remains an environment-specific manual
  verification limitation.
- Dataset/model persistence in a model registry, training, hyperparameter tuning,
  classification metrics, anomaly detection, fusion, alerting, and hypotheses
  belong to later phases and are absent.

## Migration notes

No database or Phase 3 feature-schema migration is required. Existing schema
version `1` and feature schema `1.0.0` are unchanged. New configuration keys have
validated defaults.

## Version-control checkpoint

- Branch: `phase/04-dataset-quality`
- Baseline main: `21750914ab0da09a36b60972e6abdff5d565d454`
- Pull request: pending
- Merge commit: pending
- Completion tag: pending; must not be created before merge

## Next phase

Phase 5 — Supervised Detection is not started. It must consume only a reviewed,
quality-approved, group-exclusive manifest and must not begin before the Phase 4
PR is reviewed and merged and the user explicitly authorizes it.
