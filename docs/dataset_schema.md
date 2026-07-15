# Canonical Dataset Contract

Schema version: `1.0.0`

Feature schema: Phase 3 `1.0.0` (43 ordered features)

Conversion version: `1.0.0`

## Row boundary

Every JSON Lines row has exactly four top-level fields:

```json
{
  "canonical_schema_version": "1.0.0",
  "metadata": {},
  "features": {},
  "labels": {}
}
```

Strict Pydantic validation rejects unexpected fields. The three sections are
intentionally separate so training code can consume only `features.values`.

## Metadata

| Field | Meaning | Missing behavior |
| --- | --- | --- |
| `dataset_id`, `dataset_version` | Stable registry identity | Reject |
| `record_id`, `original_row_id` | Canonical and provider row references | Reject |
| `source_file`, `source_file_checksum` | Safe relative source identifier and SHA-256 | Reject; absolute/traversal paths rejected |
| `source_access_date` | Operator-recorded acquisition/generation date used by manifests | Reject |
| `capture_session_id`, `scenario_id`, `group_id` | Split and provenance identities | Reject |
| `observed_at` | UTC evidence time | Allowed by schema for sources without a row time, but quality gate fails until handled explicitly |
| `provenance` | String-only converter/source evidence | Reject empty key/value |
| `conversion_version` | Transformation contract | Reject unsupported version |

Metadata never enters the default feature vector. In particular, raw IPs,
ports, host IDs, timestamps, filenames, source paths, captures, scenarios,
groups, row IDs, and checksums are not model features.

## Features

`features.schema_version` must equal `1.0.0`; `features.names` must exactly equal
the tuple exported by `aegishunt.flows.registry.feature_names()`; and
`features.values` has the same length and position. Every value is finite and
within the Phase 3 registry range. Integer features must be integer-valued.

There is no dict-order fallback, column inference, label-derived feature,
silent imputation, NaN, or Infinity. An external dataset that cannot provide all
features with the same calculation semantics is rejected rather than padded.

## Labels

| Field | Meaning |
| --- | --- |
| `ground_truth_label` | Normalized `benign`, `malicious`, or explicitly `unmapped` |
| `binary_label` | `0`, `1`, or `null` only when a mapping explicitly marks an unknown label; quality then fails |
| `attack_family` | Normalized research family or `unmapped` |
| `original_label` | Unchanged provider text |
| `label_mapping_version` | Versioned YAML mapping used |

Unknown labels default to failure. Mapping never inspects feature values and
never changes labels for class balance.

## Deterministic conversion

The implemented CSV adapter accepts metadata columns followed by all 43 feature
columns in the exact registry order. The CLI requires an explicit
`--access-date YYYY-MM-DD`. It computes the raw SHA-256, preserves the source,
validates timestamps and values, normalizes labels, and emits stable sorted-key
JSON Lines. It does not overwrite raw or processed files.

The controlled demo directly builds harmless `PacketRecord` observations and
uses the Phase 3 finalizer/feature engine. It is therefore schema-compatible but
is not the output of a real PCAP capture and must remain labeled synthetic.

## Split contract

Splitting hashes `seed:group_id`, assigns whole groups, and refuses any source
file, capture session, or scenario shared by different groups. There is no
row-random fallback. The test split is frozen and explicitly prohibited for
model, threshold, or feature selection.

## Required outputs

- `dataset_manifest.json`
- `split_manifest.json`
- `quality_report.json`
- `leakage_report.json`
- `class_distribution.csv`
- `feature_statistics.csv`
- `canonical.jsonl`, `train.jsonl`, `validation.jsonl`, `test.jsonl`

Generated datasets and machine reports live under configured ignored roots and
are not committed. Definitions, mapping files, schemas, tests, and documentation
are committed.
