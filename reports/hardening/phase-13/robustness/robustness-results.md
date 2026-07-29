# AegisHunt Phase 13 Robustness Experiment Results

These are controlled offline robustness checks on a development host. They are not a public benchmark or production reliability claim.

- Matrix schema: `1.1.0`
- Result schema: `1.0.0`
- Random seed: `20260729`
- Total: 21
- Passed: 21
- Failed: 0
- Network: not required
- Privilege: no root or administrator access

| ID | Category | Expected invariant | Status | Duration s |
|---|---|---|---:|---:|
| ROB-001 | malformed-pcap | Invalid captures are rejected without unbounded reads. | PASS | 0.540 |
| ROB-002 | invalid-csv | Invalid flow CSV rows are rejected without persistence. | PASS | 4.084 |
| ROB-003 | oversized-upload | HTTP 413 is returned and no ingestion job is created. | PASS | 3.831 |
| ROB-004 | model-schema | Invalid inference batches fail closed before model execution. | PASS | 8.598 |
| ROB-005 | path-traversal | Relative traversal, absolute paths, and unsafe archive members are rejected. | PASS | 0.559 |
| ROB-006 | sqlite-concurrency | Jobs have unique identities and reach durable terminal states without lock leakage. | PASS | 0.638 |
| ROB-007 | corrupt-model | Bundle verification fails closed before deserialization or prediction. | PASS | 9.434 |
| ROB-008 | model-version-collision | A model-version collision is rejected and the original bundle remains intact. | PASS | 9.612 |
| ROB-009 | duplicate-ingestion | Jobs remain independently auditable while immutable content is safely reused. | PASS | 4.190 |
| ROB-010 | transaction-rollback | Commit and rollback boundaries remain durable and isolated. | PASS | 4.309 |
| ROB-011 | provenance | Generator-equivalence verification rejects altered canonical content. | PASS | 2.895 |
| ROB-012 | fusion-identity | Model or feature-schema drift is rejected before policy fitting. | PASS | 2.925 |
| ROB-013 | json-bounds | Oversized records are rejected without whole-file materialization. | PASS | 3.954 |
| ROB-014 | pcapng-bounds | Excess interface blocks are rejected before packet processing. | PASS | 3.935 |
| ROB-015 | file-size-boundary | An oversized file is rejected and no staging residue remains. | PASS | 0.550 |
| ROB-016 | idempotent-demo | Repeated execution returns stable evidence without duplicate durable state. | PASS | 45.957 |
| ROB-017 | atomic-flow-persistence | The ingestion job fails safely and the transaction leaves no partial flows. | PASS | 0.679 |
| ROB-018 | exact-upload-boundary | Exact-limit bytes persist and the next byte is rejected without staging residue. | PASS | 4.118 |
| ROB-019 | cross-split-near-duplicate | Values inside the declared tolerance fail the leakage gate despite rounded-bin drift. | PASS | 2.863 |
| ROB-020 | supervised-bundle-contract | Isolated evidence is deterministic and invalid bundles or inference contracts are rejected. | PASS | 13.908 |
| ROB-021 | fusion-policy-contract | Extra, corrupt, missing, and unsafe policy artifacts are rejected. | PASS | 12.506 |

## Interpretation

- PASS means the named regression test passed in an isolated pytest process.
- FAIL is never converted to skip or xfail by this runner.
- Full command evidence remains in the JSON and CSV results.
- The matrix does not rerun frozen model-selection or test-set evidence.
