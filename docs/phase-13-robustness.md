# Phase 13 Robustness Experiments

## Contract

The predefined matrix is
`configs/hardening/phase-13-robustness.yaml`, schema `1.1.0`, seed `20260729`.
It contains 21 scenarios covering malformed input, schema drift, bounded
uploads, path safety, SQLite concurrency and rollback, duplicate execution,
artifact corruption, model/policy identity, controlled provenance, and
atomic flow persistence.

Each scenario runs in a separate pytest process with coverage disabled for that
subprocess only. The repository-wide coverage gate is run separately. Tests use
temporary directories/databases, do not access the public network, require no
root privilege, and do not perform live capture or attack activity.

## Actual result

- Scenarios: 21
- Passed: 21
- Failed: 0
- Test instances represented: 27
- Formal frozen evidence regenerated: No
- Model or fusion policy selected/activated: No
- Workspace database or model binary generated: No

The initial v1.0.0 matrix run reported 16 PASS / 1 FAIL because ROB-011 referred
to an old test function name. This was a test-matrix configuration defect, not
a product pass. The node was corrected, the direct test passed, and the whole
matrix was rerun. The matrix was then expanded to v1.1.0 before final evidence
to cover exact upload boundaries, cross-split quantization boundaries,
supervised bundle contracts, and fusion-policy integrity.

Final evidence:

- `reports/hardening/phase-13/robustness/robustness-results.json`
- `reports/hardening/phase-13/robustness/robustness-results.csv`
- `reports/hardening/phase-13/robustness/robustness-results.md`

## Limitations

These controlled offline tests demonstrate expected fail-closed invariants for
the tested fixtures. They are not a production reliability benchmark, public
dataset result, real-attack experiment, zero-day claim, or proof that every
possible malformed file or filesystem race is covered. SQLite remains a
single-node store, and DEF-004 remains: total database unavailability cannot be
persisted into that same unavailable database.

## Reproduction

```bash
PYTHONPATH=src .venv/bin/python -m scripts.run_phase13_robustness
```

The command exits non-zero if any scenario fails. It never converts failures to
skip or xfail.
