# Reproducibility statement

The repository records source/config versions, fixed feature order, seeds,
group splits, checksums, artifact inventories, one-time frozen identities,
environment metadata, source-backed figures/tables, and automated tests.

Reproduce the final delivery by:

1. checking out the Phase 14 PR commit;
2. using Python 3.11 or 3.12;
3. running `python -m build`;
4. installing the wheel without editable mode or `PYTHONPATH`;
5. running the quality and Phase 14 delivery tests;
6. running the explicit controlled demo offline;
7. generating figures/tables from their committed sources;
8. building and verifying a fresh ignored release bundle.

Formal frozen tests must not be rerun or overwritten. Demo artifacts use an
isolated namespace. Exact runtime UUIDs and timestamps may differ; stable input,
feature, policy, and evidence contracts are verified. Docker base-tag mutation
and package-index availability are residual supply-chain dependencies.
