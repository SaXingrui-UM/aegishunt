# Consolidated limitations and future work

## Research evidence

- Current model evidence is controlled synthetic and small. There is no public
  benchmark result, enterprise capture validation, external validity, or
  production performance evidence.
- The Phase 5 corrected frozen test has wide intervals. The LOF corrective path
  is validation-qualified only and has no untouched independent holdout.
- Phase 7 fusion is inconclusive, did not exceed supervised-only on known late
  groups, underperformed anomaly-only on family-macro LOAO recall, and missed
  held-out exfiltration and reconnaissance.
- Deterministic correlation and hypothesis templates are explainable but do not
  attribute a threat actor, prove intent, or establish causality.
- Analyst feedback can be noisy or malicious. Retraining candidates are
  review-only, and no automatic training or activation exists.
- Model/domain drift, capture visibility, label uncertainty, and benign
  reference-profile generalization remain open.

## Runtime and deployment

- Local single-node SQLite supports one worker. It is not a distributed or
  high-availability queue.
- Recovery restarts deterministically from packet zero; there is no exact
  durable packet cursor or distributed exactly-once guarantee.
- There is no live capture, automatic response, automatic recovery, automatic
  retraining, authentication/RBAC, TLS termination, multi-tenancy, cloud
  orchestration, systemd unit, or remote target.
- Docker Compose is local-only. Containers reduce accidental privilege but do
  not provide a production isolation guarantee.
- DEF-004 remains: a completely unavailable database cannot receive a failure
  record in that same database. The process fails closed with a sanitized error.

## Measurement and security

- Phase 13 resource measurements are one Darwin arm64 development-host
  observation. TestClient API latency is in-process rather than network
  latency; performance is not an SLA or capacity guarantee.
- The formal exact-final-head Codex Security rescan was explicitly waived by
  the user and was not executed. No pass is claimed.
- Secret-history scanning covered 1,264 text blobs with 18 binary blobs and one
  documented oversized historical blob excluded. Zero confirmed secrets,
  unreviewed candidates, and stale allowlist entries were reported, but this
  does not mean every reachable blob was scanned.
- The Phase 13 ledger retains accepted, deferred, and needs-validation risks.
  Same-user filesystem access, artifact replacement opportunities, denial of
  service, and supply-chain controls need stronger production boundaries.
- The Docker base uses a patch-level tag without an immutable digest.

## Final-delivery samples

The two user-supplied captures have unknown acquisition provenance and license,
contain real-style network identities/application content, and are therefore
ignored. Distributable derivatives contain generated headers only,
documentation addresses, no copied payload, and aggregate profiles. Their
`attack-like`/`benign-like` names are not verified labels. They demonstrate
pipeline mechanics, not model quality.

Future work includes licensed benchmark evaluation, independent holdouts,
multi-site benign baselines, authenticated deployment, an independent durable
control plane, multi-node storage/queue design, signed builds and SBOMs,
immutable base-image digests, and externally reviewed security testing.
