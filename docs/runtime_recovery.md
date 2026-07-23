# Runtime Recovery and Worker Operations

## Recovery model

Phase 11 provides deterministic origin replay, not exact cursor resume. An
interrupted or stale job enters `recovery_pending` with its lease cleared.
Automatic recovery is configuration-locked to false. An operator must run:

```bash
aegishunt runtime jobs recover <job-uuid>
```

Recovery resets attempt progress and counters, increments `recovery_count`, and
queues the same immutable pinned snapshot. It does not delete previously
committed flows, detections, alerts, ledgers, groups, or hypotheses.

During replay the output ledger validates committed evidence. Exact output is
reused; missing or conflicting evidence stops the job. A new attempt record
preserves the interruption and restart history.

## Pause and shutdown

Pause is a cooperative same-worker operation:

1. the operator requests pause on a running job;
2. the live owner reaches a control point and persists `paused`;
3. the owner renews its lease while paused;
4. resume returns that same attempt to `running`.

If the worker shuts down while paused or running, the attempt is interrupted and
the job becomes `recovery_pending`. Open flow state is discarded and will be
rebuilt on explicit origin replay. Completed batches remain durable.

SIGINT and SIGTERM handlers only set a shutdown event. Replay sleep checks it in
short quanta. The worker then persists interruption and stopped state where the
database remains available.

## Lease reconciliation

At startup a worker finds expired leases in validating, running,
pause-requested, or paused state. It marks them `recovery_pending` and records a
single audit event. It does not infer that replay is safe to resume and does not
steal an unexpired lease.

## Resource monitoring

The worker samples its own CPU and RSS plus system-memory percentage with
`psutil`. Sampling is interval-controlled and bounded per worker. If sampling
fails:

- all measurement fields are null, not zero;
- `sampler_available` is false;
- the worker becomes degraded with a safe reason;
- replay continues;
- resource samples and heartbeats do not generate per-sample audit spam.

These measurements are local development observations, not a production
capacity claim or SLA.

## Failure boundaries

Source/artifact drift, malformed capture data, scoring errors, evidence
conflicts, and database transaction failures fail closed. Error strings are
bounded and must not include credentials, traceback, or arbitrary absolute
paths. A total database outage cannot write its own durable failure record into
the unavailable database; DEF-004 remains documented and non-blocking for this
single-node phase.
