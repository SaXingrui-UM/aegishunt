# Runtime Recovery and Worker Operations

## Recovery model

Phase 11 provides deterministic origin replay, not exact cursor resume. An
interrupted or stale job enters `recovery_pending` with its lease cleared.
Automatic recovery is configuration-locked to false. An operator must run:

```bash
aegishunt runtime jobs recover <job-uuid>
```

Recovery resets the new attempt's observed and durable progress/counters,
increments `recovery_count`, and queues the same immutable pinned snapshot. The
interrupted attempt retains both progress layers as historical evidence. It does
not delete previously committed flows, detections, alerts, ledgers, groups, or
hypotheses.

Observed replay progress is explicitly non-durable live telemetry. It may show
how far the prior worker read, but it is not a checkpoint and is never used as a
packet offset. Durable progress describes committed evidence only. Since Phase
11 does not atomically persist an exact packet cursor together with every open
flow and timeout state, recovery always uses
`deterministic_restart_from_origin`.

During replay the output ledger validates committed evidence. Exact output is
reused; missing or conflicting evidence stops the job. A new attempt record
preserves the interruption and restart history.

## Pause and shutdown

Pause is a cooperative same-worker operation:

1. the operator requests pause on a running job;
2. the live owner reaches a control point and persists `paused`;
3. the owner renews its lease while paused;
4. resume returns that same attempt to `running`.

The same live attempt retains observed progress while paused and retains the
last committed durable progress. Pause does not flush open flows. These
properties apply only while that worker remains alive; they do not turn observed
progress into a recoverable cursor.

If the worker shuts down while paused or running, the attempt is interrupted and
the job becomes `recovery_pending`. Open flow state is discarded and will be
rebuilt on explicit origin replay. Completed batches remain durable.

SIGINT and SIGTERM handlers only set a shutdown event. Replay sleep checks it in
short quanta. The worker then persists interruption and stopped state where the
database remains available.

## Lease reconciliation

At startup a worker first reconciles persisted active worker records whose
heartbeat is older than the configured stale-worker threshold. Those records
become `failed` with a safe reason; this status cleanup does not recover or
requeue any job. The worker then finds expired job leases in validating,
running, pause-requested, or paused state. It marks those jobs
`recovery_pending` and records a single audit event. It does not infer that
replay is safe to resume and does not steal an unexpired lease.

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
