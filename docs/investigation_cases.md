# Investigation Case Contract

## Purpose and semantics

An `InvestigationCase` is an analyst-controlled work item. It is not a confirmed
attack, confirmed compromise, attribution, or automated incident declaration. Case
priority is triage priority—not probability, certainty, or an automatic business-impact
finding. The primary Phase 10 boundary is:

```text
reviewable ThreatHypothesis
→ deterministic primary InvestigationCase
→ typed evidence / notes / lifecycle / analyst verdict
```

Possible ATT&CK mappings remain behavioral analogies. Suggested queries remain
structured `not_executed` data and report generation never executes them.

## Identity and creation

One primary hypothesis has at most one primary Case. UUIDv5 identity binds the
hypothesis UUID, Case schema `1.0.0`, and configured policy ID/version; wall-clock
time is excluded. Repeating creation returns the first record without changing its
`created_at` or evidence. Eligible hypothesis states are configured and limited to
reviewable states. The group and all supporting alerts must resolve and agree before
the transaction writes anything.

Creation atomically writes the Case, immutable initial references, cautious uncertainty
snapshot, and audit event. The snapshot preserves assumptions, benign alternatives,
possible mappings, source event window, and hypothesis/policy identities. It never
changes the hypothesis, alert group, supporting alerts, model, or policy.

## Lifecycle

Policy `aegishunt-case-feedback-controlled` `1.0.0` defines:

```text
open → investigating | needs_more_information | closed
investigating → needs_more_information | closed
needs_more_information → investigating | closed
closed → terminal
```

The explicit `close` operation—not a generic status update—requires an actor, bounded
closure note, non-empty evidence, a related hypothesis, and one of
`true_positive`, `false_positive`, or `benign_expected`. `needs_more_information`
is non-final. Closing never changes hypothesis or alert status and triggers no response,
training, threshold change, or model activation.

Event time and lifecycle time are distinct. Hypothesis/alert/flow observations retain
their original timestamps. Case/note/reference/feedback/report/export timestamps use an
injectable aware UTC clock, and mutations must be strictly later than the prior Case
lifecycle timestamp.

## Mutable workflow fields

- Priority begins from the configured hypothesis-severity mapping and changes only via
  an explicit actor/reason operation.
- Assignment accepts a bounded local identifier or explicit unassignment; there is no
  network or external identity lookup.
- Notes are append-only records with stable ID, author, type, body, schema version, and
  UTC creation time. Corrections require a new note; no update/delete interface exists.
- Verdict and confidence are an analyst's current, revisable judgment—not ground truth.
  An exact duplicate is idempotent; a conflict requires an explicit update and reason.

## Evidence references

Allowed types are `threat_hypothesis`, `alert_group`, `security_alert`,
`detection_result`, and `network_flow`. Every object must exist in the database. A
canonical JSON snapshot and SHA-256 checksum are stored with the reference. Flow
snapshots deliberately omit `ground_truth_label` and `attack_family`. References are
append-only and duplicate object references are idempotent.

Phase 10 accepts no arbitrary attachment path, URL, upload, symlink, external download,
or raw file embed. Core Case evidence is immutable; later work adds only new typed
references.

## Case report

The explicit report command creates data-only JSON/Markdown plus a manifest and
checksums. It separates observed evidence, model inference, and analyst judgment;
shows event and lifecycle timelines; retains assumptions/alternatives; and states its
limitations. The exact inventory is non-overwriting and restricted to the configured
project-relative root. No LLM, query execution, network lookup, or automated response
is involved. A full Case API and Streamlit workspace remain Phase 12 scope.
