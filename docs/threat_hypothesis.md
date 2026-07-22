# Phase 9 Threat Hypothesis Contract

## Meaning

A threat hypothesis is a deterministic, reviewable hunting lead. It is not a fact,
confirmed attack, attribution statement, model probability, or automated-response
instruction. The default status is `proposed` and no core path can directly or
automatically set `confirmed`.

## Generation gate

Generation requires a Phase 9 group, the configured minimum member count, a
correlation score at or above the configured hypothesis threshold, non-empty rule
provenance, and retained evidence. Below-gate groups remain queryable but do not receive
fabricated hypotheses.

## Templates and evidence

Version `1.0.0` supports possible reconnaissance, credential abuse, brute force,
beaconing, command-and-control-like behavior, data exfiltration, denial of service, and
an unclassified fallback. Rule/reason evidence selects candidates in a fixed priority
order. One primary template is recorded and all eligible candidate IDs are retained.

Every record separates:

- observed facts copied from the alert group;
- derived inferences with non-probabilistic semantics;
- assumptions that need validation;
- plausible benign alternatives;
- possible MITRE ATT&CK mappings with support and limitations;
- structured query suggestions marked `not_executed`;
- defensive analyst review steps.

Possible mappings currently reference T1046, T1078, T1110, T1071, T1041, or T1498
where relevant. They are behavioral analogies for analyst review, never attribution.
Mapping catalog `1.0.0` was checked on 2026-07-22 against official MITRE ATT&CK
Enterprise `v19.1`; every mapping retains its official technique URL, low/medium
support level, supporting evidence, and limitation. Relevant official sources include
[T1046](https://attack.mitre.org/techniques/T1046/),
[T1078](https://attack.mitre.org/techniques/T1078/),
[T1110](https://attack.mitre.org/techniques/T1110/),
[T1071](https://attack.mitre.org/techniques/T1071/),
[T1041](https://attack.mitre.org/techniques/T1041/), and
[T1498](https://attack.mitre.org/techniques/T1498/). Insufficient evidence yields no
mapping rather than a forced catalog entry.

## Confidence and lifecycle

Confidence combines group correlation, rule specificity, evidence diversity, and
entity coherence with checksummed configured weights. It is a finite bounded triage
score, not likelihood. Safe analyst-controlled transitions include under review, needs
more information, dismissed, rejected, or closed unresolved. Transitions are audited
in the same transaction. Phase 10 case creation and feedback workflows are explicitly
out of scope.
