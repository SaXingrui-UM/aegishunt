# ADR 0018: Bounded deterministic alert correlation and hypotheses

- Status: Accepted

## Context

Phase 8 produces immutable analyst-reviewable alerts, but individual alerts do not
express repeated or entity-centered behavior. Phase 9 must correlate those records
without turning suspiciousness into attack confirmation, introducing unbounded
pairwise processing, depending on external enrichment, or making an LLM part of the
core decision path.

## Decision

Use a checksummed, versioned YAML policy; canonical typed entity keys; observed event
times retained in alert evidence; earliest-event-anchored inclusive windows; bounded
entity indexes; and deterministic rule evaluation. Stable UUIDv5 identities bind a
group to policy identity and sorted source alert IDs. A transparent weighted score
retains risk, count, evidence-diversity, and temporal-density components and is defined
only as triage evidence strength.

Generate at most one deterministic primary hypothesis template per eligible group
while retaining all candidate template IDs. The record separates observed facts,
derived inferences, assumptions, benign alternatives, possible ATT&CK mappings,
structured non-executed queries, and defensive review steps. Hypotheses begin as
`proposed`; direct or automatic `confirmed` transitions are prohibited.

## Alternatives considered

- All-pairs alert comparison: rejected because it is harder to bound and explain.
- Processing-time windows: rejected because replay order would change results.
- Learned/LLM correlation: rejected as non-deterministic and unnecessary for the core.
- Automatic attack confirmation or response: rejected by the analyst-control boundary.

## Consequences

Replay of the same alert evidence and policy produces stable groups, feature values,
templates, and IDs. False-positive/benign verdicts are explicitly excluded. Repository
writes and analyst status changes remain auditable. New correlation patterns require a
versioned policy/rule change rather than hidden code-path tuning.

## Risks

Fixed windows and thresholds are context-sensitive. Entity quality depends on retained
local evidence. Periodicity, fan-in, and fan-out can have benign explanations. ATT&CK
mappings are only possible analogies, not technique confirmation or attribution.
