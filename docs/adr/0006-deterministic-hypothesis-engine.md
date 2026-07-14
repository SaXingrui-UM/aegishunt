# ADR 0006: Use a deterministic hypothesis engine

## Status

Accepted

## Context

Threat hunting requires more than isolated scores: analysts need grouped
evidence, possible interpretations, benign alternatives, and validation steps.
Free-form generation would make core decisions difficult to test, reproduce,
audit, and constrain. The system must not turn uncertainty into unsupported
attack confirmation.

## Decision

Generate hypotheses from versioned deterministic templates, structured alert
and correlation evidence, model explanations, and optional curated MITRE
mappings. Template selection and every populated field must be explainable and
testable. Hypotheses explicitly separate observed facts, inference,
assumptions, alternatives, and recommended steps and cannot default to `confirmed`.

## Alternatives considered

- Free-form LLM generation as the primary engine.
- Emit alerts without hypotheses.
- Hard-coded unstructured prose embedded in correlation rules.
- Automatically map each high-risk result to a confirmed attack technique.

## Consequences

Outputs are reproducible, offline-capable, safe to test, and traceable to
evidence. Template coverage and wording require deliberate maintenance, and
unclassified behavior may receive a generic hypothesis rather than fluent prose.

## Risks

Templates can be too rigid, omit a useful alternative, or create a misleading
mapping if evidence conditions are weak. Confidence and severity could still be
overread by users. Review, conservative thresholds, provenance, and explicit
uncertainty language are required.
