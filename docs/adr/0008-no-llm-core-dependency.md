# ADR 0008: Do not require an LLM for core operation

## Status

Accepted

## Context

Core detection and hunting must run reproducibly without an API key or public
network. An external LLM introduces nondeterminism, data-transmission concerns,
cost, availability dependencies, prompt-injection exposure, and explanations
that may not be faithful to stored evidence.

## Decision

Do not use an LLM for telemetry processing, detection, scoring, correlation,
hypothesis selection, case workflow, model evaluation, or required explanations.
If a later phase proposes an optional summary adapter, it must be disabled by
default, receive only explicitly approved bounded data, identify generated text,
and have no authority to confirm attacks or execute actions.

## Alternatives considered

- Require an LLM for hypothesis generation.
- Use an LLM as the detector or fusion engine.
- Use an LLM only for all user-facing explanation text.
- Exclude LLM integration permanently, including optional research extensions.

## Consequences

Core operation is offline-capable, deterministic, cheaper, safer to reproduce,
and easier to test. Template and explanation quality must be engineered locally.
Optional summarization remains possible only behind a documented trust boundary.

## Risks

Deterministic text may be less flexible or fluent. A future optional adapter
could accidentally become a hidden dependency or transmit sensitive evidence.
Tests, configuration defaults, UI labeling, data minimization, and explicit user
control must preserve the boundary.
