# Phase 09 Release Notes

## Objective and status

Correlate immutable Phase 8 alerts into deterministic evidence groups and generate
cautious, reviewable threat-hunting hypotheses without confirmation, attribution,
external enrichment, LLM dependency, or automated response.
Correlation and confidence scores are not attack probability.
A hypothesis is not a confirmed attack; severity is triage priority only.

Status: **Phase complete**.

- Branch: `phase/09-hypothesis-engine`
- Base main: `5b7c9496d77404fadcd757d75e482ce78476e55f`
- Pull request: [#28](https://github.com/SaXingrui-UM/aegishunt/pull/28),
  `[Phase 09] Alert correlation and threat hypothesis engine`, merged from
  `phase/09-hypothesis-engine` into `main`; both required `quality` checks passed
- Merge commit: `ffdd7639b60d944b19d70096e1ff38de0d8761f8`
- Completion tag: annotated `phase-09-complete` (object
  `e5b39861c23e15f887cf9d4a586d0dcda5d93d1e`), remotely verified at the merge commit
- Completion date: 2026-07-22 (Asia/Shanghai)
- Phase 10: Not started

## Completed scope

- Checksummed/versioned correlation policy and strict fail-closed validation.
- Canonical typed entity keys, immutable evidence snapshots, and observed event time.
- Bounded earliest-event-anchored inclusive windows and deterministic ordering.
- Seven versioned rules covering source reconnaissance/fan-out, repeated pair failures,
  destination fan-in, periodic timing, multi-engine evidence, and accumulation.
- Transparent risk/count/diversity/density components, configured severity, stable UUIDv5
  group identities, group deduplication, and policy provenance.
- Eight deterministic hypothesis templates, stable primary/candidate selection, and
  unclassified fallback.
- Separate facts, derived inferences, assumptions, benign alternatives, possible MITRE
  mappings, defensive steps, and structured query suggestions marked `not_executed`.
- Non-probabilistic confidence components and a configured generation gate.
- Default `proposed` lifecycle, audited analyst transitions, and prohibition of direct
  or automatic confirmation.
- Existing schema/ORM/repository extension, additive schema v2→v3 migration, restart
  persistence, and idempotent rerun behavior.
- Separate observed event windows from injectable-clock lifecycle timestamps; stable
  identities remain independent of wall-clock time and idempotent reruns preserve the
  first persisted creation time.
- Typed `aegishunt hunt` configuration, correlation, group, generation, hypothesis, and
  status commands.
- Truthful Streamlit/README/architecture/data-model status and detailed contracts.

## Architecture decisions

ADR 0018 records the bounded entity-index architecture, event-time semantics, stable
identity, transparent scoring, deterministic templates, analyst-control boundary, and
no-LLM/no-enrichment core. Alert creation remains Phase 8; case and feedback workflow
remains Phase 10; full runtime hunting API/frontend remains Phase 12.

## Tests

- Ruff: passed for the complete repository.
- Strict mypy: passed for all 168 source files.
- Final closure pytest: 365 passed, 0 failed, 0 skipped, 0 xfailed in
  1,062.84 seconds.
- Branch-aware coverage: 86.74%, above the unchanged 85% project gate.
- Focused Phase 9 unit/integration/restart/lifecycle/CLI/E2E/status selection:
  39 passed in 7.58 seconds.
- Manual `aegishunt hunt --help` and correlation-policy verification passed with
  `PYTHONPATH=src`; the desktop editable-install `.pth` visibility issue is recorded
  as an environment limitation, not as a standard-install success.
- Tests use controlled local fixtures and temporary SQLite databases only; no network,
  root privilege, live capture, external target, generated model, or formal experiment
  evidence is used.

## Review outcome

Native post-merge `codex review` against the pre-merge base could not start because
the installed arm64 executable is missing (`ENOENT`), so an equivalent read-only diff
review was used.
The first pass found one Medium issue: normal generation-gate rejection was handled
through a silently caught exception. Commit `8c80e8e` made gate eligibility explicit
and added regression coverage. A subsequent user review found one correctness-related
Medium lifecycle issue: group and hypothesis record creation times were incorrectly
copied from the observed event window. Commit `864ef66` introduced injectable clocks,
separated event and lifecycle timestamps, retained generation time in structured
evidence, preserved stable identities/idempotent creation time, and required later
status-update timestamps. Post-fix and post-merge Ruff, strict mypy, focused tests,
the full suite, scope scans, and equivalent review passed with zero Blocking, zero
High, and zero unresolved correctness-related Medium findings. Both PR #28 `quality`
checks passed before merge.

## Known limitations

- Correlation quality depends on retained local entity/event facts and configured
  context-sensitive thresholds.
- Fan-in, fan-out, failure, and periodic patterns can be benign; alternatives are kept.
- Deterministic templates are limited to the committed catalog and use no external
  context enrichment or LLM dependency.
- ATT&CK mappings are possible behavioral analogies, not technique proof or attribution.
- Cross-group case management, analyst feedback export, retraining, and model activation
  are later phases.
- Full operational API/frontend workflows remain Phase 12 scope; this remains a
  controlled research prototype.
- DEF-004 remains a non-blocking limitation: a completely unavailable database cannot
  persist an outage record into itself.

## Next phase

Phase 10 — Investigation Case Management and Analyst Feedback, planned branch
`phase/10-case-feedback`. It is **Not started** and must not begin without separate,
explicit user authorization after this closure is merged and `main` is synchronized.
