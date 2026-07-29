# Phase 13 Codex Security Findings Ledger

## Canonical evidence

The machine-reviewable ledger is
`configs/hardening/phase-13-security-findings.json`. It contains every finding
from the immutable full-repository baseline:

- Scan ID: `182ceaf4-8d4a-4a23-983a-ffa0a4b0610a`
- Revision: `75c73bc86a40a78a22edde5fb175359a7b755c05`
- Findings: 80
- Critical: 0
- High: 0
- Medium: 7
- Low: 73

Every row retains the original finding number and a stable tracking ID, title,
severity, confidence, subsystem, root-cause cluster, reachability, required
attacker capability, disposition, fix/test evidence where applicable,
mitigation, residual impact, Phase 14 action, and notes.

## Disposition summary

| Disposition | Count |
| --- | ---: |
| Fixed | 9 |
| Accepted risk | 39 |
| Deferred to Phase 14 | 19 |
| Needs further validation | 13 |
| Duplicate | 0 |
| False positive | 0 |
| Not reachable | 0 |
| Untriaged | 0 |
| **Total** | **80** |

The nine Fixed rows are all seven original Medium findings plus Low finding 35
(excessive JSON nesting) and Low finding 61 (disabled reason-code enforcement).
Each Fixed row names its corrective commit and regression test. All 73 Low
findings have an individual disposition; none is represented by a bulk
"residual" label.

Accepted-risk rows retain the local single-user or same-user filesystem
prerequisite, current containment, possible residual impact, and a Phase 14
delivery recommendation. Deferred and further-validation rows likewise retain
their per-finding action rather than being silently ignored.

## Validation

`scripts/validate_phase13_security_findings.py` fails closed when the ledger:

- does not contain exactly findings 1–80;
- does not contain exactly 7 Medium and 73 Low rows;
- duplicates an original number or tracking ID;
- uses an unsupported or untriaged disposition;
- omits fix/test evidence for a Fixed row; or
- omits rationale and mitigation for a risk disposition.

The ledger describes the immutable baseline. The exact-final-HEAD Codex
Security rescan is a separate merge gate and must use the final PR revision.
