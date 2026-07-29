# Phase 13 Dependency Vulnerability Review

## Result

The Phase 13 dependency gate passed on 2026-07-29. This is a real audit of the
installed editable development environment, not a manifest-only or simulated
result.

- Python: CPython 3.12.13
- `pip-audit`: 2.10.1
- `pip`: 26.1.2
- Installed distributions audited: 113
- `pip check`: PASS
- Network status: available
- Critical advisories: 0
- High advisories: 0
- Medium advisories: 0
- Low advisories: 0
- Reachable unresolved runtime advisories: 0

Because the final audit returned no advisory, there is no advisory ID, severity,
fixed version, reachability exception, or review-date exception to record.
Failure to reach the audit service is represented as a failed gate and cannot be
reported as a pass.

## Remediation performed

An initial audit of the older environment reported 49 advisories across 109
installed distributions. Only dependencies required to remove those findings
were updated. The development tooling is fixed at:

- `pip-audit==2.10.1`
- `bandit==1.9.4`
- `detect-secrets==1.5.0`

The resulting environment was checked with the complete repository test suite,
bundle and policy loading paths, API/frontend tests, controlled sample demo,
runtime replay, and offline E2E tests. No model, threshold, calibration,
selection policy, fusion weight, frozen evaluation, or active artifact pointer
was changed to satisfy the audit.

## Scope and interpretation

`pip-audit` inspects both direct and transitive packages in the actual Phase 13
development environment, so runtime and development dependencies are included.
The pull-request-only GitHub Dependency Review job independently checks
dependency changes at the PR boundary and fails on Moderate or higher severity.

This is a point-in-time vulnerability review. It is not a guarantee that future
advisories will remain absent. Phase 14 delivery must preserve automated audit
execution and define an operational review cadence.
