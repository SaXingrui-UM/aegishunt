# Phase 13 Security Tool Review

## Sanitized result

The Phase 13 local security gate passed on 2026-07-29. Its committed runner is
`scripts/run_phase13_security.py`; machine output is written only to a temporary
or ignored path.

| Gate | Tool | Version | Scope | Result |
| --- | --- | --- | --- | --- |
| Dependency audit | `pip-audit` | 2.10.1 | 114 Python 3.12 and 110 clean Python 3.11 installed direct/transitive distributions | PASS; 0 advisories in both environments |
| Environment consistency | `pip check` | pip 26.1.2 | Installed environment | PASS |
| Secret scan | `detect-secrets` | 1.5.0 | Tracked tree, complete reachable Git blob history, `.github`, configs, docs, scripts, tests, sample manifests, generated PR body | PASS; 0 confirmed secrets |
| Static scan | Bandit | 1.9.4 | `src/aegishunt` and `scripts` | PASS; 45 Low, 0 Medium/High, 0 errors |

## Secret scan

- Unique historical text blobs scanned: 1,264
- Binary blobs safely skipped: 18
- Oversized blobs safely skipped: 1
- Current tracked/generated-body candidates: 33
- Historical candidates: 45
- Reviewed exact false positives: 45
- Stale allowlist entries: 0
- Unreviewed candidates: 0
- Confirmed secrets: 0

Candidate values are never written to the summary. Only detector type, path, and
a one-way digest are used for exact review. Each allowlist entry names one path,
one detector type, one digest, its historical occurrence count, and a rationale.
There is no blanket path or detector suppression. The generated PR body is read
from `.github/generated/phase-13-pr.md` when present or from the GitHub
pull-request event payload in CI.

The one oversized historical blob is excluded by the documented scanner work
bound and is recorded as a limitation rather than silently treated as scanned.
Tracked current files remain subject to the normal file scanner. A confirmed
secret or an unreviewed candidate makes the gate fail closed.

## Static scan

Bandit reported 45 Low-severity observations and no Medium or High finding.
There are no `# nosec` suppressions. The scan includes production source and
repository scripts; test-only deliberate fixtures are validated by the separate
secret and security-gate tests rather than used as the production static-scan
scope.

The Bandit gate rejects scanner errors and blocks a Medium or High result. It
also records severity totals in sanitized JSON. Bandit is not represented as a
formal Codex Security repository rescan. The user explicitly removed that final
rescan from this task, and no rescan result is claimed.

## Boundaries

No raw scanner log, secret candidate value, private temporary path, database,
model binary, upload, or large scanner artifact is committed. These checks do
not convert the local research prototype into a public or production service.
