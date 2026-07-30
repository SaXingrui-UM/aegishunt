"""Regression tests for the durable Phase 13 post-merge checkpoint."""

from pathlib import Path

PROJECT_ROOT = Path(__file__).parents[2]
PHASE_13_CANONICAL_MERGE = "".join(
    ("38e5b8b9", "05aba50f", "f9acfc7f", "84f850f0", "3eb3f2f3")
)
PHASE_13_FINAL_HEAD = "".join(
    ("5b183a53", "d76aaa72", "807200e6", "d54793e9", "c0a4fcda")
)


def _section(content: str, start: str, end: str) -> str:
    """Return one explicitly bounded Markdown section."""
    return content.split(start, maxsplit=1)[1].split(end, maxsplit=1)[0]


def test_readme_records_phase_thirteen_without_starting_phase_fourteen() -> None:
    content = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    current = _section(content, "## Current status", "## Planned architecture")
    normalized = " ".join(current.split())

    assert "Phases 0–13 are complete" in current
    assert "Phase 13 PR [#39]" in current
    assert "is merged as" in normalized
    assert PHASE_13_CANONICAL_MERGE in current
    assert PHASE_13_FINAL_HEAD in current
    assert "phase-13-complete" in current
    assert "Phase 14 is **Not started**" in normalized
    assert "phase/14-final-delivery" in normalized
    assert "has not been created" in normalized
    assert "offline, rootless PCAP replay" in normalized
    assert "durable jobs" in normalized
    assert "verified artifact pinning" in normalized
    assert "does not enable live capture or automatic recovery" in normalized
    assert "observed event time separate" in normalized
    assert "pipeline verification only" in current
    assert "recommendation is **inconclusive**" in normalized
    assert "was not shown to be superior" in normalized
    assert "family-macro LOAO Recall was lower than anomaly-only" in normalized
    assert "missed held-out exfiltration and reconnaissance" in normalized
    assert "negative results are retained" in normalized.lower()
    assert "operational suspiciousness risk" in normalized
    assert "not attack probability" in normalized
    assert "alert is a prompt for analyst review" in normalized
    assert "not attack probabilities" in normalized
    assert "hypotheses are not facts" in normalized
    assert "never executed" in normalized
    assert "public benchmark" in current and "production validation" in current
    assert "proof of zero-day detection" in current
    for transient in (
        "live capture is enabled",
        "automatic recovery is enabled",
        "Phase 13 is **In progress**",
        "Implementation complete — awaiting PR review",
        "Phase 14 is **In progress**",
    ):
        assert transient not in current
    assert "No operation trains, activates, or replaces a model" in normalized
    assert "retraining_candidate" in normalized


def test_frontend_records_phase_thirteen_complete() -> None:
    source = (
        PROJECT_ROOT / "src/aegishunt/frontend/app.py"
    ).read_text(encoding="utf-8")

    assert "Phase 13 hardening: Complete" in source
    assert "PR #39 merged" in source
    assert "Checkpoint tag phase-13-complete verified" in source
    assert "Phase 14: Not started" in source
    assert "awaiting PR review" not in source
    assert "Phase 14: In progress" not in source


def test_pm_def_001_is_resolved_without_erasing_history() -> None:
    defects = (PROJECT_ROOT / "docs/known_defects.md").read_text(encoding="utf-8")
    pm_def_001 = defects.split("## DEF-004", maxsplit=1)[0]

    assert "- Status: Resolved" in pm_def_001
    assert "0.19178394648427863" in pm_def_001
    assert "isotonic" in pm_def_001 and "Brier `0.0`" in pm_def_001
    assert "76f79972dff778f5d30d550bc6da78583e338fa1" in pm_def_001
    assert "phase-05-complete" in pm_def_001
    assert "phase-05-pm-def-001-complete" in pm_def_001
    assert "[#15]" in pm_def_001
    assert "pull/15" in pm_def_001
    assert "not public\n  benchmark or real-world performance evidence" in pm_def_001


def test_progress_and_release_record_phase_thirteen_without_phase_fourteen_scope() -> None:
    progress = (PROJECT_ROOT / "docs/codex_progress.md").read_text(encoding="utf-8")
    release = (PROJECT_ROOT / "docs/releases/phase-13.md").read_text(encoding="utf-8")

    progress_current = _section(
        progress,
        "## Current state",
        "## Phase 13 implementation checkpoint",
    )
    release_current = _section(
        release,
        "## Objective and status",
        "## Completed scope",
    )
    normalized_progress_current = " ".join(progress_current.split())
    normalized_release_current = " ".join(release_current.split())
    normalized_release = " ".join(release.split())

    for content in (progress_current, release_current):
        assert "Phase complete" in content
        assert "Phase 14" in content and "not started" in content.lower()
        assert "Implementation complete — awaiting PR review" not in content

    assert "Current phase | Phase 13" in normalized_progress_current
    assert "Status | Phase complete" in normalized_progress_current
    assert "Phase 10 status | Phase complete" in normalized_progress_current
    assert "Phase 11 status | Phase complete" in normalized_progress_current
    assert "Phase 12 status | Phase complete" in normalized_progress_current
    assert "Phase 13 status | Phase complete" in normalized_progress_current
    assert "Phase 14 status | Not started" in normalized_progress_current
    assert "phase/13-hardening" in normalized_progress_current
    assert "was merged through PR #39" in normalized_progress_current
    assert "phase/14-final-delivery" in normalized_progress_current
    assert "has not been created" in normalized_progress_current
    assert "PR [#39]" in normalized_progress_current
    assert "pull/39" in progress_current
    assert PHASE_13_FINAL_HEAD in progress_current
    assert PHASE_13_CANONICAL_MERGE in progress_current
    assert "phase-13-complete" in progress_current
    assert "complete 80-finding disposition ledger" in normalized_progress_current
    assert "80-row ledger validated" in normalized_progress_current
    assert "All 17 core packages pass 80%" in normalized_progress_current

    assert "Status: **Phase complete**" in release_current
    assert "Pull request: [#39]" in normalized_release_current
    assert "pull/39" in release_current
    assert "(Merged)" in release_current
    assert "Final source-branch Head" in release_current
    assert PHASE_13_FINAL_HEAD in release_current
    assert "Canonical squash merge" in release_current
    assert PHASE_13_CANONICAL_MERGE in release_current
    assert "Completion tag: annotated `phase-13-complete`" in release_current
    assert "Phase 14: Not started" in normalized_release_current
    assert "pending" not in normalized_release_current.lower()

    assert "ADR 0022" in release
    assert "21 scenarios" in release
    assert "27 represented test instances" in release
    assert "7 Medium, 73 Low, 0 High, and 0 Critical" in release
    assert "not an SLA" in release
    assert "public benchmark" in normalized_release
    assert "Phase 14" in release
    assert "was explicitly waived by the user" in normalized_release
    assert "was not executed" in normalized_release
    assert "no final-rescan result is claimed" in normalized_release
    assert "not represented as a substitute result" in normalized_release

    for current in (progress_current, release_current):
        for transient in (
            "PR #33 remains open",
            "must pass before merge",
            "Phase 11 remains unmerged",
            "Wait for PR #33",
            "Current branch | `phase/11-runtime-replay`",
            "Phase 14 implementation complete",
            "Phase 14 is in progress",
            "phase/14-final-delivery` (created",
        ):
            assert transient not in current


def test_phase_eleven_gate_records_satisfied_stable_ancestor_invariant() -> None:
    progress = (PROJECT_ROOT / "docs/codex_progress.md").read_text(encoding="utf-8")
    startup_gate = _section(
        progress,
        "## Phase 11 startup invariant (satisfied)",
        "## Phase 12 startup invariant",
    )
    normalized = " ".join(startup_gate.split())

    # Protect against a self-referential post-merge closure loop: the permanent
    # checkpoint is an ancestor, not a future documentation-only main HEAD.
    assert "git merge-base --is-ancestor" in startup_gate
    assert "ba40211a374aa8e4efa62702a83d063f9eb88039 main" in startup_gate
    assert "Later documentation commits may be descendants" in normalized
    assert "rather than requiring the Tag to equal" in normalized
    assert "does not require documents to hard-code the live `main` HEAD" in normalized
    assert "no additional final-status or closure PR is required" in normalized
    assert "The full baseline then passed" in normalized
    assert "future merge SHA" not in startup_gate


def test_phase_twelve_gate_records_stable_phase_eleven_ancestor_invariant() -> None:
    progress = (PROJECT_ROOT / "docs/codex_progress.md").read_text(encoding="utf-8")
    startup_gate = _section(
        progress,
        "## Phase 12 startup invariant (satisfied)",
        "## Phase 13 startup invariant",
    )
    normalized = " ".join(startup_gate.split())

    # Protect against a self-referential post-merge closure loop: the permanent
    # checkpoint remains an ancestor of later documentation-only descendants.
    assert "PR #33 merge commit" in normalized
    assert "8f85949406e3db7d2fa2b3c48d04e832e84f3559" in startup_gate
    assert "annotated `phase-11-complete` Tag" in normalized
    assert "Later documentation-only commits may be descendants" in normalized
    assert "git merge-base --is-ancestor" in startup_gate
    assert "8f85949406e3db7d2fa2b3c48d04e832e84f3559 main" in startup_gate
    assert "does not require the Tag to equal" in normalized
    assert "does not require permanent documents to hard-code the live `main` HEAD" in (
        normalized
    )
    assert "does not require another final-status or closure PR" in normalized
    assert "`phase/12-api-frontend` branch must not already exist" in normalized
    assert "required baseline tests must pass" in normalized
    assert "explicit user authorization" in normalized


def test_phase_thirteen_gate_records_stable_phase_twelve_ancestor_invariant() -> None:
    progress = (PROJECT_ROOT / "docs/codex_progress.md").read_text(encoding="utf-8")
    startup_gate = _section(
        progress,
        "## Phase 13 startup invariant (satisfied)",
        "## Phase 14 startup invariant",
    )
    normalized = " ".join(startup_gate.split())

    assert "PR #35 merge commit" in normalized
    assert "baac8e5ecf9f8a2ac66afe2873269bebcbbcbf17" in startup_gate
    assert "annotated `phase-12-complete` Tag" in normalized
    assert "Later documentation-only commits may be descendants" in normalized
    assert "git merge-base --is-ancestor" in startup_gate
    assert (
        "baac8e5ecf9f8a2ac66afe2873269bebcbbcbf17 main" in startup_gate
    )
    assert "does not require the Tag to equal" in normalized
    assert "does not require permanent documents to hard-code the live `main` HEAD" in (
        normalized
    )
    assert "does not require another final-status or closure PR" in normalized
    assert "`phase/13-hardening` branch must not already exist" in normalized
    assert "required baseline Ruff, mypy, pytest" in normalized
    assert "explicit user authorization" in normalized
    assert "future merge SHA" not in startup_gate


def test_phase_fourteen_gate_uses_stable_phase_thirteen_ancestor() -> None:
    progress = (PROJECT_ROOT / "docs/codex_progress.md").read_text(encoding="utf-8")
    startup_gate = _section(
        progress,
        "## Phase 14 startup invariant",
        "## Phase 10 implementation checkpoint",
    )
    normalized = " ".join(startup_gate.split())

    assert "PR #39 merge commit" in normalized
    assert PHASE_13_CANONICAL_MERGE in startup_gate
    assert PHASE_13_FINAL_HEAD in startup_gate
    assert "annotated `phase-13-complete` Tag" in normalized
    assert "git merge-base --is-ancestor" in startup_gate
    assert (
        f"{PHASE_13_CANONICAL_MERGE} \\ main" in normalized
    )
    assert "checks ancestry instead of requiring the live `main` HEAD" in normalized
    assert "does not need the number or future merge commit" in normalized
    assert "does not require another Phase 13 status-closure PR" in normalized
    assert "does not require the final Codex Security rescan" in normalized
    assert "`phase/14-final-delivery` does not exist locally or remotely" in normalized
    assert "merged-main baseline checks pass" in normalized
    assert "user explicitly authorizes Phase 14" in normalized
    assert "Phase 14 not started" in normalized
    assert "main` HEAD to remain equal" in normalized
    assert "checkpoint PR" not in startup_gate
