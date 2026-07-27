"""Regression tests for the Phase 12 implementation checkpoint."""

from pathlib import Path

PROJECT_ROOT = Path(__file__).parents[2]


def _section(content: str, start: str, end: str) -> str:
    """Return one explicitly bounded Markdown section."""
    return content.split(start, maxsplit=1)[1].split(end, maxsplit=1)[0]


def test_readme_records_phase_twelve_without_starting_phase_thirteen() -> None:
    content = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    current = _section(content, "## Current status", "## Planned architecture")
    normalized = " ".join(current.split())

    assert "Phases 0–11 are complete" in current
    assert "Phase 11 PR [#33]" in current
    assert "is merged as" in normalized
    assert "8f85949406e3db7d2fa2b3c48d04e832e84f3559" in current
    assert "phase-11-complete" in current
    assert "Implementation complete — awaiting PR review" in normalized
    assert "phase/12-api-frontend" in normalized
    assert "Phase 13 is **Not started**" in normalized
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
    ):
        assert transient not in current
    assert "No operation trains, activates, or replaces a model" in normalized
    assert "retraining_candidate" in normalized


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


def test_progress_and_release_record_phase_twelve_without_phase_thirteen_scope() -> None:
    progress = (PROJECT_ROOT / "docs/codex_progress.md").read_text(encoding="utf-8")
    release = (PROJECT_ROOT / "docs/releases/phase-12.md").read_text(encoding="utf-8")

    progress_current = _section(
        progress,
        "## Current state",
        "## Phase 12 implementation checkpoint",
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
        assert "Implementation complete — awaiting PR review" in content
        assert "Phase 13" in content and "not started" in content.lower()

    assert "Current phase | Phase 12" in normalized_progress_current
    assert "Status | Implementation complete — awaiting PR review" in (
        normalized_progress_current
    )
    assert "Phase 10 status | Phase complete" in normalized_progress_current
    assert "Phase 11 status | Phase complete" in normalized_progress_current
    assert "Phase 12 status | Implementation complete — awaiting PR review" in (
        normalized_progress_current
    )
    assert "Phase 13 status | Not started" in normalized_progress_current
    assert "Phase 12 acceptance corrections are complete" in (
        normalized_progress_current
    )
    assert "PR [#35]" in normalized_progress_current
    assert "pull/35" in normalized_progress_current
    assert "refreshed required CI passing" in normalized_progress_current
    assert "PR #35 heads `4226ccb` and `f8a464d` exposed" in (
        normalized_progress_current
    )
    assert "both required GitHub Actions `quality` jobs passed" in progress_current
    assert "all 458 tests at 85.46% branch-aware coverage" in progress_current
    assert "phase-11-complete" in progress_current
    assert "8f85949406e3db7d2fa2b3c48d04e832e84f3559" in progress_current

    assert "Status: **Implementation complete — awaiting PR review**" in release_current
    assert "Pull request: [#35]" in normalized_release_current
    assert "pull/35" in normalized_release_current
    assert "open and ready for review" in normalized_release_current
    assert "Completion tag: pending" in normalized_release_current
    assert "Phase 13: Not started" in normalized_release_current

    assert "ADR 0021" in release
    assert "API-only frontend boundary" in release
    assert "458 passed, 0 failed" in release
    assert "85.40%" in release
    assert "HTTP 422" in release
    assert "`f8a464d`" in release
    assert "`f98a593`" in release
    assert "all 458 tests" in release
    assert "85.46% branch-aware coverage" in normalized_release
    assert "portable selection policy" in release
    assert "isolated `12.0.0` model identity" in release
    assert "shared previous/next pagination" in release
    assert "worker run-once" in release
    assert "Phase 13 performance" in release

    for current in (progress_current, release_current):
        for transient in (
            "PR #33 remains open",
            "must pass before merge",
            "Phase 11 remains unmerged",
            "Wait for PR #33",
            "Current branch | `phase/11-runtime-replay`",
            "Phase 13 implementation complete",
            "Phase 13 is in progress",
            "phase/13-hardening` (created",
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
        "## Phase 12 startup invariant",
        "## Phase 10 implementation checkpoint",
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
