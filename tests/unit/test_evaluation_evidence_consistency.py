"""Prevent core fusion evidence from drifting across mentor-facing documents."""

from __future__ import annotations

from pathlib import Path

PROJECT_ROOT = Path(__file__).parents[2]
EVIDENCE_DOCUMENTS = (
    "docs/final_experiment_summary.md",
    "docs/model_cards.md",
    "docs/fusion_policy_card.md",
    "docs/releases/phase-07.md",
    "docs/codex_progress.md",
)


def test_fusion_family_macro_loao_recall_is_consistent() -> None:
    expected = ("0.6000", "0.9333", "0.3333")
    for relative_path in EVIDENCE_DOCUMENTS:
        content = (PROJECT_ROOT / relative_path).read_text(encoding="utf-8")
        windows = [
            part[:500]
            for part in content.split("family-macro")[1:]
        ] + [
            part[:500]
            for part in content.split("Family-macro")[1:]
        ]
        assert any(
            all(value in window for value in expected)
            for window in windows
        ), relative_path


def test_old_incorrect_fusion_loao_value_is_absent_from_core_documents() -> None:
    for relative_path in EVIDENCE_DOCUMENTS:
        content = (PROJECT_ROOT / relative_path).read_text(encoding="utf-8")
        assert "fusion `0.8000`" not in content, relative_path
