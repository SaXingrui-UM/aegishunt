"""Regression tests for the portable Phase 13 CI security contract."""

from pathlib import Path

PROJECT_ROOT = Path(__file__).parents[2]


def test_development_environment_pins_a_non_vulnerable_setuptools() -> None:
    pyproject = (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert pyproject.count('"setuptools>=83.0.0,<84.0.0"') == 2


def test_ci_uses_portable_pytest_module_invocation() -> None:
    workflow = (PROJECT_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    assert workflow.count("python -m pytest") == 5
    assert "\n        run: pytest" not in workflow


def test_ci_does_not_require_unsupported_github_dependency_review() -> None:
    workflow = (PROJECT_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    assert "actions/dependency-review-action" not in workflow
    assert "\n  dependency-review:" not in workflow
    assert "scripts.run_phase13_security" in workflow
