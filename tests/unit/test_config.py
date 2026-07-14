"""Tests for the intentionally small Phase 0 configuration placeholder."""

from pytest import MonkeyPatch

from aegishunt.config import FoundationSettings


def test_environment_uses_default(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.delenv("AEGISHUNT_ENV", raising=False)

    assert FoundationSettings.from_environment().environment == "development"


def test_blank_environment_uses_default(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("AEGISHUNT_ENV", "  ")

    assert FoundationSettings.from_environment().environment == "development"
