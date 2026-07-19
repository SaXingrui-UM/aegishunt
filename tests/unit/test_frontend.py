"""Tests for truthful post-merge content in the Phase 6 Streamlit shell."""

from typing import Any

from aegishunt.frontend import app


def test_frontend_renders_closed_phase_six_without_fake_results(monkeypatch: Any) -> None:
    rendered: list[str] = []
    monkeypatch.setattr(app.st, "set_page_config", lambda **kwargs: None)
    monkeypatch.setattr(app.st, "title", rendered.append)
    monkeypatch.setattr(app.st, "caption", rendered.append)
    monkeypatch.setattr(app.st, "info", rendered.append)
    monkeypatch.setattr(app.st, "success", rendered.append)
    monkeypatch.setattr(app.st, "subheader", rendered.append)
    monkeypatch.setattr(app.st, "markdown", rendered.append)
    monkeypatch.setattr(app.st, "warning", rendered.append)

    app.main()

    content = "\n".join(rendered)
    assert "AegisHunt" in content
    assert "Phase 6 complete" in content
    assert "PR #18" in content and "PR #19" in content
    assert "phase-06-complete" in content
    assert "awaiting PR review" not in content
    assert "Phase 7: Not started" in content
    assert "anomaly training" in content
    assert "fusion" in content
    assert "Research prototype only" in content
    assert "Accuracy" not in content
    assert "SecurityAlert" not in content
