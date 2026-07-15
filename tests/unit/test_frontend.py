"""Tests for truthful content in the Phase 1 Streamlit shell."""

from typing import Any

from aegishunt.frontend import app


def test_frontend_renders_phase_status_without_fake_results(monkeypatch: Any) -> None:
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
    assert "Phase 1 data foundation" in content
    assert "SQLite storage foundation" in content
    assert "Research prototype only" in content
    assert "Accuracy" not in content
