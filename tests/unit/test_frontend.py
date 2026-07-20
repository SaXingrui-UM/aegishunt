"""Tests for truthful Phase 7 content in the Streamlit shell."""

from typing import Any

from aegishunt.frontend import app


def test_frontend_renders_phase_seven_without_fake_results(monkeypatch: Any) -> None:
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
    assert "Phase 7 complete" in content
    assert "PR #21 and PR #22 are merged" in content
    assert "phase-07-complete" in content
    assert "Recommendation: Inconclusive" in content
    assert "Phase 8: Not started" in content
    assert "did not establish a fusion advantage" in content
    assert "LOAO Recall was lower than anomaly-only" in content
    assert "held-out exfiltration and reconnaissance" in content
    assert "Negative results are retained" in content
    assert "controlled synthetic pipeline verification" in content
    assert "not a public benchmark, production validation" in content
    assert "proof of zero-day detection" in content
    assert "Fusion score is not probability, risk, severity, or attack confirmation" in content
    assert "Research prototype only" in content
    assert "awaiting PR review" not in content
    assert "pending merge" not in content
    assert "Phase 8 implementation" not in content
    assert "Accuracy" not in content
    assert "SecurityAlert" not in content
