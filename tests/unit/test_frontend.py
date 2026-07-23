"""Tests for truthful completed Phase 10 content in Streamlit."""

from typing import Any

from aegishunt.frontend import app


def test_frontend_renders_phase_ten_without_fake_results(monkeypatch: Any) -> None:
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
    assert "Phase 10 complete" in content
    assert "PR #31 is merged" in content
    assert "phase-10-complete is verified" in content
    assert "Phase 11: Not started" in content
    assert "Recommendation: Inconclusive" in content
    assert "deterministic proposed" in content
    assert "not a fact or confirmed attack" in content
    assert "never executed" in content
    assert "A Case is not a confirmed attack" in content
    assert "priority is triage" in content
    assert "feedback may be noisy" in content
    assert "not propagated to all related flows" in content
    assert "never train, activate, or replace a model" in content
    assert "No case counts or feedback metrics are fabricated" in content
    assert "did not establish a fusion advantage" in content
    assert "LOAO Recall was lower than anomaly-only" in content
    assert "held-out exfiltration and reconnaissance" in content
    assert "Negative results are retained" in content
    assert "controlled synthetic pipeline verification" in content
    assert "not a public benchmark, production validation" in content
    assert "proof of zero-day detection" in content
    assert "Fusion score is not probability, risk, severity, or attack confirmation" in content
    assert "Risk is not attack probability" in content
    assert "alerts are not confirmed attacks" in content
    assert "non-causal global/local explanations" in content
    assert "Research prototype only" in content
    assert "awaiting PR review" not in content
    assert "phase/10-case-feedback" not in content
    assert "pending merge" not in content
    assert "Phase 11 implementation" not in content
    assert "Accuracy" not in content
    assert "SecurityAlert" in content
