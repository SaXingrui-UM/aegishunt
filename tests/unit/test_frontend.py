"""Tests for truthful completed Phase 11 content in Streamlit."""

from typing import Any

from aegishunt.frontend import app
from aegishunt.runtime.contracts import RuntimeStatus
from tests.fixtures.runtime import runtime_job


def test_frontend_renders_phase_eleven_runtime_without_fake_results(
    monkeypatch: Any,
) -> None:
    rendered: list[str] = []
    monkeypatch.setattr(app.st, "set_page_config", lambda **kwargs: None)
    monkeypatch.setattr(app.st, "title", rendered.append)
    monkeypatch.setattr(app.st, "caption", rendered.append)
    monkeypatch.setattr(app.st, "info", rendered.append)
    monkeypatch.setattr(app.st, "success", rendered.append)
    monkeypatch.setattr(app.st, "subheader", rendered.append)
    monkeypatch.setattr(app.st, "markdown", rendered.append)
    monkeypatch.setattr(app.st, "warning", rendered.append)
    monkeypatch.setattr(
        app,
        "_read_runtime_status",
        lambda: RuntimeStatus(
            queue_length=2,
            recovery_pending=1,
            running_jobs=1,
            paused_jobs=0,
            latest_jobs=(runtime_job(),),
            workers=(),
            latest_samples=(),
            latest_errors=(),
            model_loading_state="verified_per_job_preflight",
            live_capture_enabled=False,
            automatic_recovery=False,
        ),
    )

    app.main()

    content = "\n".join(rendered)
    assert "AegisHunt" in content
    assert "Phase 11 complete" in content
    assert "PR #33 is merged" in content
    assert "phase-11-complete checkpoint is verified" in content
    assert "Phase 12: Not started" in content
    assert "awaiting PR review" not in content
    assert "queued=2" in content
    assert "running=1" in content
    assert "recovery_pending=1" in content
    assert "stage=queued" in content
    assert "attempt=0" in content
    assert "progress_mode=indeterminate" in content
    assert "Observed replay progress (non-durable)=0.000000" in content
    assert "Durable committed evidence=0.000000" in content
    assert "not a checkpoint or resume cursor" in content
    assert "automatic recovery and live capture are disabled" in content
    assert "deterministically restarts from packet zero" in content
    assert "not exact packet-cursor resume" in content
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
    assert "phase/10-case-feedback" not in content
    assert "pending merge" not in content
    assert "Accuracy" not in content
    assert "SecurityAlert" in content


def test_frontend_does_not_fabricate_unavailable_runtime_status(
    monkeypatch: Any,
) -> None:
    rendered: list[str] = []
    monkeypatch.setattr(app.st, "set_page_config", lambda **kwargs: None)
    monkeypatch.setattr(app.st, "title", rendered.append)
    monkeypatch.setattr(app.st, "caption", rendered.append)
    monkeypatch.setattr(app.st, "info", rendered.append)
    monkeypatch.setattr(app.st, "success", rendered.append)
    monkeypatch.setattr(app.st, "subheader", rendered.append)
    monkeypatch.setattr(app.st, "markdown", rendered.append)
    monkeypatch.setattr(app.st, "warning", rendered.append)
    monkeypatch.setattr(app, "_read_runtime_status", lambda: None)

    app.main()

    content = "\n".join(rendered)
    assert "Runtime status is unavailable" in content
    assert "No zero-valued resource measurements" in content
    assert "queued=0" not in content


def test_runtime_summary_has_truthful_empty_state_without_fake_progress() -> None:
    summary = app._runtime_summary(  # noqa: SLF001 - frontend status contract
        RuntimeStatus(
            queue_length=0,
            recovery_pending=0,
            running_jobs=0,
            paused_jobs=0,
            latest_jobs=(),
            workers=(),
            latest_samples=(),
            latest_errors=(),
            model_loading_state="verified_per_job_preflight",
            live_capture_enabled=False,
            automatic_recovery=False,
        )
    )

    assert "latest_job=none" in summary
    assert "Observed replay progress (non-durable)=" not in summary
    assert "Durable committed evidence=" not in summary
    assert "queued=0" in summary
    assert "not a checkpoint or resume cursor" in summary
