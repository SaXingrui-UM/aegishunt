"""Truthful Streamlit shell for the Phase 11 runtime checkpoint."""

from __future__ import annotations

import streamlit as st
from sqlalchemy.exc import SQLAlchemyError

from aegishunt.config import load_settings
from aegishunt.errors import AegisHuntError
from aegishunt.metadata import APPLICATION_DESCRIPTION, APPLICATION_NAME
from aegishunt.runtime.contracts import RuntimeStatus
from aegishunt.runtime.status import RuntimeStatusReader
from aegishunt.storage import Database

PLANNED_MODULES = (
    "Public benchmark acquisition and validated label joining",
    "Complete Cases API and Streamlit investigation workspace",
    "Unified Phase 12 API and frontend workflow",
    "Model activation and controlled retraining",
)


def _read_runtime_status() -> RuntimeStatus | None:
    """Read persisted runtime state or return explicit UI-unavailable semantics."""

    database: Database | None = None
    try:
        settings = load_settings()
        database = Database(settings.database)
        database.initialize()
        return RuntimeStatusReader(database).read()
    except (AegisHuntError, SQLAlchemyError):
        return None
    finally:
        if database is not None:
            database.dispose()


def _runtime_summary(status: RuntimeStatus) -> str:
    workers = len(status.workers)
    available_samples = sum(
        sample.sampler_available for sample in status.latest_samples
    )
    latest = (
        "latest_job=none"
        if not status.latest_jobs
        else (
            f"latest_job={status.latest_jobs[0].job_id}, "
            f"stage={status.latest_jobs[0].current_stage.value}, "
            f"attempt={status.latest_jobs[0].current_attempt_number}, "
            f"progress_mode={status.latest_jobs[0].progress_mode.value}, "
            f"progress={status.latest_jobs[0].progress:.6f}"
        )
    )
    return (
        "Runtime status: "
        f"queued={status.queue_length}, running={status.running_jobs}, "
        f"paused={status.paused_jobs}, recovery_pending={status.recovery_pending}, "
        f"workers={workers}, resource_samples_available={available_samples}, "
        f"{latest}. "
        "Models and policies are verified per job before packet replay; automatic "
        "recovery and live capture are disabled."
    )


def main() -> None:
    """Render Phase 11 state without inventing jobs, resources, or detections."""

    st.set_page_config(page_title=APPLICATION_NAME, page_icon="🛡️", layout="wide")
    st.title(APPLICATION_NAME)
    st.caption(APPLICATION_DESCRIPTION)
    st.info(
        "Current status: Phase 11 implementation complete — awaiting PR review. "
        "The supported runtime is offline, rootless PCAP replay on a single SQLite "
        "node. Phase 12: Not started."
    )
    runtime_status = _read_runtime_status()
    if runtime_status is None:
        st.warning(
            "Runtime status is unavailable. No zero-valued resource measurements, "
            "queue counts, job results, or worker state are fabricated."
        )
    else:
        st.info(_runtime_summary(runtime_status))
    st.success(
        "Recommendation: Inconclusive. The controlled experiment did not establish a "
        "fusion advantage; fusion family-macro LOAO Recall was lower than anomaly-only, "
        "and held-out exfiltration and reconnaissance rows were missed. Negative results "
        "are retained."
    )
    st.info(
        "Phase 8 implements configuration-controlled operational risk, severity, "
        "threshold-gated SecurityAlert records, evidence-backed reason codes, "
        "non-causal global/local explanations, and audited analyst verdicts. Risk is "
        "not attack probability; severity is not certainty; alerts are not confirmed "
        "attacks. No runtime alert records or metrics are fabricated on this page."
    )
    st.info(
        "Phase 9 adds bounded event-time alert correlation and deterministic proposed "
        "hunting hypotheses. Correlation and confidence are non-probabilistic triage "
        "scores; a hypothesis is a reviewable lead, not a fact or confirmed attack. "
        "Suggested queries are structured data only and are never executed by the core."
    )
    st.info(
        "Phase 10 adds deterministic InvestigationCase creation, audited lifecycle and "
        "append-only notes, typed evidence snapshots, analyst verdict/feedback, and "
        "checksummed data-only exports. A Case is not a confirmed attack; priority is "
        "triage, feedback may be noisy, and a Case verdict is not propagated to all "
        "related flows. Retraining candidates require manual review and never train, "
        "activate, or replace a model. No case counts or feedback metrics are fabricated."
    )
    st.info(
        "Phase 11 adds a persistent RuntimeJob queue, atomic claim and lease ownership, "
        "explicit pause/resume/recovery, interruptible event-time replay, verified "
        "artifact pinning, transactional flow/detection output ledgers, worker health, "
        "and bounded resource samples. Recovery deterministically restarts from packet "
        "zero and reuses committed evidence; it is not exact packet-cursor resume. "
        "No live capture, external target, automatic recovery, or Phase 12 workflow is "
        "enabled."
    )
    st.subheader("Planned system modules")
    for module in PLANNED_MODULES:
        st.markdown(f"- {module}")
    st.warning(
        "Research prototype only. This is controlled synthetic pipeline verification—"
        "not a public benchmark, production validation, real-world performance result, "
        "or proof of zero-day detection. AegisHunt does not confirm attacks or perform "
        "automated response actions. Fusion score is not probability, risk, severity, "
        "or attack confirmation."
    )


if __name__ == "__main__":
    main()
