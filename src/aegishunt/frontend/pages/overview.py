"""Overview and explicit sample-demo page."""

from __future__ import annotations

from datetime import datetime

import streamlit as st

from aegishunt.frontend.client import AegisHuntApiClient, ApiClientError
from aegishunt.frontend.components import (
    actor_input,
    api_error,
    empty,
    limitation,
    metrics,
    page_header,
    research_disclaimer,
)


def _open_hypothesis_count(client: AegisHuntApiClient) -> int:
    return sum(
        client.hypotheses(limit=1, hypothesis_status=status).total
        for status in ("proposed", "under_review", "needs_more_information")
    )


def _active_alert_count(client: AegisHuntApiClient) -> int:
    return sum(
        client.alerts(limit=1, alert_status=status).total
        for status in ("open", "acknowledged")
    )


def _open_case_count(client: AegisHuntApiClient) -> int:
    return sum(
        client.cases(limit=1, case_status=status).total
        for status in ("open", "investigating", "needs_more_information")
    )


def render(client: AegisHuntApiClient) -> None:
    page_header("Overview", "System health, runtime state, and controlled sample demo")
    st.caption(
        "Controlled synthetic evidence is not a public benchmark or production validation."
    )
    try:
        system = client.system_status()
        runtime = client.runtime_status()
        flows = client.flow_summary()
        recent_alerts = client.alerts(limit=5)
        active_alerts = _active_alert_count(client)
        critical_alerts = client.alerts(limit=1, severity="critical").total
        open_hypotheses = _open_hypothesis_count(client)
        open_cases = _open_case_count(client)
        ingestion = client.ingestion_jobs(limit=5)
        model_state = client.effective_models()
        demo = client.demo_status()
    except ApiClientError as error:
        api_error(error)
        research_disclaimer()
        return

    worker_states = (
        ", ".join(
            f"{status}: {sum(item.status.value == status for item in runtime.status.workers)}"
            for status in sorted({item.status.value for item in runtime.status.workers})
        )
        or "No registered worker"
    )
    latest_ingestion = (
        "No ingestion jobs"
        if not ingestion.items
        else f"{ingestion.items[0].status.value} ({ingestion.items[0].progress:.0%})"
    )

    metrics(
        {
            "Database": system.database,
            "Processed flows": flows.total,
            "Active alerts": active_alerts,
            "Critical alerts": critical_alerts,
            "Open hypotheses": open_hypotheses,
            "Open cases": open_cases,
        }
    )
    metrics(
        {
            "Observed runtime p50 (ms)": runtime.latency.p50_ms,
            "Observed runtime p95 (ms)": runtime.latency.p95_ms,
            "Latency observations (n)": runtime.latency.observation_count,
            "Latency source": runtime.latency.source,
        }
    )
    metrics(
        {
            "Ingestion status": latest_ingestion,
            "Queue length": runtime.status.queue_length,
            "Running jobs": runtime.status.running_jobs,
            "Worker status": worker_states,
        }
    )
    if runtime.latency.status == "unavailable":
        st.info(runtime.latency.unavailable_reason or "Runtime latency is unavailable.")
    st.caption(
        f"{runtime.latency.metric_name} · {runtime.latency.unit} · "
        f"calculated {runtime.latency.calculated_at.isoformat()} · "
        f"{runtime.latency.limitation}"
    )
    st.subheader("Global Active Models")
    if not model_state.global_active_models:
        empty("None. No global model pointer is active.")
    else:
        st.dataframe(
            [
                {
                    "engine": item.engine,
                    "algorithm": "registry bundle",
                    "version": item.version,
                    "status": item.state,
                    "source": "global_active",
                    "artifact_hash": item.checksum,
                }
                for item in model_state.global_active_models
            ],
            use_container_width=True,
            hide_index=True,
        )
    st.subheader("Effective Models for Latest Demo/Runtime Job")
    if not model_state.effective_models:
        empty(model_state.unavailable_reason or "No completed runtime snapshot is available.")
    else:
        st.dataframe(
            [
                {
                    "engine": item.engine_type,
                    "algorithm": item.algorithm,
                    "version": item.version,
                    "status": item.registry_status,
                    "source": item.source,
                    "runtime_job_id": str(item.runtime_job_id),
                    "global_pointer_active": item.global_pointer_active,
                    "artifact_hash": item.artifact_hash,
                    "threshold": item.threshold,
                    "qualification": item.qualification,
                }
                for item in model_state.effective_models
            ],
            use_container_width=True,
            hide_index=True,
        )
        st.caption(
            "These artifacts come from the immutable latest completed runtime-job "
            "snapshot; they do not modify global active pointers."
        )
    limitation(
        "Observed replay progress is non-durable live observation. Durable progress "
        "represents committed evidence; recovery restarts deterministically from origin."
    )
    st.subheader("Recent activity timeline")
    activity: list[tuple[datetime, str]] = []
    activity.extend(
        (
            item.created_at,
            (
                f"SecurityAlert {item.alert_id} · {item.severity.value} · "
                f"{item.status.value}"
            ),
        )
        for item in recent_alerts.items
    )
    activity.extend(
        (
            item.updated_at,
            f"RuntimeJob {item.job_id} · {item.status.value} · {item.current_stage.value}",
        )
        for item in runtime.status.latest_jobs
    )
    for item in ingestion.items:
        occurred_at = item.completed_at or item.started_at
        if occurred_at is not None:
            activity.append(
                (
                    occurred_at,
                    f"IngestionJob {item.job_id} · {item.status.value}",
                )
            )
    if not activity:
        empty("No persisted alert, runtime, or ingestion activity is available.")
    else:
        for occurred_at, description in sorted(
            activity,
            key=lambda item: item[0],
            reverse=True,
        )[:10]:
            st.markdown(f"- `{occurred_at.isoformat()}` — {description}")

    st.subheader("Controlled sample demonstration")
    if not demo.available:
        empty("No checksum-declared packaged samples are available.")
    else:
        with st.form("sample-demo"):
            sample_id = st.selectbox("Packaged sample", demo.sample_ids)
            actor = actor_input("Actor (audit attribution only)")
            reason = st.text_area("Reason")
            create_case = st.checkbox(
                "Create a case if a hypothesis is actually produced",
                value=False,
            )
            confirmed = st.checkbox("I confirm this explicit local demo action")
            submitted = st.form_submit_button("Run controlled demo", type="primary")
        if submitted:
            if not confirmed:
                st.error("Explicit confirmation is required.")
            else:
                try:
                    result = client.run_demo(
                        sample_id,
                        actor=actor,
                        reason=reason,
                        create_case=create_case,
                    )
                    st.success(f"Demo state: {result.state}")
                    st.json(result.model_dump(mode="json"))
                except ApiClientError as error:
                    api_error(error)
    research_disclaimer()
