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
        active_alerts = client.alerts(limit=1, alert_status="open").total
        critical_alerts = client.alerts(limit=1, severity="critical").total
        open_hypotheses = _open_hypothesis_count(client)
        open_cases = _open_case_count(client)
        ingestion = client.ingestion_jobs(limit=5)
        models = client.models(limit=100)
        demo = client.demo_status()
    except ApiClientError as error:
        api_error(error)
        research_disclaimer()
        return

    active_supervised = next(
        (
            f"{item.version} ({item.state})"
            for item in models.items
            if item.engine == "supervised" and item.active
        ),
        None,
    )
    active_anomaly = next(
        (
            f"{item.version} ({item.state})"
            for item in models.items
            if item.engine == "anomaly" and item.active
        ),
        None,
    )
    fusion = next((item for item in models.items if item.engine == "fusion"), None)
    fusion_policy = (
        None if fusion is None else f"{fusion.version} ({fusion.state})"
    )
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
            "Active supervised model": active_supervised,
            "Active anomaly model": active_anomaly,
            "Fusion policy": fusion_policy,
            "P95 pipeline latency": None,
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
    st.caption(
        "P95 pipeline latency is Unavailable because no verified end-to-end latency "
        "series is currently persisted; no value is inferred from request timing."
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
