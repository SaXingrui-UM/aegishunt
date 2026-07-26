"""System Health and runtime-control page."""

from __future__ import annotations

import streamlit as st

from aegishunt.frontend.client import AegisHuntApiClient, ApiClientError
from aegishunt.frontend.components import actor_input, api_error, metrics, page_header, table


def render(client: AegisHuntApiClient) -> None:
    page_header("System Health", "Database, workers, runtime queue, and resource evidence")
    try:
        system = client.system_status()
        runtime = client.runtime_status()
        workers = client.runtime_workers()
        jobs = client.runtime_jobs()
    except ApiClientError as error:
        api_error(error)
        return
    metrics(
        {
            "Database": system.database,
            "Schema": system.schema_version,
            "Queued": runtime.status.queue_length,
            "Running": runtime.status.running_jobs,
            "Workers": workers.total,
        }
    )
    st.caption(
        "Live capture: disabled · Automatic recovery: disabled · Recovery: "
        "explicit deterministic restart from origin · Model loading: "
        f"{runtime.status.model_loading_state}"
    )
    sample = runtime.status.latest_samples[0] if runtime.status.latest_samples else None
    metrics(
        {
            "Process CPU %": None if sample is None else sample.process_cpu_percent,
            "Process RSS bytes": None if sample is None else sample.process_rss_bytes,
            "Threads": None if sample is None else sample.thread_count,
            "Heartbeat age (s)": (
                None if sample is None else sample.worker_heartbeat_age_seconds
            ),
        }
    )
    table(
        (
            {
                "worker_id": item.worker_id,
                "status": item.status.value,
                "current_job_id": (
                    None if item.current_job_id is None else str(item.current_job_id)
                ),
                "heartbeat_at": item.heartbeat_at,
                "model_load_state": item.model_load_state,
                "latest_error": item.latest_error_summary,
            }
            for item in workers.items
        ),
        empty_message="No worker process is registered; resource metrics are unavailable.",
    )
    table(
        (
            {
                "job_id": str(item.job_id),
                "status": item.status.value,
                "stage": item.current_stage.value,
                "observed_progress": item.observed_progress,
                "durable_progress": item.progress,
                "attempt": item.current_attempt_number,
                "runtime_policy": item.runtime_policy_version,
                "error": item.failure_message,
            }
            for item in jobs.items
        ),
        empty_message="No runtime jobs are registered.",
    )
    st.caption(
        "Observed progress is non-durable. Recovery restarts from origin and reuses "
        "committed evidence; it is not exact packet-cursor resume."
    )
    if runtime.status.latest_errors:
        st.subheader("Latest sanitized runtime errors")
        table(
            runtime.status.latest_errors,
            empty_message="No runtime error evidence is available.",
        )
    if jobs.items:
        with st.form("runtime-control"):
            job_id = st.selectbox("Runtime job", [str(item.job_id) for item in jobs.items])
            action = st.selectbox("Action", ("pause", "resume", "recover"))
            actor = actor_input()
            reason = st.text_area("Reason")
            confirm = st.checkbox("Confirm runtime action")
            submitted = st.form_submit_button("Apply runtime action")
        if submitted and confirm:
            try:
                result = client.runtime_action(
                    job_id,
                    action,
                    actor=actor,
                    reason=reason,
                )
                st.success(f"Runtime job state: {result.status.value}")
            except ApiClientError as error:
                api_error(error)
