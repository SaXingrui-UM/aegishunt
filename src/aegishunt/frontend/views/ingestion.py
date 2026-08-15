"""Data ingestion and replay-control view."""

from __future__ import annotations

import streamlit as st

from aegishunt.api.contracts import RuntimeRunOnceResult
from aegishunt.frontend.client import AegisHuntApiClient, ApiClientError
from aegishunt.frontend.components import (
    actor_input,
    api_error,
    empty,
    page_header,
    paginated_table,
    pagination_offset,
)
from aegishunt.runtime.contracts import RuntimeJob

_TRACKED_RUNTIME_JOB_KEY = "aegishunt-runtime-worker-job-id"


def _worker_result_message(result: RuntimeRunOnceResult) -> str:
    """Explain which worker, if any, won the atomic queued-job claim."""

    worker_id = result.worker.worker_id
    if result.outcome == "job_claimed_by_request_worker":
        return f"Worker {worker_id} claimed one job, finished its cycle, and stopped."
    if result.outcome == "job_already_claimed_by_another_worker":
        return (
            f"Worker {worker_id} did not duplicate an existing claim: another worker "
            "already claimed available work and is processing it independently."
        )
    if result.outcome == "job_queued_after_cycle":
        return (
            f"Worker {worker_id} stopped before a new job entered the queue; the "
            "background worker can process it, or run another bounded cycle."
        )
    return f"Worker {worker_id} found no queued or active job and stopped."


def _render_runtime_job_status(job: RuntimeJob | None) -> None:
    """Persistently show the job associated with the last manual worker cycle."""

    if job is None:
        return
    message = f"Runtime job {job.job_id} · status {job.status.value}"
    if job.status.value == "completed":
        st.success(message)
    elif job.status.value == "failed":
        st.error(message)
    else:
        st.info(message)


def render(client: AegisHuntApiClient) -> None:
    page_header("Data Ingestion", "Bounded PCAP/CSV/JSON upload and offline replay")
    upload_tab, sample_tab, replay_tab, jobs_tab = st.tabs(
        ("Upload", "Packaged sample", "Replay", "Jobs")
    )
    with upload_tab:
        st.caption(
            "Configured upload limits are enforced while Phase 2 streams data into "
            "checksum-addressed storage. Original filenames never become storage paths."
        )
        with st.form("telemetry-upload"):
            kind = st.selectbox("Telemetry type", ("pcap", "csv", "json"))
            uploaded = st.file_uploader(
                "Telemetry file",
                type=[kind, "pcapng", "jsonl"],
            )
            actor = actor_input(key="upload-actor")
            reason = st.text_area("Reason", key="upload-reason")
            confirm = st.checkbox("Confirm bounded telemetry upload")
            submitted = st.form_submit_button(
                "Upload telemetry",
                type="primary",
            )
        if submitted and uploaded is None:
            st.warning("Choose a telemetry file before submitting the upload.")
        elif submitted and not confirm:
            st.warning("Confirm the bounded telemetry upload before submitting.")
        elif submitted:
            assert uploaded is not None
            try:
                job = client.upload(
                    kind,
                    filename=uploaded.name,
                    stream=uploaded,
                    content_type=uploaded.type or "application/octet-stream",
                    actor=actor,
                    reason=reason,
                )
                st.success(f"Ingestion job {job.job_id}: {job.status.value}")
            except ApiClientError as error:
                api_error(error)
    with sample_tab:
        try:
            samples = client.samples()
        except ApiClientError as error:
            api_error(error)
            samples = []
        if samples:
            with st.form("sample-ingestion"):
                sample_id = st.selectbox(
                    "Allowlisted sample",
                    [item.sample_id for item in samples],
                )
                actor = actor_input(key="sample-actor")
                reason = st.text_area("Reason", key="sample-reason")
                confirm = st.checkbox("Confirm sample ingestion")
                submitted = st.form_submit_button("Ingest sample")
            if submitted and confirm:
                try:
                    result = client.ingest_sample(
                        sample_id,
                        actor=actor,
                        reason=reason,
                    )
                    st.success(f"Source {result.job_id} is {result.status.value}.")
                except ApiClientError as error:
                    api_error(error)
        else:
            empty("No packaged sample is available.")
    with replay_tab:
        try:
            source_page = client.telemetry_sources(
                offset=pagination_offset("ingestion-sources")
            )
            sources = source_page.items
        except ApiClientError as error:
            api_error(error)
            sources = []
            source_page = None
        if sources:
            assert source_page is not None
            paginated_table(
                source_page,
                (
                    {
                        "source_id": str(item.source_id),
                        "type": item.source_type.value,
                        "status": item.status.value,
                        "filename": item.filename_or_interface,
                        "records": item.records_processed,
                    }
                    for item in sources
                ),
                key="ingestion-sources",
                empty_message="No stored telemetry sources are available.",
            )
            with st.form("replay-create"):
                source_id = st.selectbox("Stored source", [str(item.source_id) for item in sources])
                speed = st.number_input("Replay speed", min_value=0.01, value=1.0)
                actor = actor_input(key="replay-actor")
                reason = st.text_area("Reason", key="replay-reason")
                confirm = st.checkbox("Confirm replay-job creation")
                submitted = st.form_submit_button("Create replay job")
            if submitted and confirm:
                try:
                    runtime_job = client.create_replay(
                        source_id,
                        speed=float(speed),
                        actor=actor,
                        reason=reason,
                    )
                    st.success(
                        f"Runtime job {runtime_job.job_id} queued; worker was not auto-run."
                    )
                except ApiClientError as error:
                    api_error(error)
        else:
            empty("No stored source can be replayed.")
    with jobs_tab:
        try:
            jobs = client.ingestion_jobs(
                offset=pagination_offset("ingestion-jobs")
            )
            runtime_jobs = client.runtime_jobs(
                offset=pagination_offset("ingestion-runtime-jobs")
            )
            paginated_table(
                jobs,
                (
                    {
                        "job_id": str(item.job_id),
                        "type": item.source_type.value,
                        "status": item.status.value,
                        "progress": item.progress,
                        "records": item.records_processed,
                        "error": None if item.error is None else item.error.message,
                    }
                    for item in jobs.items
                ),
                key="ingestion-jobs",
                empty_message="No ingestion jobs are present.",
            )
            st.subheader("Replay runtime jobs")
            paginated_table(
                runtime_jobs,
                (
                    {
                        "job_id": str(item.job_id),
                        "status": item.status.value,
                        "observed_progress": item.observed_progress,
                        "durable_progress": item.progress,
                        "attempt": item.current_attempt_number,
                    }
                    for item in runtime_jobs.items
                ),
                key="ingestion-runtime-jobs",
                empty_message="No runtime replay jobs are present.",
            )
            tracked_runtime_job = None
            tracked_runtime_job_id = st.session_state.get(_TRACKED_RUNTIME_JOB_KEY)
            if isinstance(tracked_runtime_job_id, str):
                try:
                    tracked_runtime_job = client.runtime_job(
                        tracked_runtime_job_id
                    ).job
                except ApiClientError as error:
                    api_error(error)
            with st.form("runtime-run-once"):
                worker_actor = actor_input(key="runtime-worker-actor")
                worker_reason = st.text_area(
                    "Reason",
                    key="runtime-worker-reason",
                )
                worker_confirm = st.checkbox(
                    "Confirm one bounded worker cycle; it will claim at most one job"
                )
                worker_submitted = st.form_submit_button("Run one worker")
            if worker_submitted and worker_confirm:
                try:
                    worker_result = client.run_runtime_worker_once(
                        actor=worker_actor,
                        reason=worker_reason,
                    )
                    message = _worker_result_message(worker_result)
                    if worker_result.outcome == "job_claimed_by_request_worker":
                        st.success(message)
                    elif worker_result.outcome == "job_queued_after_cycle":
                        st.warning(message)
                    else:
                        st.info(message)
                    if worker_result.job is not None:
                        tracked_runtime_job = worker_result.job
                        st.session_state[_TRACKED_RUNTIME_JOB_KEY] = str(
                            worker_result.job.job_id
                        )
                except ApiClientError as error:
                    api_error(error)
            _render_runtime_job_status(tracked_runtime_job)
            if runtime_jobs.items:
                with st.form("runtime-control"):
                    selected_job = st.selectbox(
                        "Runtime job",
                        [str(item.job_id) for item in runtime_jobs.items],
                    )
                    action = st.selectbox("Action", ("pause", "resume", "recover"))
                    actor = actor_input(key="runtime-action-actor")
                    reason = st.text_area("Reason", key="runtime-action-reason")
                    confirm = st.checkbox(
                        "Confirm explicit runtime action; recovery restarts from origin"
                    )
                    submitted = st.form_submit_button("Apply runtime action")
                if submitted and confirm:
                    try:
                        updated = client.runtime_action(
                            selected_job,
                            action,
                            actor=actor,
                            reason=reason,
                        )
                        st.success(f"Runtime job is now {updated.status.value}.")
                    except ApiClientError as error:
                        api_error(error)
        except ApiClientError as error:
            api_error(error)
