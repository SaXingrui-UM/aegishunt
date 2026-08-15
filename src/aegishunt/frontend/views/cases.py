"""Investigation Cases and analyst feedback view."""

from __future__ import annotations

import streamlit as st

from aegishunt.frontend.client import AegisHuntApiClient, ApiClientError
from aegishunt.frontend.components import (
    actor_input,
    api_error,
    page_header,
    paginated_table,
    pagination_offset,
    runtime_job_filter,
    table,
)


def render(client: AegisHuntApiClient) -> None:
    page_header("Cases", "Analyst-controlled investigations, evidence, notes, and feedback")
    try:
        job_id = runtime_job_filter(client)
        cases = client.cases(
            job_id=job_id,
            offset=pagination_offset("cases-records", scope=job_id or "all"),
        )
    except ApiClientError as error:
        api_error(error)
        return
    paginated_table(
        cases,
        (
            {
                "case_id": str(item.case_id),
                "title": item.title,
                "priority": item.priority.value,
                "status": item.status.value,
                "assigned_to": item.assigned_to,
                "verdict": item.verdict,
            }
            for item in cases.items
        ),
        key="cases-records",
        empty_message="No investigation cases are available.",
    )
    if not cases.items:
        st.caption("Cases are created explicitly from eligible threat hypotheses.")
        return
    selected = st.selectbox("Inspect case", [str(item.case_id) for item in cases.items])
    try:
        detail = client.case(selected)
    except ApiClientError as error:
        api_error(error)
        return
    overview, notes_tab, evidence_tab, feedback_tab, audit_tab, report_tab = st.tabs(
        ("Overview", "Notes", "Evidence", "Feedback", "Audit History", "Close & report")
    )
    with overview:
        st.json(detail.case.model_dump(mode="json"))
        st.caption("A case is an analyst workflow object, not a confirmed attack.")
        with st.form("case-update"):
            action = st.selectbox(
                "Update",
                ("status", "priority", "assignment", "verdict"),
            )
            value = st.text_input(
                "Value",
                help=(
                    "Status: open/investigating/needs_more_information; "
                    "priority: low/medium/high/critical; assignment: analyst or blank; "
                    "verdict: true_positive/false_positive/benign_expected/"
                    "needs_more_information"
                ),
            )
            confidence = st.number_input(
                "Verdict confidence",
                min_value=0.0,
                max_value=1.0,
                value=0.5,
            )
            actor = actor_input(key="case-update-actor")
            reason = st.text_area("Reason", key="case-update-reason")
            confirm = st.checkbox("Confirm case lifecycle update")
            replace_existing_verdict = st.checkbox(
                "Confirm modification of existing Case verdict",
                disabled=detail.case.verdict is None,
                help=(
                    "Required only when the selected update replaces the Case verdict "
                    f"currently recorded as {detail.case.verdict.value!r}."
                    if detail.case.verdict is not None
                    else "No Case verdict is currently recorded."
                ),
            )
            submitted = st.form_submit_button("Update case")
        if submitted and confirm:
            if (
                action == "verdict"
                and detail.case.verdict is not None
                and not replace_existing_verdict
            ):
                st.error(
                    "Confirm modification of existing Case verdict before replacing it."
                )
            else:
                update: dict[str, object]
                if action == "assignment":
                    update = {"assigned_to": value or None}
                elif action == "verdict":
                    update = {
                        "verdict": value,
                        "verdict_confidence": float(confidence),
                        "confirm_verdict_replacement": replace_existing_verdict,
                    }
                else:
                    update = {action: value}
                try:
                    updated = client.update_case(
                        selected,
                        actor=actor,
                        reason=reason,
                        **update,
                    )
                    st.success(f"Case updated: {updated.status.value}.")
                except ApiClientError as error:
                    api_error(error)
    with notes_tab:
        table(
            (
                {
                    "created_at": item.created_at,
                    "author": item.author,
                    "type": item.note_type,
                    "body": item.body,
                }
                for item in detail.notes
            ),
            empty_message="No notes have been appended.",
        )
        with st.form("case-note"):
            body = st.text_area("New note")
            actor = actor_input()
            reason = st.text_area("Reason")
            confirm = st.checkbox("Confirm append-only note")
            submitted = st.form_submit_button("Add note")
        if submitted and confirm:
            try:
                note = client.add_case_note(
                    selected,
                    body=body,
                    actor=actor,
                    reason=reason,
                )
                st.success(f"Note {note.note_id} appended.")
            except ApiClientError as error:
                api_error(error)
    with evidence_tab:
        table(
            (
                {
                    "type": item.object_type.value,
                    "object_id": item.object_id,
                    "checksum": item.snapshot_checksum,
                    "description": item.description,
                }
                for item in detail.evidence
            ),
            empty_message="No additional evidence references are present.",
        )
        with st.form("case-evidence"):
            object_type = st.selectbox(
                "Evidence type",
                (
                    "network_flow",
                    "detection_result",
                    "security_alert",
                    "alert_group",
                    "threat_hypothesis",
                ),
            )
            object_id = st.text_input("Evidence object ID")
            description = st.text_area("Evidence description")
            actor = actor_input(key="evidence-actor")
            reason = st.text_area("Reason", key="evidence-reason")
            confirm = st.checkbox("Confirm immutable evidence reference")
            submitted = st.form_submit_button("Add evidence reference")
        if submitted and confirm:
            try:
                reference = client.add_case_evidence(
                    selected,
                    object_type=object_type,
                    object_id=object_id,
                    description=description,
                    actor=actor,
                    reason=reason,
                )
                st.success(f"Evidence {reference.reference_id} appended.")
            except ApiClientError as error:
                api_error(error)
    with feedback_tab:
        table(
            (
                {
                    "feedback_id": str(item.feedback_id),
                    "verdict": item.verdict.value,
                    "confidence": item.confidence,
                    "actor": item.actor,
                    "notes": item.notes,
                }
                for item in detail.feedback
            ),
            empty_message="No human feedback is recorded.",
        )
        st.caption("Analyst feedback is human-supplied and may be noisy.")
        with st.form("case-feedback"):
            verdict = st.selectbox(
                "Feedback verdict",
                (
                    "true_positive",
                    "false_positive",
                    "benign_expected",
                    "needs_more_information",
                ),
            )
            confidence = st.slider("Confidence", 0.0, 1.0, 0.5)
            notes = st.text_area("Feedback notes")
            actor = actor_input(key="feedback-actor")
            reason = st.text_area("Reason", key="feedback-reason")
            confirm = st.checkbox("Confirm human-supplied feedback")
            submitted = st.form_submit_button("Record feedback")
        if submitted and confirm:
            try:
                feedback = client.add_feedback(
                    "cases",
                    selected,
                    verdict=verdict,
                    confidence=confidence,
                    notes=notes,
                    actor=actor,
                    reason=reason,
                )
                st.success(f"Feedback {feedback.feedback_id} recorded.")
            except ApiClientError as error:
                api_error(error)
    with audit_tab:
        st.caption(
            "Read-only, append-only audit history from the same persisted audit records "
            "used by case, note, feedback, and report services."
        )
        action_filter = st.text_input(
            "Action filter (exact)",
            key="case-audit-action",
        )
        actor_filter = st.text_input(
            "Actor filter (exact)",
            key="case-audit-actor",
        )
        order = st.selectbox(
            "Order",
            ("desc", "asc"),
            key="case-audit-order",
        )
        audit_page_number = int(
            st.number_input(
                "Audit page",
                min_value=1,
                value=1,
                step=1,
                key="case-audit-page",
            )
        )
        try:
            audit = client.case_audit_events(
                selected,
                page=audit_page_number,
                action=action_filter or None,
                actor=actor_filter or None,
                order=order,
            )
        except ApiClientError as error:
            api_error(error)
        else:
            table(
                (
                    {
                        "timestamp": item.timestamp,
                        "action": item.action,
                        "actor": item.actor,
                        "reason": item.reason,
                        "object_type": item.object_type,
                        "object_id": item.object_id,
                        "before_summary": item.before_summary,
                        "after_summary": item.after_summary,
                        "metadata_summary": item.metadata_summary,
                    }
                    for item in audit.items
                ),
                empty_message="No audit events match the selected fixed filters.",
            )
            st.caption(
                f"Page {audit.page} of {max(audit.total_pages, 1)} · "
                f"{audit.total} event(s) · page size {audit.page_size}"
            )
    with report_tab:
        with st.form("case-close"):
            closure_note = st.text_area("Closure note")
            actor = actor_input(key="close-actor")
            reason = st.text_area("Reason", key="close-reason")
            confirm = st.checkbox("Confirm case closure")
            submitted = st.form_submit_button("Close case")
        if submitted and confirm:
            try:
                closed = client.close_case(
                    selected,
                    closure_note=closure_note,
                    actor=actor,
                    reason=reason,
                )
                st.success(f"Case is {closed.status.value}.")
            except ApiClientError as error:
                api_error(error)
        with st.form("case-report"):
            version = st.text_input("New report version")
            actor = actor_input(key="report-actor")
            reason = st.text_area("Reason", key="report-reason")
            confirm = st.checkbox("Confirm versioned case report export")
            submitted = st.form_submit_button("Generate verified report")
        if submitted and confirm:
            try:
                report = client.generate_case_report(
                    selected,
                    version=version,
                    actor=actor,
                    reason=reason,
                )
                st.success(f"Verified report {report.version} generated.")
                report_bytes = client.download_case_report(selected, version)
                st.download_button(
                    "Download verified Markdown report",
                    data=report_bytes,
                    file_name=f"aegishunt-case-{selected}-{version}.md",
                    mime="text/markdown",
                    key="download-created-case-report",
                    on_click="ignore",
                )
            except ApiClientError as error:
                api_error(error)
        st.markdown("#### Download an existing case report")
        st.caption(
            "The API verifies the case identity, report manifest, exact inventory, "
            "and checksums before returning the Markdown file."
        )
        with st.form("existing-case-report-download"):
            existing_report_version = st.text_input(
                "Existing report version",
                key="existing-case-report-version",
            )
            prepare_report = st.form_submit_button("Prepare existing report download")
        if prepare_report:
            try:
                report_bytes = client.download_case_report(
                    selected,
                    existing_report_version,
                )
                st.success(f"Case report {existing_report_version} verified.")
                st.download_button(
                    "Download verified Markdown report",
                    data=report_bytes,
                    file_name=(
                        f"aegishunt-case-{selected}-{existing_report_version}.md"
                    ),
                    mime="text/markdown",
                    key="download-existing-case-report",
                    on_click="ignore",
                )
            except ApiClientError as error:
                api_error(error)
        with st.form("feedback-export"):
            version = st.text_input("Feedback artifact version")
            artifact_type = st.selectbox(
                "Artifact",
                ("reviewed feedback export", "retraining candidate proposal"),
            )
            actor = actor_input(key="feedback-export-actor")
            reason = st.text_area("Reason", key="feedback-export-reason")
            confirm = st.checkbox(
                "Confirm data-only export; this does not train or activate a model"
            )
            submitted = st.form_submit_button("Create data-only artifact")
        if submitted and confirm:
            try:
                result = client.export_feedback(
                    version=version,
                    actor=actor,
                    reason=reason,
                    retraining_candidates=artifact_type.startswith("retraining"),
                )
                st.success(f"{result.artifact_type} {result.version} generated.")
                with st.expander("View generated artifact manifest", expanded=True):
                    st.json(result.manifest)
                archive = client.download_data_artifact(
                    version,
                    retraining_candidates=artifact_type.startswith("retraining"),
                )
                st.download_button(
                    "Download verified data-only artifact (.zip)",
                    data=archive,
                    file_name=(
                        f"aegishunt-retraining-candidates-{version}.zip"
                        if artifact_type.startswith("retraining")
                        else f"aegishunt-feedback-export-{version}.zip"
                    ),
                    mime="application/zip",
                    key="download-created-data-artifact",
                    on_click="ignore",
                )
            except ApiClientError as error:
                api_error(error)
        st.markdown("#### Download an existing data-only artifact")
        st.caption(
            "The API verifies the declared inventory and checksums before preparing "
            "the ZIP. Downloading never trains or activates a model."
        )
        with st.form("feedback-artifact-download"):
            existing_version = st.text_input(
                "Existing artifact version",
                key="existing-feedback-artifact-version",
            )
            existing_type = st.selectbox(
                "Existing artifact",
                ("reviewed feedback export", "retraining candidate proposal"),
                key="existing-feedback-artifact-type",
            )
            prepare_download = st.form_submit_button("Prepare verified download")
        if prepare_download:
            try:
                archive = client.download_data_artifact(
                    existing_version,
                    retraining_candidates=existing_type.startswith("retraining"),
                )
                st.success(f"{existing_type} {existing_version} verified.")
                st.download_button(
                    "Download verified data-only artifact (.zip)",
                    data=archive,
                    file_name=(
                        f"aegishunt-retraining-candidates-{existing_version}.zip"
                        if existing_type.startswith("retraining")
                        else f"aegishunt-feedback-export-{existing_version}.zip"
                    ),
                    mime="application/zip",
                    key="download-existing-data-artifact",
                    on_click="ignore",
                )
            except ApiClientError as error:
                api_error(error)
