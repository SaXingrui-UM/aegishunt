"""Detection and SecurityAlert investigation page."""

from __future__ import annotations

import streamlit as st

from aegishunt.frontend.client import AegisHuntApiClient, ApiClientError
from aegishunt.frontend.components import actor_input, api_error, page_header, table


def render(client: AegisHuntApiClient) -> None:
    page_header("Alerts", "Operational risk evidence and analyst verdicts")
    st.caption(
        "A SecurityAlert is an analyst-review prompt, not a confirmed attack. "
        "Risk is not attack probability and explanation evidence is non-causal."
    )
    try:
        detections = client.detections()
    except ApiClientError as error:
        api_error(error)
        return
    st.subheader("Detection results")
    table(
        (
            {
                "detection_id": str(item.detection_id),
                "flow_id": str(item.flow_id),
                "supervised": item.supervised_label,
                "anomaly": item.normalized_anomaly_score,
                "fusion": item.fusion_score,
                "risk": item.risk_score,
            }
            for item in detections.items
        ),
        empty_message="No DetectionResult evidence is available.",
    )
    severity = st.selectbox(
        "Severity",
        ("", "informational", "low", "medium", "high", "critical"),
    )
    try:
        page = client.alerts(severity=severity)
    except ApiClientError as error:
        api_error(error)
        return
    table(
        (
            {
                "alert_id": str(item.alert_id),
                "severity": item.severity.value,
                "risk": item.risk_score,
                "title": item.title,
                "status": item.status.value,
                "verdict": item.analyst_verdict,
            }
            for item in page.items
        ),
        empty_message="No SecurityAlert records match the filters.",
    )
    if not page.items:
        return
    selected = st.selectbox("Inspect alert", [str(item.alert_id) for item in page.items])
    try:
        detail = client.alert(selected)
    except ApiClientError as error:
        api_error(error)
        return
    facts_tab, inference_tab, explanation_tab, action_tab = st.tabs(
        ("Observed facts", "Model inferences", "Explanation", "Analyst action")
    )
    with facts_tab:
        st.json(detail.alert.evidence.get("observed_facts", {}))
    with inference_tab:
        st.json(detail.alert.evidence.get("model_inferences", {}))
        st.caption("Risk is not attack probability; severity is not certainty.")
    with explanation_tab:
        st.json(detail.alert.explanation)
        st.caption("Importance and contributions are non-causal sensitivity evidence.")
    with action_tab:
        with st.form("alert-verdict"):
            verdict = st.selectbox(
                "Analyst verdict",
                (
                    "true_positive",
                    "false_positive",
                    "benign_expected",
                    "needs_more_information",
                ),
            )
            actor = actor_input()
            reason = st.text_area("Reason")
            confirm = st.checkbox("Confirm verdict update")
            submitted = st.form_submit_button("Update verdict")
        if submitted and confirm:
            try:
                updated = client.update_alert_verdict(
                    selected,
                    verdict=verdict,
                    actor=actor,
                    reason=reason,
                )
                st.success(f"Verdict updated to {updated.analyst_verdict}.")
            except ApiClientError as error:
                api_error(error)
