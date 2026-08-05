"""Detection and SecurityAlert investigation view."""

from __future__ import annotations

import streamlit as st

from aegishunt.frontend.client import AegisHuntApiClient, ApiClientError
from aegishunt.frontend.components import (
    actor_input,
    api_error,
    metrics,
    page_header,
    paginated_table,
    pagination_offset,
    table,
)


def render(client: AegisHuntApiClient) -> None:
    page_header("Alerts", "Operational risk evidence and analyst verdicts")
    st.caption(
        "A SecurityAlert is an analyst-review prompt, not a confirmed attack. "
        "Risk is not attack probability and explanation evidence is non-causal."
    )
    detection_offset = pagination_offset("alerts-detections")
    try:
        detections = client.detections(offset=detection_offset)
    except ApiClientError as error:
        api_error(error)
        return
    st.subheader("Detection results")
    paginated_table(
        detections,
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
        key="alerts-detections",
        empty_message="No DetectionResult evidence is available.",
    )
    severity = st.selectbox(
        "Severity",
        ("", "informational", "low", "medium", "high", "critical"),
    )
    alert_offset = pagination_offset("alerts-records", scope=severity)
    try:
        page = client.alerts(severity=severity, offset=alert_offset)
    except ApiClientError as error:
        api_error(error)
        return
    st.subheader("Security alerts")
    paginated_table(
        page,
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
        key="alerts-records",
        empty_message="No SecurityAlert records match the filters.",
    )
    if not page.items:
        return
    selected = st.selectbox("Inspect alert", [str(item.alert_id) for item in page.items])
    try:
        detail = client.alert(selected)
        detection = client.detection(str(detail.alert.detection_id)).detection
    except ApiClientError as error:
        api_error(error)
        return
    (
        facts_tab,
        inference_tab,
        reason_tab,
        relations_tab,
        explanation_tab,
        limitations_tab,
        action_tab,
    ) = st.tabs(
        (
            "Observed facts",
            "Scores and thresholds",
            "Reasons and entities",
            "Related investigations",
            "Explanation",
            "Limitations",
            "Analyst action",
        )
    )
    with facts_tab:
        st.json(detail.alert.evidence.get("observed_facts", {}))
    with inference_tab:
        metrics(
            {
                "Supervised score": detection.supervised_probability,
                "Supervised threshold": detection.supervised_threshold,
                "Anomaly score": detection.normalized_anomaly_score,
                "Anomaly threshold": detection.anomaly_threshold,
                "Fusion score": detection.fusion_score,
                "Fusion threshold": detection.fusion_threshold,
                "Risk score": detail.alert.risk_score,
                "Alert threshold": detection.alert_threshold,
            }
        )
        st.json(detail.alert.evidence.get("model_inferences", {}))
        st.caption("Risk is not attack probability; severity is not certainty.")
    with reason_tab:
        st.subheader("Structured reason codes")
        table(
            ({"reason_code": code} for code in detail.alert.reason_codes),
            empty_message="No threshold-backed reason codes are available.",
        )
        st.subheader("Involved entities")
        table(
            ({"entity": entity} for entity in detail.alert.involved_entities),
            empty_message="No involved entities are available.",
        )
    with relations_tab:
        table(
            (
                {"related_alert_group_id": str(group_id)}
                for group_id in detail.related_group_ids
            ),
            empty_message="This alert is not part of a persisted AlertGroup.",
        )
        table(
            (
                {"related_threat_hypothesis_id": str(hypothesis_id)}
                for hypothesis_id in detail.related_hypothesis_ids
            ),
            empty_message="No ThreatHypothesis references this alert.",
        )
    with explanation_tab:
        st.json(detail.alert.explanation)
        st.caption("Importance and contributions are non-causal sensitivity evidence.")
    with limitations_tab:
        for item in detail.limitations:
            st.caption(f"• {item}")
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
