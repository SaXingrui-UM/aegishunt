"""Correlated alert groups and threat-hypothesis view."""

from __future__ import annotations

import streamlit as st

from aegishunt.frontend.client import AegisHuntApiClient, ApiClientError
from aegishunt.frontend.components import (
    actor_input,
    api_error,
    empty,
    page_header,
    paginated_table,
    pagination_offset,
    runtime_job_filter,
)


def render(client: AegisHuntApiClient) -> None:
    page_header("Threat Hunts", "Correlation groups and deterministic proposed hypotheses")
    st.caption(
        "A hypothesis is a reviewable lead, not a fact. Confidence and correlation "
        "are not attack probabilities; possible MITRE mappings are not attribution, "
        "and recommended queries are not executed."
    )
    try:
        job_id = runtime_job_filter(client)
    except ApiClientError as error:
        api_error(error)
        return
    scope = job_id or "all"
    groups_tab, hypotheses_tab = st.tabs(("Alert groups", "Hypotheses"))
    with groups_tab:
        try:
            groups = client.groups(
                job_id=job_id,
                offset=pagination_offset("hunts-groups", scope=scope),
            )
            paginated_table(
                groups,
                (
                    {
                        "group_id": str(item.group_id),
                        "alerts": len(item.alert_ids),
                        "severity": item.severity,
                        "correlation_score": item.correlation_score,
                        "status": item.status,
                    }
                    for item in groups.items
                ),
                key="hunts-groups",
                empty_message="No correlated groups are available.",
            )
            st.caption("Correlation score is a non-probabilistic triage score.")
        except ApiClientError as error:
            api_error(error)
    with hypotheses_tab:
        try:
            hypotheses = client.hypotheses(
                job_id=job_id,
                offset=pagination_offset("hunts-hypotheses", scope=scope),
            )
        except ApiClientError as error:
            api_error(error)
            return
        paginated_table(
            hypotheses,
            (
                {
                    "hypothesis_id": str(item.hypothesis_id),
                    "title": item.title,
                    "confidence": item.confidence,
                    "severity": item.severity.value,
                    "status": item.status.value,
                }
                for item in hypotheses.items
            ),
            key="hunts-hypotheses",
            empty_message="No hypotheses have been generated.",
        )
        if not hypotheses.items:
            empty("A hypothesis is generated only from qualifying persisted evidence.")
            return
        selected = st.selectbox(
            "Inspect hypothesis",
            [str(item.hypothesis_id) for item in hypotheses.items],
        )
        try:
            detail = client.hypothesis(selected)
        except ApiClientError as error:
            api_error(error)
            return
        st.json(detail.hypothesis.model_dump(mode="json"))
        st.caption(
            "Hypothesis confidence is not attack probability; the hypothesis is a "
            "reviewable lead, not a fact. MITRE mappings are not attribution."
        )
        with st.form("hypothesis-action"):
            action = st.selectbox(
                "Explicit action",
                (
                    "under_review",
                    "needs_more_information",
                    "dismissed",
                    "closed_unresolved",
                    "rejected",
                    "create_case",
                ),
            )
            actor = actor_input()
            reason = st.text_area("Reason")
            confirm = st.checkbox("Confirm action")
            submitted = st.form_submit_button("Apply")
        if submitted and confirm:
            try:
                if action == "create_case":
                    case_result = client.create_case(
                        selected,
                        actor=actor,
                        reason=reason,
                    )
                    st.success(f"Case {case_result.case_id} created or reused.")
                else:
                    hypothesis_result = client.update_hypothesis(
                        selected,
                        status=action,
                        actor=actor,
                        reason=reason,
                    )
                    st.success(
                        f"Hypothesis status: {hypothesis_result.status.value}"
                    )
            except ApiClientError as error:
                api_error(error)
