"""Overview and explicit sample-demo page."""

from __future__ import annotations

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
    table,
)


def render(client: AegisHuntApiClient) -> None:
    page_header("Overview", "System health, runtime state, and controlled sample demo")
    st.caption(
        "Controlled synthetic evidence is not a public benchmark or production validation."
    )
    try:
        system = client.system_status()
        flows = client.flow_summary()
        alerts = client.alerts(limit=5)
        cases = client.cases()
        demo = client.demo_status()
    except ApiClientError as error:
        api_error(error)
        research_disclaimer()
        return
    metrics(
        {
            "Database": system.database,
            "Runtime jobs": len(system.runtime.latest_jobs),
            "Flows": flows.total,
            "Alerts": alerts.total,
            "Cases": cases.total,
        }
    )
    limitation(
        "Observed replay progress is non-durable live observation. Durable progress "
        "represents committed evidence; recovery restarts deterministically from origin."
    )
    st.subheader("Recent alerts")
    table(
        (
            {
                "alert_id": str(item.alert_id),
                "severity": item.severity.value,
                "title": item.title,
                "risk": item.risk_score,
                "status": item.status.value,
            }
            for item in alerts.items
        ),
        empty_message="No SecurityAlert records are available.",
    )
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
