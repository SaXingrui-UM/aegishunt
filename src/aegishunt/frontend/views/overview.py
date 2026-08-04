"""Mentor-oriented overview of the latest controlled analysis."""

from __future__ import annotations

from collections.abc import Mapping

import streamlit as st

from aegishunt.frontend.client import AegisHuntApiClient, ApiClientError
from aegishunt.frontend.components import (
    actor_input,
    api_error,
    metrics,
    page_header,
    section_header,
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


def _label(value: str) -> str:
    return value.replace("_", " ").title()


def _demo_completed(previous_run: Mapping[str, object] | None) -> bool:
    return previous_run is not None and previous_run.get("runtime_status") == "completed"


def render(client: AegisHuntApiClient) -> None:
    page_header(
        "Overview",
        "End-to-end view of the latest controlled threat-hunting analysis",
    )
    try:
        system = client.system_status()
        flows = client.flow_summary()
        detections = client.detections(limit=1)
        alerts = client.alerts(limit=1)
        active_alerts = _active_alert_count(client)
        critical_alerts = client.alerts(limit=1, severity="critical").total
        groups = client.groups(limit=1)
        hypotheses = client.hypotheses(limit=1)
        cases = client.cases(limit=1)
        open_hypotheses = _open_hypothesis_count(client)
        open_cases = _open_case_count(client)
        model_state = client.effective_models()
        demo = client.demo_status()
    except ApiClientError as error:
        api_error(error)
        return

    if system.database == "ready":
        st.success("System ready")

    primary_metrics = st.columns(4)
    primary_metrics[0].metric("Processed Flows", flows.total)
    primary_metrics[1].metric("Open Alerts", f"{active_alerts} open")
    primary_metrics[1].caption(f"{critical_alerts} critical")
    primary_metrics[2].metric("Open Hypotheses", open_hypotheses)
    primary_metrics[3].metric("Open Cases", open_cases)

    section_header("Analysis pipeline")
    metrics(
        {
            "Packets": flows.total_packets,
            "Flows": flows.total,
            "Detections": detections.total,
            "Alerts": alerts.total,
            "Groups": groups.total,
            "Hypotheses": hypotheses.total,
            "Cases": cases.total,
        }
    )
    st.caption(
        "PCAP packets are aggregated into bidirectional flows, scored by the two "
        "models and fusion policy, then correlated into reviewable hunting evidence."
    )

    section_header("Models used in latest analysis")
    if not model_state.effective_models:
        st.info(model_state.unavailable_reason or "No completed analysis is available yet.")
    else:
        columns = st.columns(len(model_state.effective_models))
        for column, model in zip(
            columns,
            model_state.effective_models,
            strict=True,
        ):
            with column:
                st.markdown(
                    f"**{_label(model.engine_type)} · "
                    f"{_label(model.algorithm or 'model')}**"
                )
                st.write(f"v{model.version} · {_label(model.registry_status)}")
                st.caption(
                    f"Threshold {model.threshold:.1f} · {model.qualification}"
                    if model.threshold is not None
                    else model.qualification
                )
    fusion = model_state.effective_fusion_policy
    if fusion is not None:
        st.markdown(
            "**Fusion:** "
            f"{fusion.supervised_weight:.0%} supervised + "
            f"{fusion.anomaly_weight:.0%} anomaly · threshold "
            f"{fusion.fusion_threshold:.1f}"
        )
        st.caption(f"Decision: {_label(fusion.recommendation)}")

    with st.expander("Run or reset controlled demo", expanded=False):
        if _demo_completed(demo.previous_run):
            st.success("Demo completed")
        if not demo.available:
            st.info("No checksum-declared packaged sample is available.")
        else:
            with st.form("sample-demo"):
                sample_id = st.selectbox("Packaged sample", demo.sample_ids)
                actor = actor_input("Actor (audit attribution only)")
                reason = st.text_area("Reason")
                create_case = st.checkbox(
                    "Create a case if a hypothesis is produced",
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
                        st.success(
                            "Demo completed"
                            if result.state == "completed"
                            else f"Demo state: {result.state}"
                        )
                    except ApiClientError as error:
                        api_error(error)

    with st.expander("Limitations", expanded=False):
        st.markdown(
            "- The packaged evidence is controlled and synthetic.\n"
            "- Model, fusion, risk, and confidence scores are not attack probabilities.\n"
            "- Results do not establish public-benchmark or production performance.\n"
            "- The prototype performs no automated response."
        )
