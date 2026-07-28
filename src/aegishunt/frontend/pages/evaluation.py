"""Read-only evaluation evidence page."""

from __future__ import annotations

import streamlit as st

from aegishunt.frontend.client import AegisHuntApiClient, ApiClientError
from aegishunt.frontend.components import (
    api_error,
    empty,
    page_header,
    paginated_table,
    pagination_offset,
)


def render(client: AegisHuntApiClient) -> None:
    page_header("Evaluation", "Verified read-only research evidence")
    try:
        evaluations = client.evaluations(
            offset=pagination_offset("evaluation-records")
        )
        fusion = client.fusion_evaluation_status()
    except ApiClientError as error:
        api_error(error)
        return
    st.subheader("Phase 7 Fusion Evaluation Discovery")
    st.json(
        {
            "status": fusion.status,
            "experiment_id": fusion.experiment_id,
            "run_id": fusion.run_id,
            "recommendation": fusion.recommendation,
            "metrics_available": fusion.metrics_available,
            "artifact_hash": fusion.artifact_hash,
            "dataset_reference": fusion.dataset_reference,
            "split_reference": fusion.split_reference,
            "invalid_reason": fusion.invalid_reason,
        }
    )
    if fusion.status == "unavailable":
        st.info(
            "The registered Phase 7 machine-readable artifact is unavailable. "
            "The retained research conclusion is inconclusive; no metric row is fabricated."
        )
        st.code("\n".join(fusion.missing_artifacts))
    elif fusion.status == "invalid":
        st.error(
            fusion.invalid_reason
            or "The registered Phase 7 artifact failed integrity or schema verification."
        )
    else:
        st.success(
            "The verified Phase 7 run is present below, including known/unseen-family "
            "comparisons and stored confidence intervals."
        )
    for item in fusion.limitations:
        st.caption(f"• {item}")
    st.subheader("Verified Evaluation Runs")
    paginated_table(
        evaluations,
        (
            {
                "run_id": item.run_id,
                "engine": item.engine,
                "version": item.version,
                "available": item.available,
                "verification": item.verification,
            }
            for item in evaluations.items
        ),
        key="evaluation-records",
        empty_message="No verified evaluation evidence is available.",
    )
    if not evaluations.items:
        return
    selected = st.selectbox("Evaluation run", [item.run_id for item in evaluations.items])
    try:
        detail = client.evaluation(selected)
    except ApiClientError as error:
        api_error(error)
        return
    if detail.metrics is None:
        empty("Evaluation artifact unavailable; no curve or metric is fabricated.")
    else:
        st.json(detail.metrics)
    st.json(detail.provenance)
    for item in detail.limitations:
        st.caption(f"• {item}")
    st.warning(
        "Fusion recommendation remains inconclusive. Fusion was not established as "
        "better than supervised-only; negative LOAO and held-out misses are retained."
    )
