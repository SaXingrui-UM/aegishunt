"""Read-only evaluation evidence page."""

from __future__ import annotations

import streamlit as st

from aegishunt.frontend.client import AegisHuntApiClient, ApiClientError
from aegishunt.frontend.components import api_error, empty, page_header, table


def render(client: AegisHuntApiClient) -> None:
    page_header("Evaluation", "Verified read-only research evidence")
    try:
        evaluations = client.evaluations()
    except ApiClientError as error:
        api_error(error)
        return
    table(
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
