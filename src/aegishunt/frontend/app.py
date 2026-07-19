"""Minimal Streamlit page for the completed Phase 6 research foundation."""

from __future__ import annotations

import streamlit as st

from aegishunt.metadata import APPLICATION_DESCRIPTION, APPLICATION_NAME

PLANNED_MODULES = (
    "PCAP replay and runtime orchestration",
    "Public benchmark acquisition and validated label joining",
    "Supervised/anomaly signal fusion",
    "Risk fusion, alerting, and correlation",
    "Threat hypotheses, cases, and analyst feedback",
    "Model activation and controlled retraining",
)


def main() -> None:
    """Render truthful completed Phase 6 status and planned capabilities."""

    st.set_page_config(page_title=APPLICATION_NAME, page_icon="🛡️", layout="wide")
    st.title(APPLICATION_NAME)
    st.caption(APPLICATION_DESCRIPTION)
    st.info(
        "Current status: Phase 6 complete. PR #18 and post-merge metadata PR #19 "
        "are merged; annotated checkpoint phase-06-complete is verified. "
        "Phase 7: Not started."
    )
    st.success(
        "Benign-only anomaly training, one-time evaluation, and safe bundle workflows "
        "are implemented. No anomaly model metric is displayed as a deployment claim."
    )
    st.subheader("Planned system modules")
    for module in PLANNED_MODULES:
        st.markdown(f"- {module}")
    st.warning(
        "Research prototype only. AegisHunt is not a production security product, "
        "does not confirm attacks, and does not perform automated response actions."
    )


if __name__ == "__main__":
    main()
