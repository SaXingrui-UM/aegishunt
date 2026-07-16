"""Minimal Streamlit page for the Phase 5 supervised research foundation."""

from __future__ import annotations

import streamlit as st

from aegishunt.metadata import APPLICATION_DESCRIPTION, APPLICATION_NAME

PLANNED_MODULES = (
    "PCAP replay and runtime orchestration",
    "Public benchmark acquisition and validated label joining",
    "Anomaly detection and supervised/anomaly fusion",
    "Risk fusion, alerting, and correlation",
    "Threat hypotheses, cases, and analyst feedback",
    "Model activation and controlled retraining",
)


def main() -> None:
    """Render truthful Phase 5 foundation status and planned capabilities."""

    st.set_page_config(page_title=APPLICATION_NAME, page_icon="🛡️", layout="wide")
    st.title(APPLICATION_NAME)
    st.caption(APPLICATION_DESCRIPTION)
    st.info("Current status: Phase 5 supervised pipeline awaiting PR review")
    st.success("Quality-gated supervised training and safe model bundles are available.")
    st.subheader("Planned system modules")
    for module in PLANNED_MODULES:
        st.markdown(f"- {module}")
    st.warning(
        "Research prototype only. AegisHunt is not a production security product, "
        "does not confirm attacks, and does not perform automated response actions."
    )


if __name__ == "__main__":
    main()
