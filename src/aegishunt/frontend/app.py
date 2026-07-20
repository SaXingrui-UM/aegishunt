"""Minimal Streamlit page for the Phase 7 research checkpoint."""

from __future__ import annotations

import streamlit as st

from aegishunt.metadata import APPLICATION_DESCRIPTION, APPLICATION_NAME

PLANNED_MODULES = (
    "PCAP replay and runtime orchestration",
    "Public benchmark acquisition and validated label joining",
    "Detection results, alerting, and explanations",
    "Alert correlation and entity grouping",
    "Threat hypotheses, cases, and analyst feedback",
    "Model activation and controlled retraining",
)


def main() -> None:
    """Render truthful Phase 7 status without inventing evaluation output."""

    st.set_page_config(page_title=APPLICATION_NAME, page_icon="🛡️", layout="wide")
    st.title(APPLICATION_NAME)
    st.caption(APPLICATION_DESCRIPTION)
    st.info(
        "Current status: Phase 7 implementation complete — awaiting PR review. "
        "Phase 8: Not started."
    )
    st.success(
        "Configurable dual-engine fusion, validation-only policy selection, known and "
        "held-out-family comparisons, temporal holdout, bounded parameter shifts, "
        "group-aware confidence intervals, and integrity-checked policy artifacts are "
        "implemented. The experiment did not establish a fusion advantage."
    )
    st.subheader("Planned system modules")
    for module in PLANNED_MODULES:
        st.markdown(f"- {module}")
    st.warning(
        "Research prototype only. AegisHunt is not a production security product, "
        "does not confirm attacks, and does not perform automated response actions. "
        "Fusion score is not probability, risk, severity, or attack confirmation."
    )


if __name__ == "__main__":
    main()
