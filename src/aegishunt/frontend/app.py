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
        "Current status: Phase 7 complete. PR #21 and PR #22 are merged, and "
        "phase-07-complete is the annotated checkpoint. Phase 8: Not started."
    )
    st.success(
        "Recommendation: Inconclusive. The controlled experiment did not establish a "
        "fusion advantage; fusion family-macro LOAO Recall was lower than anomaly-only, "
        "and held-out exfiltration and reconnaissance rows were missed. Negative results "
        "are retained."
    )
    st.subheader("Planned system modules")
    for module in PLANNED_MODULES:
        st.markdown(f"- {module}")
    st.warning(
        "Research prototype only. This is controlled synthetic pipeline verification—"
        "not a public benchmark, production validation, real-world performance result, "
        "or proof of zero-day detection. AegisHunt does not confirm attacks or perform "
        "automated response actions. Fusion score is not probability, risk, severity, "
        "or attack confirmation."
    )


if __name__ == "__main__":
    main()
