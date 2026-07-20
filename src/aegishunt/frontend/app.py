"""Minimal truthful Streamlit shell for the Phase 8 review checkpoint."""

from __future__ import annotations

import streamlit as st

from aegishunt.metadata import APPLICATION_DESCRIPTION, APPLICATION_NAME

PLANNED_MODULES = (
    "PCAP replay and runtime orchestration",
    "Public benchmark acquisition and validated label joining",
    "Alert correlation and entity grouping",
    "Threat hypotheses, cases, and analyst feedback",
    "Model activation and controlled retraining",
)


def main() -> None:
    """Render truthful Phase 8 status without inventing runtime alert output."""

    st.set_page_config(page_title=APPLICATION_NAME, page_icon="🛡️", layout="wide")
    st.title(APPLICATION_NAME)
    st.caption(APPLICATION_DESCRIPTION)
    st.info(
        "Current status: Phase 8 implementation complete — awaiting PR review. "
        "Phase 7 remains complete at phase-07-complete. Phase 9: Not started."
    )
    st.success(
        "Recommendation: Inconclusive. The controlled experiment did not establish a "
        "fusion advantage; fusion family-macro LOAO Recall was lower than anomaly-only, "
        "and held-out exfiltration and reconnaissance rows were missed. Negative results "
        "are retained."
    )
    st.info(
        "Phase 8 implements configuration-controlled operational risk, severity, "
        "threshold-gated SecurityAlert records, evidence-backed reason codes, "
        "non-causal global/local explanations, and audited analyst verdicts. Risk is "
        "not attack probability; severity is not certainty; alerts are not confirmed "
        "attacks. No runtime alert records or metrics are fabricated on this page."
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
