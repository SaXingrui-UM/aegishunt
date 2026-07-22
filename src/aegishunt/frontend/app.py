"""Truthful Streamlit shell for Phase 10 implementation review."""

from __future__ import annotations

import streamlit as st

from aegishunt.metadata import APPLICATION_DESCRIPTION, APPLICATION_NAME

PLANNED_MODULES = (
    "PCAP replay and runtime orchestration",
    "Public benchmark acquisition and validated label joining",
    "Complete Cases API and Streamlit investigation workspace",
    "Model activation and controlled retraining",
)


def main() -> None:
    """Render Phase 10 status without inventing cases, feedback, or metrics."""

    st.set_page_config(page_title=APPLICATION_NAME, page_icon="🛡️", layout="wide")
    st.title(APPLICATION_NAME)
    st.caption(APPLICATION_DESCRIPTION)
    st.info(
        "Current status: Phase 10 implementation complete — awaiting PR review on "
        "phase/10-case-feedback. Phase 9 and annotated checkpoint phase-09-complete "
        "remain closed and immutable. Phase 11: Not started."
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
    st.info(
        "Phase 9 adds bounded event-time alert correlation and deterministic proposed "
        "hunting hypotheses. Correlation and confidence are non-probabilistic triage "
        "scores; a hypothesis is a reviewable lead, not a fact or confirmed attack. "
        "Suggested queries are structured data only and are never executed by the core."
    )
    st.info(
        "Phase 10 adds deterministic InvestigationCase creation, audited lifecycle and "
        "append-only notes, typed evidence snapshots, analyst verdict/feedback, and "
        "checksummed data-only exports. A Case is not a confirmed attack; priority is "
        "triage, feedback may be noisy, and a Case verdict is not propagated to all "
        "related flows. Retraining candidates require manual review and never train, "
        "activate, or replace a model. No case counts or feedback metrics are fabricated."
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
