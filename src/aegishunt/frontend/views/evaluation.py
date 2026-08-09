"""Read-only presentation of verified controlled evaluation evidence."""

from __future__ import annotations

import streamlit as st

from aegishunt.api.contracts import EvaluationSummary
from aegishunt.frontend.client import AegisHuntApiClient, ApiClientError
from aegishunt.frontend.components import (
    api_error,
    metrics,
    page_header,
    section_header,
    table,
)


def _label(value: str) -> str:
    return value.replace("_", " ").title()


def _available_contract(summary: EvaluationSummary) -> bool:
    return all(
        value is not None
        for value in (
            summary.dataset_id,
            summary.dataset_version,
            summary.row_count,
            summary.group_count,
            summary.supervised_weight,
            summary.anomaly_weight,
            summary.selected_threshold,
            summary.recommendation,
            summary.loao_aggregate,
            summary.provenance,
        )
    )


def _optional_number(value: float | None, *, suffix: str = "") -> str:
    return "Unavailable" if value is None else f"{value:.2f}{suffix}"


def _render_replay_statistics(client: AegisHuntApiClient) -> None:
    section_header("Replay Statistics")
    st.caption(
        "Operational inference statistics for one stored source and its replay job; "
        "these values are not accuracy, Recall, or ground truth."
    )
    try:
        sources = client.telemetry_sources(limit=100)
    except ApiClientError as error:
        api_error(error)
        return
    if not sources.items:
        st.info("No stored telemetry source is available for replay statistics.")
        return
    labels = {
        str(item.source_id): (
            f"{item.filename_or_interface} · {item.source_type.value} · {item.source_id}"
        )
        for item in sources.items
    }
    selected_source = st.selectbox(
        "Stored source / PCAP",
        tuple(labels),
        format_func=lambda source_id: labels[source_id],
    )
    try:
        statistics = client.replay_statistics(selected_source)
    except ApiClientError as error:
        api_error(error)
        return
    if statistics.status == "unavailable":
        st.info(statistics.message)
        return

    duration_seconds = (
        None if statistics.duration_ms is None else statistics.duration_ms / 1_000.0
    )
    metrics(
        {
            "Flows": statistics.flow_count,
            "Detections": statistics.detection_count,
            "Alerts": statistics.alert_count,
            "Alert rate": (
                "Unavailable"
                if statistics.alert_rate is None
                else f"{statistics.alert_rate:.1%}"
            ),
            "Replay duration": _optional_number(duration_seconds, suffix=" s"),
            "Throughput": _optional_number(
                statistics.throughput_flows_per_second,
                suffix=" flows/s",
            ),
        }
    )
    st.write(
        f"Runtime job `{statistics.runtime_job_id}` · status "
        f"`{statistics.runtime_status.value if statistics.runtime_status else 'unknown'}`"
    )
    if not statistics.score_distributions:
        st.info("No committed detection scores are available for this replay job.")
        return

    score_tabs = st.tabs(
        tuple(item.score.title() for item in statistics.score_distributions)
    )
    for score_tab, distribution in zip(
        score_tabs,
        statistics.score_distributions,
        strict=True,
    ):
        with score_tab:
            metrics(
                {
                    "Minimum": _optional_number(distribution.minimum),
                    "Mean": _optional_number(distribution.mean),
                    "Maximum": _optional_number(distribution.maximum),
                    "Available scores": distribution.available_count,
                    "Missing scores": distribution.missing_count,
                }
            )
            chart_rows = [
                {"Score range": item.label, "Flows": item.count}
                for item in distribution.buckets
            ]
            st.vega_lite_chart(
                {
                    "data": {"values": chart_rows},
                    "mark": {"type": "bar", "tooltip": True},
                    "encoding": {
                        "x": {
                            "field": "Score range",
                            "type": "ordinal",
                            "sort": None,
                            "title": "Score range",
                        },
                        "y": {
                            "field": "Flows",
                            "type": "quantitative",
                            "scale": {
                                "domain": [
                                    0,
                                    max(
                                        1,
                                        max(item.count for item in distribution.buckets),
                                    ),
                                ]
                            },
                            "title": "Flows",
                        },
                    },
                },
                use_container_width=True,
            )


def render(client: AegisHuntApiClient) -> None:
    page_header(
        "Evaluation",
        "Controlled model comparison and held-out-family results",
    )
    _render_replay_statistics(client)
    st.divider()
    section_header("Controlled Model Evaluation")
    try:
        summary = client.evaluation_summary()
    except ApiClientError as error:
        api_error(error)
        return

    if summary.status == "unavailable":
        st.info(summary.message)
        st.caption("Return to Overview and open “Run or reset controlled demo”.")
        return
    if summary.status == "invalid" or not _available_contract(summary):
        st.error(summary.message)
        return

    assert summary.row_count is not None
    assert summary.group_count is not None
    assert summary.supervised_weight is not None
    assert summary.anomaly_weight is not None
    assert summary.selected_threshold is not None
    assert summary.recommendation is not None
    assert summary.loao_aggregate is not None
    assert summary.provenance is not None

    scope, configuration = st.columns(2)
    with scope:
        section_header("Evidence Scope")
        st.markdown("**Controlled synthetic evaluation**")
        st.write(f"{summary.row_count} rows · {summary.group_count} isolated groups")
        st.caption("Not a public benchmark")
    with configuration:
        section_header("Selected Fusion Configuration")
        st.markdown(
            f"**{summary.supervised_weight:.0%} supervised + "
            f"{summary.anomaly_weight:.0%} anomaly**"
        )
        st.write(f"Threshold {summary.selected_threshold:.1f}")
        st.caption(f"Recommendation: {_label(summary.recommendation)}")

    section_header("Known Controlled Comparison")
    table(
        (
            {
                "Engine": _label(item.engine),
                "Recall": f"{item.recall:.4f}",
                "Macro F1": f"{item.macro_f1:.4f}",
                "PR-AUC": f"{item.pr_auc:.4f}",
                "False Positive Rate": f"{item.false_positive_rate:.4f}",
            }
            for item in summary.known_comparison
        ),
        empty_message="Verified known-group comparison rows are unavailable.",
    )
    st.info(
        "Fusion matched, but did not outperform, the supervised baseline in this "
        "controlled comparison."
    )

    section_header("Held-out Family Evaluation")
    metrics(
        {
            "Supervised family-macro Recall": (
                f"{summary.loao_aggregate.supervised_recall:.4f}"
            ),
            "Anomaly family-macro Recall": (
                f"{summary.loao_aggregate.anomaly_recall:.4f}"
            ),
            "Fusion family-macro Recall": f"{summary.loao_aggregate.fusion_recall:.4f}",
        }
    )
    families = tuple(
        dict.fromkeys(item.held_out_family for item in summary.loao_comparison)
    )
    recall_by_identity = {
        (item.held_out_family, item.engine): item.recall
        for item in summary.loao_comparison
    }
    table(
        (
            {
                "Held-out family": _label(family),
                "Supervised Recall": f"{recall_by_identity[(family, 'supervised')]:.4f}",
                "Anomaly Recall": f"{recall_by_identity[(family, 'anomaly')]:.4f}",
                "Fusion Recall": f"{recall_by_identity[(family, 'fusion')]:.4f}",
            }
            for family in families
        ),
        empty_message="Verified held-out-family rows are unavailable.",
    )
    zero_recall_families = [
        _label(item.held_out_family)
        for item in summary.loao_comparison
        if item.engine == "fusion" and item.recall == 0.0
    ]
    if zero_recall_families:
        st.caption(
            "Fusion Recall was 0.0000 for held-out "
            + " and ".join(zero_recall_families)
            + "."
        )

    section_header("Interpretation")
    st.write(
        "Fusion remains part of the controlled pipeline, but the experiment did not "
        "establish that it is better than the supervised model. Its held-out-family "
        "performance was weaker than anomaly-only."
    )

    with st.expander("Evidence provenance", expanded=False):
        st.write(
            f"Experiment `{summary.experiment_id}` · dataset "
            f"`{summary.dataset_id}:{summary.dataset_version}`"
        )
        st.write(
            f"Runtime job `{summary.provenance.runtime_job_id}` · policy "
            f"`{summary.provenance.policy_id}` v{summary.provenance.policy_version}"
        )
        st.write(
            f"Feature schema `{summary.provenance.feature_schema_version}` · "
            f"snapshot `{summary.provenance.snapshot_created_at.isoformat()}`"
        )
        st.caption(
            "Policy manifest hash: " + summary.provenance.policy_manifest_hash
        )
        st.caption(
            "Evaluation artifact hash: "
            + summary.provenance.evaluation_artifact_hash
        )
        st.caption(
            "LOAO evidence checksum: "
            + summary.provenance.loao_evidence_checksum
        )
        if summary.confidence_intervals:
            table(
                (
                    {
                        "Comparison": _label(item.comparison),
                        "Metric": _label(item.metric),
                        "95% interval": f"[{item.lower:.4f}, {item.upper:.4f}]",
                        "Successful draws": item.successful_draws,
                    }
                    for item in summary.confidence_intervals
                ),
                empty_message="No verified confidence interval summary is available.",
            )
        for item in summary.limitations:
            st.caption(f"• {item}")
