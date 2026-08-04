"""Traffic Explorer view."""

from __future__ import annotations

import streamlit as st

from aegishunt.frontend.client import AegisHuntApiClient, ApiClientError
from aegishunt.frontend.components import (
    api_error,
    empty,
    metrics,
    page_header,
    paginated_table,
    pagination_offset,
    table,
)


def render(client: AegisHuntApiClient) -> None:
    page_header(
        "Traffic Explorer",
        "Canonical flows, directional behavior, detections, and related alerts",
    )
    protocol = st.selectbox("Protocol filter", ("", "tcp", "udp", "icmp", "other"))
    source_ip = st.text_input("Source IP")
    destination_ip = st.text_input("Destination IP")
    minimum_risk = st.slider("Minimum operational risk", 0.0, 1.0, 0.0)
    filter_scope = "|".join(
        (protocol, source_ip.strip(), destination_ip.strip(), f"{minimum_risk:.6f}")
    )
    offset = pagination_offset("traffic-flows", scope=filter_scope)
    try:
        summary = client.flow_summary()
        page = client.flows(
            protocol=protocol,
            source_ip=source_ip,
            destination_ip=destination_ip,
            minimum_risk=minimum_risk if minimum_risk > 0 else None,
            offset=offset,
        )
    except ApiClientError as error:
        api_error(error)
        return
    metrics(
        {
            "Processed flows": summary.total,
            "Packets": summary.total_packets,
            "Bytes": summary.total_bytes,
            "First seen": summary.first_seen,
            "Last seen": summary.last_seen,
        }
    )
    st.subheader("Protocol and endpoint distribution")
    st.json(
        {
            "protocol_distribution": summary.protocol_distribution,
            "top_source_destination_pairs": summary.top_source_destination_pairs,
        }
    )
    paginated_table(
        page,
        (
            {
                "flow_id": str(item.flow_id),
                "source": f"{item.source_ip}:{item.source_port or '-'}",
                "destination": f"{item.destination_ip}:{item.destination_port or '-'}",
                "protocol": item.protocol.value,
                "packets": item.forward_packet_count + item.backward_packet_count,
                "bytes": item.forward_bytes + item.backward_bytes,
                "duration": item.duration,
            }
            for item in page.items
        ),
        key="traffic-flows",
        empty_message="No flows match the selected runtime filters.",
    )
    if not page.items:
        st.caption(
            "Ground-truth labels are not exposed as the default runtime view. "
            "Feature values are behavioral evidence, not attack confirmation."
        )
        return

    selected = st.selectbox(
        "Inspect flow",
        [str(item.flow_id) for item in page.items],
    )
    try:
        flow = client.flow(selected)
        detection_page = client.detections(flow_id=selected, limit=1)
        detection_detail = (
            client.detection(str(detection_page.items[0].detection_id))
            if detection_page.items
            else None
        )
        alert_detail = (
            client.alert(str(detection_detail.alert_id))
            if detection_detail is not None and detection_detail.alert_id is not None
            else None
        )
    except ApiClientError as error:
        api_error(error)
        return

    flow_tab, features_tab, distribution_tab, detection_tab, alert_tab = st.tabs(
        ("Flow detail", "Behavioral features", "Traffic distribution", "Detection", "Alert")
    )
    with flow_tab:
        st.json(
            {
                "flow_id": str(flow.flow_id),
                "source_id": str(flow.source_id),
                "capture_session_id": flow.capture_session_id,
                "first_seen": flow.first_seen.isoformat(),
                "last_seen": flow.last_seen.isoformat(),
                "duration_seconds": flow.duration,
                "protocol": flow.protocol.value,
                "source": {
                    "ip": flow.source_ip,
                    "port": flow.source_port,
                    "direction": "forward (first observed packet)",
                },
                "destination": {
                    "ip": flow.destination_ip,
                    "port": flow.destination_port,
                    "direction": "backward when reversed",
                },
            }
        )
    with features_tab:
        table(
            (
                {"feature": name, "value": value}
                for name, value in flow.behavioral_features.items()
            ),
            empty_message="This flow has no persisted behavioral features.",
        )
        st.caption(
            "Feature values are deterministic flow-level observations; they do not "
            "confirm an attack and do not include application payload."
        )
    with distribution_tab:
        total_packets = flow.forward_packet_count + flow.backward_packet_count
        total_bytes = flow.forward_bytes + flow.backward_bytes
        metrics(
            {
                "Forward packets": flow.forward_packet_count,
                "Backward packets": flow.backward_packet_count,
                "Forward bytes": flow.forward_bytes,
                "Backward bytes": flow.backward_bytes,
            }
        )
        st.caption("Directional packet share")
        st.progress(
            0.0 if total_packets == 0 else flow.forward_packet_count / total_packets,
            text="Forward share",
        )
        st.caption("Directional byte share")
        st.progress(
            0.0 if total_bytes == 0 else flow.forward_bytes / total_bytes,
            text="Forward share",
        )
    with detection_tab:
        if detection_detail is None:
            empty("No DetectionResult is associated with this flow.")
        else:
            detection = detection_detail.detection
            metrics(
                {
                    "Supervised score": detection.supervised_probability,
                    "Supervised threshold": detection.supervised_threshold,
                    "Anomaly score": detection.normalized_anomaly_score,
                    "Anomaly threshold": detection.anomaly_threshold,
                    "Fusion score": detection.fusion_score,
                    "Fusion threshold": detection.fusion_threshold,
                    "Risk score": detection.risk_score,
                    "Alert threshold": detection.alert_threshold,
                }
            )
            table(
                ({"reason_code": code} for code in detection.reason_codes),
                empty_message="No threshold-backed reason codes were recorded.",
            )
            for limitation in detection_detail.limitations:
                st.caption(f"• {limitation}")
    with alert_tab:
        if alert_detail is None:
            empty("No SecurityAlert is associated with this flow's detection.")
        else:
            st.json(
                {
                    "alert_id": str(alert_detail.alert.alert_id),
                    "severity": alert_detail.alert.severity.value,
                    "status": alert_detail.alert.status.value,
                    "title": alert_detail.alert.title,
                    "involved_entities": alert_detail.alert.involved_entities,
                    "reason_codes": alert_detail.alert.reason_codes,
                    "related_group_ids": [
                        str(item) for item in alert_detail.related_group_ids
                    ],
                    "related_hypothesis_ids": [
                        str(item) for item in alert_detail.related_hypothesis_ids
                    ],
                }
            )
            for limitation in alert_detail.limitations:
                st.caption(f"• {limitation}")
    st.caption(
        "Ground-truth labels are not exposed as the default runtime view. "
        "Feature values and model outputs are evidence, not attack confirmation."
    )
