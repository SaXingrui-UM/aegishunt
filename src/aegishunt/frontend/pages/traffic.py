"""Traffic Explorer page."""

from __future__ import annotations

import streamlit as st

from aegishunt.frontend.client import AegisHuntApiClient, ApiClientError
from aegishunt.frontend.components import api_error, metrics, page_header, table


def render(client: AegisHuntApiClient) -> None:
    page_header("Traffic Explorer", "Canonical flows and bounded backend summaries")
    protocol = st.selectbox("Protocol filter", ("", "tcp", "udp", "icmp", "other"))
    source_ip = st.text_input("Source IP")
    destination_ip = st.text_input("Destination IP")
    minimum_risk = st.slider("Minimum operational risk", 0.0, 1.0, 0.0)
    try:
        summary = client.flow_summary()
        page = client.flows(
            protocol=protocol,
            source_ip=source_ip,
            destination_ip=destination_ip,
            minimum_risk=minimum_risk if minimum_risk > 0 else None,
        )
    except ApiClientError as error:
        api_error(error)
        return
    metrics(
        {
            "Flows": summary.total,
            "Packets": summary.total_packets,
            "Bytes": summary.total_bytes,
            "First seen": summary.first_seen,
            "Last seen": summary.last_seen,
        }
    )
    st.caption("Protocol distribution")
    st.json(summary.protocol_distribution)
    table(
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
        empty_message="No flows match the selected runtime filters.",
    )
    st.caption(
        "Ground-truth labels are not exposed as the default runtime view. "
        "Feature values are behavioral evidence, not attack confirmation."
    )
