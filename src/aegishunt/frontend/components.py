"""Reusable truthful Streamlit presentation components."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from datetime import date, datetime
from typing import Any

import streamlit as st

from aegishunt.frontend.client import ApiClientError


def page_header(title: str, subtitle: str) -> None:
    st.title(title)
    st.caption(subtitle)


def limitation(text: str) -> None:
    st.info(text)


def unavailable(message: str) -> None:
    st.warning(f"Unavailable — {message}")


def empty(message: str) -> None:
    st.info(f"Empty — {message}")


def api_error(error: ApiClientError) -> None:
    suffix = f" Request ID: {error.request_id}." if error.request_id else ""
    st.error(f"{error}{suffix}")


def metrics(values: Mapping[str, object | None]) -> None:
    columns = st.columns(len(values))
    for column, (label, value) in zip(columns, values.items(), strict=True):
        column.metric(label, "Unavailable" if value is None else str(value))


def _safe_markdown_cell(value: object) -> str:
    """Render one value without allowing Markdown/HTML injection or Arrow conversion."""

    if value is None:
        return "Unavailable"
    if isinstance(value, (datetime, date)):
        rendered = value.isoformat()
    elif isinstance(value, (Mapping, list, tuple)):
        rendered = json.dumps(value, sort_keys=True, default=str)
    else:
        rendered = str(value)
    markdown_tokens = (
        "\\", "`", "*", "_", "{", "}", "[", "]", "(", ")",
        "#", "+", "-", ".", "!", "|", "<", ">",
    )
    for token in markdown_tokens:
        rendered = rendered.replace(token, f"\\{token}")
    return rendered.replace("\r", " ").replace("\n", " ")


def markdown_table(rows: Iterable[Mapping[str, Any]]) -> str:
    """Return a deterministic escaped Markdown table for a bounded row set."""

    materialized = list(rows)
    if not materialized:
        return ""
    headers = tuple(materialized[0])
    header = "| " + " | ".join(_safe_markdown_cell(item) for item in headers) + " |"
    separator = "| " + " | ".join("---" for _ in headers) + " |"
    body = [
        "| "
        + " | ".join(_safe_markdown_cell(row.get(item)) for item in headers)
        + " |"
        for row in materialized
    ]
    return "\n".join((header, separator, *body))


def table(rows: Iterable[Mapping[str, Any]], *, empty_message: str) -> None:
    materialized = list(rows)
    if not materialized:
        empty(empty_message)
        return
    st.markdown(markdown_table(materialized), unsafe_allow_html=False)


def actor_input(label: str = "Actor", *, key: str | None = None) -> str:
    """Render audit attribution with the configured local default."""

    default = str(st.session_state.get("aegishunt_default_actor", ""))
    return str(st.text_input(label, value=default, key=key))


def explicit_actor_fields(prefix: str) -> tuple[str, str]:
    actor = actor_input("Actor (audit attribution only)", key=f"{prefix}-actor")
    reason = st.text_area("Reason", key=f"{prefix}-reason")
    return actor, reason


def research_disclaimer() -> None:
    st.warning(
        "Research prototype only. Controlled synthetic pipeline verification is not a "
        "public benchmark, production validation, real-world performance result, or "
        "proof of zero-day detection. Scores are not attack probabilities and no "
        "automated response is performed."
    )
