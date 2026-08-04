"""Reusable truthful Streamlit presentation components."""

from __future__ import annotations

import json
import math
from collections.abc import Iterable, Mapping
from datetime import date, datetime
from typing import Any, Protocol

import streamlit as st

from aegishunt.frontend.client import ApiClientError


class PaginationMetadata(Protocol):
    """Structural page metadata shared by API and ingestion contracts."""

    total: int
    limit: int
    offset: int
    next_offset: int | None


def page_header(title: str, subtitle: str) -> None:
    st.title(title, anchor=title.casefold().replace(" ", "-"))
    st.caption(subtitle)


def section_header(title: str) -> None:
    """Render a rerun-safe section anchor instead of reusing prior-page links."""

    st.subheader(title, anchor=title.casefold().replace(" ", "-"))


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
    """Render compact metrics with no more than four columns per row."""

    items = list(values.items())
    for start in range(0, len(items), 4):
        row = items[start : start + 4]
        columns = st.columns(len(row))
        for column, (label, value) in zip(columns, row, strict=True):
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


def pagination_offset(key: str, *, scope: str = "") -> int:
    """Return a bounded page offset and reset it when filters change."""

    offset_key = f"aegishunt-page-{key}-offset"
    scope_key = f"aegishunt-page-{key}-scope"
    if st.session_state.get(scope_key) != scope:
        st.session_state[scope_key] = scope
        st.session_state[offset_key] = 0
    raw_offset = st.session_state.setdefault(offset_key, 0)
    return max(0, int(raw_offset))


def _set_pagination_offset(key: str, value: int) -> None:
    st.session_state[f"aegishunt-page-{key}-offset"] = max(0, value)


def paginated_table(
    page: PaginationMetadata,
    rows: Iterable[Mapping[str, Any]],
    *,
    key: str,
    empty_message: str,
) -> None:
    """Render one bounded API page with stable previous/next controls."""

    table(rows, empty_message=empty_message)
    if page.total == 0 or (page.offset == 0 and page.next_offset is None):
        return
    total_pages = max(1, math.ceil(page.total / page.limit))
    current_page = min(total_pages, (page.offset // page.limit) + 1)
    previous_offset = max(0, page.offset - page.limit)
    left, center, right = st.columns((1, 3, 1))
    left.button(
        "Previous",
        key=f"{key}-previous",
        disabled=page.offset == 0,
        on_click=_set_pagination_offset,
        args=(key, previous_offset),
    )
    center.caption(
        f"Page {current_page} of {total_pages} · Offset {page.offset} · "
        f"Page size {page.limit} · Total {page.total}"
    )
    right.button(
        "Next",
        key=f"{key}-next",
        disabled=page.next_offset is None,
        on_click=_set_pagination_offset,
        args=(key, page.next_offset or page.offset),
    )


def actor_input(label: str = "Actor", *, key: str | None = None) -> str:
    """Render audit attribution with the configured local default."""

    default = str(st.session_state.get("aegishunt_default_actor", ""))
    return str(st.text_input(label, value=default, key=key))


def explicit_actor_fields(prefix: str) -> tuple[str, str]:
    actor = actor_input("Actor (audit attribution only)", key=f"{prefix}-actor")
    reason = st.text_area("Reason", key=f"{prefix}-reason")
    return actor, reason


def research_disclaimer() -> None:
    st.caption(
        "Controlled synthetic demonstration; not a public benchmark or production "
        "validation."
    )
