"""API-only Streamlit application for the complete Phase 12 local workflow."""

from __future__ import annotations

from collections.abc import Callable

import streamlit as st

from aegishunt.config import load_settings
from aegishunt.frontend.client import AegisHuntApiClient
from aegishunt.frontend.components import research_disclaimer
from aegishunt.frontend.pages import (
    alerts,
    cases,
    evaluation,
    hunts,
    ingestion,
    models,
    overview,
    system,
    traffic,
)
from aegishunt.metadata import APPLICATION_DESCRIPTION, APPLICATION_NAME, __version__

PageRenderer = Callable[[AegisHuntApiClient], None]

PAGES: dict[str, PageRenderer] = {
    "Overview": overview.render,
    "Data Ingestion": ingestion.render,
    "Traffic Explorer": traffic.render,
    "Alerts": alerts.render,
    "Threat Hunts": hunts.render,
    "Cases": cases.render,
    "Model Lab": models.render,
    "Evaluation": evaluation.render,
    "System Health": system.render,
}


def _client(
    base_url: str,
    timeout_seconds: float,
    *,
    page_size: int = 50,
    actor_header: str = "X-AegisHunt-Actor",
    safe_download_types: tuple[str, ...] = ("case_report",),
) -> AegisHuntApiClient:
    """Create one HTTP client; no database or artifact access occurs."""

    return AegisHuntApiClient(
        base_url,
        timeout_seconds=timeout_seconds,
        page_size=page_size,
        actor_header=actor_header,
        safe_download_types=safe_download_types,
    )


def main() -> None:
    """Render nine API-backed pages with explicit mutation forms."""

    settings = load_settings()
    st.session_state.setdefault("aegishunt_default_actor", settings.web.default_actor)
    st.set_page_config(
        page_title=settings.web.page_title,
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    st.sidebar.title(APPLICATION_NAME)
    st.sidebar.caption("Autonomous Threat Hunting Research Prototype")
    page_name = st.sidebar.radio("Navigation", tuple(PAGES), label_visibility="collapsed")
    st.sidebar.divider()
    auto_refresh = st.sidebar.toggle(
        "Auto-refresh current read view",
        value=False,
        disabled=not settings.web.auto_refresh_enabled,
        help=(
            "Refreshes GET-backed rendering only. It never triggers ingestion, replay, "
            "training, activation, verdicts, cases, or demo work."
        ),
    )
    st.sidebar.caption(
        f"Configured interval: {settings.web.auto_refresh_seconds}s · "
        "Local single-user mode · authentication/RBAC not implemented"
    )
    if st.sidebar.button("Refresh now"):
        st.rerun()
    st.sidebar.divider()
    st.sidebar.caption(
        f"AegisHunt {__version__} · "
        "Phase 13 checkpoint complete and immutable. "
        "Phase 14 final delivery: Implementation complete — awaiting PR review. "
        "PR #41 is open; required implementation-Head CI gates passed. "
        "No Phase 14 completion or release Tag exists. "
        "FastAPI is the only business interface."
    )
    st.sidebar.caption(APPLICATION_DESCRIPTION)
    renderer = PAGES[page_name]
    if auto_refresh:
        def refreshed() -> None:
            with _client(
                settings.web.api_base_url,
                settings.web.request_timeout_seconds,
                page_size=settings.web.maximum_table_rows,
                actor_header=settings.web.actor_header,
                safe_download_types=settings.web.safe_download_types,
            ) as client:
                renderer(client)

        refreshed_fragment: Callable[[], None] = st.fragment(
            run_every=f"{settings.web.auto_refresh_seconds}s"
        )(refreshed)
        refreshed_fragment()
    else:
        with _client(
            settings.web.api_base_url,
            settings.web.request_timeout_seconds,
            page_size=settings.web.maximum_table_rows,
            actor_header=settings.web.actor_header,
            safe_download_types=settings.web.safe_download_types,
        ) as client:
            renderer(client)
    st.divider()
    research_disclaimer()


if __name__ == "__main__":
    main()
