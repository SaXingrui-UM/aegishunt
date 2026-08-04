"""API-only Streamlit application for the local research workflow."""

from __future__ import annotations

from collections.abc import Callable

import streamlit as st

from aegishunt.config import load_settings
from aegishunt.frontend.client import AegisHuntApiClient
from aegishunt.frontend.components import research_disclaimer
from aegishunt.frontend.views import (
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
from aegishunt.metadata import APPLICATION_NAME, __version__

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


def _apply_theme() -> None:
    """Apply a restrained local-only visual system without altering navigation."""

    st.markdown(
        """
        <style>
        :root {
          --aegis-ink: #172033;
          --aegis-muted: #5e6b82;
          --aegis-line: #e3e8f0;
          --aegis-teal: #087f8c;
        }
        .stApp { background: #ffffff; color: var(--aegis-ink); }
        [data-testid="stSidebar"] { background: #f7f9fc; }
        [data-testid="stMetric"] {
          border: 1px solid var(--aegis-line);
          border-radius: 12px;
          padding: 0.75rem 0.9rem;
          background: #fbfcfe;
        }
        [data-testid="stMetricLabel"] { color: var(--aegis-muted); }
        [data-testid="stExpander"] {
          border: 1px solid var(--aegis-line);
          border-radius: 10px;
        }
        h1, h2, h3 { color: var(--aegis-ink); letter-spacing: -0.015em; }
        a { color: var(--aegis-teal); }
        </style>
        """,
        unsafe_allow_html=True,
    )


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
    """Render one selected API-backed view into a stable page container."""

    settings = load_settings()
    st.session_state.setdefault("aegishunt_default_actor", settings.web.default_actor)
    st.set_page_config(
        page_title=settings.web.page_title,
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    _apply_theme()
    st.sidebar.title(APPLICATION_NAME)
    st.sidebar.caption("Autonomous Threat Hunting Research Prototype")
    page_name = st.sidebar.radio(
        "Navigation",
        tuple(PAGES),
        key="aegishunt-primary-navigation",
        label_visibility="collapsed",
    )
    st.sidebar.divider()
    if st.sidebar.button("Refresh now"):
        st.rerun()
    st.sidebar.divider()
    st.sidebar.caption(f"AegisHunt {__version__} · Local research prototype")
    renderer = PAGES[page_name]
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
