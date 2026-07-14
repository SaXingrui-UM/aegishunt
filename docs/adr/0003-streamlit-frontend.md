# ADR 0003: Use Streamlit for the frontend

## Status

Accepted

## Context

The project requires an interactive research demonstration spanning system
status, ingestion, traffic, alerts, hypotheses, cases, model comparison, and
evaluation. The primary goal is clear evidence communication and reproducible
workflow demonstration, not a production-grade web product or custom design system.

## Decision

Use Streamlit for the demonstration frontend. It will consume FastAPI contracts
and must not access the database or model registry directly. Pages must show
truthful empty and error states, evidence provenance, uncertainty, and prototype
disclaimers. Phase 0 provides only a static foundation page.

## Alternatives considered

- React or another single-page application framework.
- Server-rendered FastAPI templates.
- Jupyter notebooks as the only visual interface.
- A desktop GUI toolkit.

## Consequences

Python developers can build and iterate on research views quickly, and local
demonstration has a small conceptual footprint. Streamlit rerun behavior and
state management must be handled deliberately. The API boundary keeps migration
to another frontend feasible.

## Risks

Large tables and frequent refresh can be inefficient. Session state can become
confusing if application logic leaks into UI code. Streamlit is not the target
for production authentication, complex multi-user workflows, or pixel-perfect UI.
