# ADR 0002: Use FastAPI for the backend

## Status

Accepted

## Context

The backend must expose typed health, ingestion, flow, alert, hypothesis, case,
model, and evaluation APIs. Request validation, predictable error contracts,
OpenAPI documentation, file-upload controls, and testability are central to the
research prototype. The implementation language is Python because packet and ML
workflows are Python-based.

## Decision

Use FastAPI as the HTTP boundary and Pydantic models for request and response
validation. Route handlers will remain thin and call application services.
Uvicorn will serve the app. Phase 0 exposes only `GET /health`; later routes are
added in their owning phases.

## Alternatives considered

- Flask with manually assembled validation and OpenAPI.
- Django and Django REST Framework.
- No HTTP API, with Streamlit accessing storage directly.

## Consequences

The project gains generated OpenAPI, strong Python typing integration, async
support where needed, and straightforward in-process tests. Pydantic/API
contracts become public interfaces that require version-conscious changes.

## Risks

Async endpoints can still block if packet, model, or database work is executed
on the event loop. Automatic documentation can expose unsafe operations if route
authorization and validation are weak. Dependency upgrades may change Pydantic
or FastAPI behavior and must be controlled and tested.
