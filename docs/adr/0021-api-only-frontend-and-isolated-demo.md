# ADR 0021: API-only frontend and isolated controlled demonstration

- Status: Accepted

## Context

Phase 12 must expose all completed local research workflows through FastAPI and
make them demonstrable in Streamlit without duplicating Phase 0–11 business
logic. Page reruns and refreshes must never mutate state. A fresh offline
demonstration also needs verified models and policies, but the formal Phase
5–11 evidence and frozen identities are immutable.

## Decision

FastAPI is the sole external business interface. Routers validate typed
requests and call existing application services or bounded read repositories.
They use one pagination contract, one sanitized error contract, request IDs,
explicit actor attribution, and confirmation for consequential mutations.

Streamlit uses only the typed HTTP client. Pages do not open SQLAlchemy
sessions, repositories, model bundles, or artifact paths. Bounded auto-refresh
performs GET requests only.

The sample demonstration accepts only the packaged `phase12-demo-pcap` identity.
It prepares a versioned, checksummed, demo-only artifact namespace through the
existing production dataset, training, evaluation, explanation, risk, runtime,
correlation, and case services. Preparation is explicit and atomic. Repeated
runs verify and reuse the same isolated evidence and stable database records
rather than resetting user data or overwriting formal evidence. It never moves
an active model pointer.

## Alternatives considered

- Let Streamlit access repositories directly: rejected because it creates a
  second business boundary and makes rerun side effects difficult to audit.
- Hard-code sample responses: rejected because fabricated IDs, metrics, or
  outputs would not verify integration.
- Reuse or overwrite formal model/evaluation directories: rejected because it
  breaks frozen-test and evidence custody.
- Add a distributed worker or broker: rejected as Phase 13/14 scope expansion
  and unnecessary for the local prototype.

## Consequences

The browser exercises the same contracts as other API clients. Empty and error
states are truthful, mutations are explicit, and the complete offline demo is
traceable to actual database and artifact identities. Generated demo artifacts
remain ignored and can be recreated in a fresh environment.

## Risks

This remains a local single-user research prototype without authentication or
RBAC; `actor` is audit attribution only. Demo artifact preparation and
controlled training are synchronous and may take tens of seconds. Controlled
synthetic results are pipeline verification, not benchmark or production
performance. A fully unavailable database still cannot record its own failure
in that same database (DEF-004).
