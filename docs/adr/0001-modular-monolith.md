# ADR 0001: Use a modular monolith

## Status

Accepted

## Context

AegisHunt needs ingestion, flow processing, ML, alerting, hunting, cases, an API,
a UI, and background work. It is a master's research prototype operated on a
personal computer, not a production multi-team platform. Distributed services
would add deployment, consistency, observability, and test complexity before
the module boundaries or performance needs are validated.

## Decision

Build one Python deployable with explicit internal boundaries for configuration,
storage, ingestion, flows, features, datasets, ML, detection, correlation,
hunting, cases, runtime, API, and frontend. Domain and application services must
not depend on Streamlit, and persistence and external adapters remain behind
interfaces so they can be tested or replaced independently.

## Alternatives considered

- Independent microservices for ingestion, inference, alerts, and cases.
- A single undivided application module.
- A notebook-led research implementation with a separate demo script.

## Consequences

Local installation, transactions, debugging, and end-to-end tests are simpler.
Module boundaries still support later extraction if evidence justifies it.
Developers must actively prevent cross-module coupling because process
boundaries do not enforce separation.

## Risks

Long-running tasks may contend with request handling; background processing and
resource limits must be designed carefully. Poor boundary discipline could
produce a large coupled codebase. Scaling beyond prototype workloads may
eventually require extracting selected workers or storage.
