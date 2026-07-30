# ADR 0023: Final delivery version and local container boundary

## Status

Accepted

## Context

The package remained at the Phase 0 development version `0.1.0` even after the
Phase 0–13 research workflow was implemented. Final delivery also requires a
wheel, a local Docker deployment, and consistent version surfaces. Model,
policy, database-schema, feature-schema, dataset, and evidence versions already
have independent contracts and must not be coupled to an application release.

The local web configuration previously accepted loopback endpoints only.
Separate Compose containers need the API process to bind the container
wildcard and the frontend to call the private `api` service name. Those
container-internal endpoints are not host exposure policy.

## Decision

The final-delivery application version is `1.0.0`. The authoritative value is
`aegishunt.metadata.__version__`; package metadata reads it dynamically.
Application versioning remains independent from every research artifact and
schema version.

The default deployment remains loopback-only. A frozen
`web.container_network_enabled` setting allows exactly:

- API bind host `0.0.0.0` inside a container; and
- frontend API origin `http://api:<port>` on the private Compose network.

The Compose host publications remain `127.0.0.1` only. Containers run as UID
10001, drop Linux capabilities, use a read-only root filesystem, and receive
only declared writable volumes.

## Alternatives considered

- Keep `0.1.0`: rejected because the feature-complete final-delivery package
  would retain a scaffold identity.
- Derive the package version from a model version: rejected because model
  evidence and software releases have different lifecycles.
- Use host networking: rejected because it weakens isolation and is not
  portable.
- Allow arbitrary container hostnames: rejected because it broadens the
  local-only trust boundary without a deployment requirement.

## Consequences

- Wheel, API, documentation, and image labels share one application version.
- Default local validation continues to reject wildcard or non-loopback web
  endpoints.
- Container configuration is explicit and cannot be activated accidentally by
  changing only one hostname.
- No release Tag or GitHub Release is created by this decision.

## Risks

- The Python base image uses the explicit
  `python:3.11.13-slim-bookworm` tag rather than an immutable digest; upstream
  tag mutation remains a supply-chain risk and is documented in the final
  threat model.
- Compose is still a local single-node SQLite research deployment without
  authentication, authorization, TLS termination, or multi-host support.
