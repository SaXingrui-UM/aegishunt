# ADR 0007: Use PCAP replay as the primary demonstration

## Status

Accepted

## Context

Live capture is platform- and privilege-dependent, difficult to reproduce, and
can expose unrelated sensitive traffic. The demonstration must work without a
fixed target, public network, root access, or real attack execution while still
showing realistic packet-to-hunt behavior.

## Decision

Make offline PCAP replay the required primary demonstration path. Use a small,
reviewed sample capture and deterministic replay controls, including speed and
progress when implemented. Treat live interface capture as an optional adapter
that must fail safely and never block replay.

## Alternatives considered

- Mandatory live packet capture.
- Active traffic generation against a fixed target.
- CSV-only demonstration with no packet-to-flow path.
- A prerecorded video instead of a runnable demonstration.

## Consequences

The end-to-end demo is reproducible, portable, safe, and suitable for CI and
review. Sample captures require provenance, privacy review, small size, and clear
labels. Replay timing and offline evidence do not prove production throughput or
live-network effectiveness.

## Risks

A sample PCAP may not represent deployment diversity and could encourage
overfitting the demonstration. Capture contents might contain sensitive data if
not controlled. Replay must validate corrupt input and avoid treating synthetic
behavior as observed real-world attacks.
