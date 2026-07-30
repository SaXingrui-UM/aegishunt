# Methodology evidence

Evidence level: **implemented and repository-tested**, with controlled
evaluation only.

AegisHunt uses a modular-monolith design. Offline PCAP/CSV/JSON telemetry enters
bounded ingestion, PCAP packets form deterministic bidirectional flows, and 43
ordered finite behavioral features feed identity-bound supervised and anomaly
engines. Validation selects candidates/calibration/thresholds; test is frozen
and excluded from selection. Fusion uses a separate controlled dataset and
fixed validation policy. Risk, alert, explanation, correlation, hypothesis,
case, and feedback stages preserve distinct semantics and audit identities.

Method sources:

- [Architecture](../architecture.md)
- [Feature dictionary](../feature_dictionary.md)
- [Experiment protocol](../experiment_protocol.md)
- [Data model](../data_model.md)
- [Threat model](../threat_model.md)

The methodology does not claim causal explanation, external validity, public
benchmark performance, or autonomous response.
