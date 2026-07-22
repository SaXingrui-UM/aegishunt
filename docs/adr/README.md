# Architecture Decision Records

Accepted decisions are immutable records of the context available when made.
Material changes require a superseding ADR rather than silently rewriting the
decision. Phase 0 establishes:

1. [Modular monolith](0001-modular-monolith.md)
2. [FastAPI backend](0002-fastapi-backend.md)
3. [Streamlit frontend](0003-streamlit-frontend.md)
4. [SQLite default storage](0004-sqlite-default-storage.md)
5. [Dual detection engine](0005-dual-detection-engine.md)
6. [Deterministic hypothesis engine](0006-deterministic-hypothesis-engine.md)
7. [PCAP replay as primary demo](0007-pcap-replay-as-primary-demo.md)
8. [No LLM core dependency](0008-no-llm-core-dependency.md)
9. [Explicit schema versioning](0009-explicit-schema-versioning.md)
10. [Durable safe-ingestion boundary](0010-durable-safe-ingestion-boundary.md)
11. [Deterministic packet-to-flow contract](0011-deterministic-packet-to-flow-contract.md)
12. [File-based dataset quality boundary](0012-file-based-dataset-quality-boundary.md)
13. [Validation-frozen supervised model bundles](0013-validation-frozen-supervised-model-bundles.md)
14. [Validation-frozen benign-baseline anomaly engine](0014-validation-frozen-benign-anomaly-engine.md)
15. [LOF validation-qualified production candidate](0015-lof-validation-qualified-production-candidate.md)
16. [Validation-selected dual-engine fusion](0016-validation-selected-dual-engine-fusion.md)
17. [Configured risk and non-causal alert explanations](0017-configured-risk-and-noncausal-explanations.md)
18. [Bounded deterministic alert correlation and hypotheses](0018-bounded-deterministic-alert-correlation.md)
