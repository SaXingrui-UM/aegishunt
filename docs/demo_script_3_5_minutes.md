# 3–5 minute AegisHunt demonstration script

## Three-minute core

| Time | Click / command | Narration and expected visible state |
| --- | --- | --- |
| 0:00–0:20 | Overview | “AegisHunt turns 1,017 controlled packets into 42 bidirectional flows, detections and alerts, then one reviewable group, hypothesis and case. These are live API counts, not slide values.” It does not take automatic response. |
| 0:20–0:40 | Architecture slide or System Health | “FastAPI is the business boundary; Streamlit is API-only; SQLite and one leased worker form the single-node runtime.” |
| 0:40–1:05 | Data Ingestion → final sample → confirm | “This payload-free sample derives only aggregate profile facts from the uploaded PCAP and uses documentation addresses. The name is not ground truth.” Capture returned IDs. |
| 1:05–1:30 | Runtime / Traffic Explorer | “Replay produces deterministic bidirectional flows and 43 finite ordered features. Observed progress is live; durable progress means committed evidence.” |
| 1:30–1:55 | Alerts | “Supervised, anomaly, and fusion values remain separate. Risk and severity are configured triage outputs, not attack probability. Reasons/explanations are non-causal.” |
| 1:55–2:20 | Threat Hunts | “Bounded event-time correlation builds a stable group and a proposed hypothesis with facts, assumptions, benign alternatives, and queries that are never executed.” |
| 2:20–2:40 | Cases | Create a case, add one note, and set a verdict. “Analyst judgment is audited and can produce review-only feedback; it does not retrain automatically.” |
| 2:40–3:00 | Evaluation / System Health | “Fusion matches supervised on known groups but family-macro LOAO Recall is 0.3333 versus anomaly-only 0.9333, including zero Recall for held-out exfiltration and reconnaissance. Performance is a development-host observation, not an SLA.” |

## Five-minute extended

Use the core path, adding:

- 0:20–0:45: show the Compose non-root/loopback deployment diagram.
- 1:05–1:35: compare observed and durable progress, then open one 43-feature
  vector and explain first-packet forward direction.
- 1:55–2:35: expand reason codes, reference profile, possible mappings, and a
  benign alternative.
- 2:35–3:30: create case, add note, verdict, feedback, and export a case report.
- 3:30–4:15: show effective Random Forest/LOF identities, the 75%/25% fusion
  policy, and the LOF validation-only limitation.
- 4:15–5:00: show the `0.6000`/`0.9333`/`0.3333` LOAO aggregate, the two fusion
  zero-Recall families, and collapsed evidence provenance.

## Fallbacks

- **No internet:** use the prebuilt wheel/image; all runtime paths are offline.
- **Worker failure:** show the queued durable job and explain that no completion
  is claimed; restart one worker.
- **API failure:** show sanitized unavailable state, then `/health`; do not
  switch Streamlit to direct DB access.
- **Time pressure:** use an already completed controlled demo namespace and
  disclose that outputs were prepared earlier.

## What not to claim

Do not say “zero-day proven,” “fusion is superior,” “production ready,” “fully
autonomous response,” “real-world benchmark,” “attack probability,” or
“guaranteed real-time.”

## Likely questions

- **Why two engines?** They expose complementary score semantics, but current
  controlled fusion evidence is inconclusive.
- **How is leakage controlled?** Whole source/session/scenario groups and
  duplicate/leakage gates; test never selects candidates.
- **Why SQLite?** It makes the local prototype reproducible; it is not a
  multi-node production choice.
- **What is autonomous?** Deterministic evidence processing and proposal
  generation; case verdict and action remain human-controlled.
- **Is the uploaded PCAP an attack benchmark?** No. Only aggregate profiles feed
  a payload-free synthetic demo; labels/provenance are unverified.
- **What would production require?** Auth/RBAC, TLS, durable distributed
  control/data planes, signed supply chain, external evaluation, monitoring,
  and independent security assessment.
