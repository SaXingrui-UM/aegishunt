# ADR 0005: Use supervised and anomaly detection engines

## Status

Accepted

## Context

Supervised classification can identify labeled, represented attack families but
cannot by itself justify claims about novel behavior. Anomaly detection can flag
deviation from a benign baseline but tends to produce false positives and does
not identify intent. The research question requires measuring whether combined
signals improve detection of held-out behavior without unacceptable false positives.

## Decision

Build two independently evaluated engines: supervised candidates selected by
validation evidence and an Isolation Forest trained on benign-only data. Keep
their outputs separate, normalize anomaly scores reproducibly, and combine them
with configured correlation/context inputs. Determine fusion weights and
thresholds from validation experiments; never interpret combined risk as an
attack probability.

## Alternatives considered

- Supervised classification only.
- Anomaly detection only.
- A single deep neural network or autoencoder as the mandatory primary model.
- Deterministic signatures only.

## Consequences

The system can compare supervised-only, anomaly-only, and fusion behavior on
known, held-out-family, temporal, and parameter-shift tests. It also carries two
training and explanation lifecycles, additional threshold choices, and a greater
need for calibration and integrity controls.

## Risks

Fusion can amplify correlated errors or hide poor component performance.
Benign-only training data may be contaminated or unrepresentative. Anomaly
scores can be mistaken for threat certainty. Research reporting must preserve
separate metrics, validation provenance, sensitivity, and confidence intervals.
