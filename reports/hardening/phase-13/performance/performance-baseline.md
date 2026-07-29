# AegisHunt Phase 13 Development-Host Performance Baseline

This is a controlled development-host research baseline. It is not an SLA, production capacity claim, public benchmark, or detection-performance result.

## Method

- Warm-ups: 2
- Repetitions: 10
- Sample: `phase12-presentation-demo.pcap`
- Sample SHA-256: `0d272ac98660eb119cded8be194a513c2db82b475d4cce982a120eb210a8ab51`
- Feature schema: `1.0.0`
- Execution: single process, offline, loopback-free, no root, no live capture
- Percentiles: deterministic linear interpolation over per-iteration latency
- Peak RSS: 2 ms process sampling during each measured component

## Results

| Component | Unit | Operations | Throughput/s | p50 ms | p95 ms | p99 ms | CPU s | Peak RSS bytes |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| pcap_packet_parsing | captured_packets | 320 | 207769.542024 | 0.141187 | 0.201206 | 0.217541 | 0.015298 | 329482240 |
| flow_aggregation_feature_extraction | captured_packets | 320 | 13380.186286 | 2.111562 | 3.665384 | 3.837044 | 0.199308 | 329515008 |
| supervised_inference | flow_rows | 90 | 8055.642651 | 1.053667 | 1.423431 | 1.499886 | 0.097619 | 329515008 |
| anomaly_inference | flow_rows | 90 | 11703.827620 | 0.770250 | 0.837913 | 0.839082 | 0.049499 | 329515008 |
| fusion | score_pairs | 90 | 229617.024316 | 0.037666 | 0.046156 | 0.051031 | 0.003634 | 329515008 |
| full_flow_to_alert_pipeline | persisted_flows | 90 | 1.458952 | 6138.570750 | 6298.038542 | 6339.971642 | 105.142812 | 298680320 |

## Artifact Sizes

- anomaly_bundle: 42175 bytes
- explanation_artifact: 36003 bytes
- fusion_policy: 3618 bytes
- supervised_bundle: 1615885 bytes

## Limitations

- The workload is a small controlled synthetic PCAP.
- Host scheduling and thermal state can affect latency.
- RSS sampling can miss peaks shorter than the sampling interval.
- Model and policy evidence is isolated and was not activated globally.
- No frozen test set, model selection, or fusion threshold was reopened.
