# AegisHunt Phase 13 Development-Host Performance Baseline

This is a controlled development-host research baseline. It is not an SLA, production capacity claim, public benchmark, or detection-performance result.

## Method

- Micro/API warm-ups: 5
- Micro/API measured samples: 100
- Full-pipeline measured samples: 10
- Sample: `phase12-presentation-demo.pcap`
- Sample SHA-256: `0d272ac98660eb119cded8be194a513c2db82b475d4cce982a120eb210a8ab51`
- Feature schema: `1.0.0`
- Execution: single process, offline, loopback-free, no root, no live capture
- Percentiles: deterministic linear interpolation over measured per-iteration latency
- p99: reported only for scenarios with at least 100 measured samples
- Peak RSS: 2 ms process sampling during each measured component

## Results

| Component | Samples | Unit | Operations | Throughput/s | p50 ms | p95 ms | p99 ms | p99 status | CPU s | Peak RSS bytes |
|---|---:|---:|---:|---:|---:|---:|---:|---|---:|---:|
| pcap_packet_parsing | 100 | captured_packets | 3200 | 323666.821420 | 0.068729 | 0.184117 | 0.280128 | available | 0.097559 | 331055104 |
| flow_aggregation_feature_extraction | 100 | captured_packets | 3200 | 10245.248124 | 2.142375 | 6.103604 | 6.576613 | available | 2.161968 | 331055104 |
| supervised_warm_inference | 100 | flow_rows | 900 | 7820.620751 | 1.114333 | 1.384670 | 1.425112 | available | 0.130914 | 331055104 |
| anomaly_warm_inference | 100 | flow_rows | 900 | 17320.277154 | 0.515667 | 0.663604 | 0.751111 | available | 0.304153 | 331055104 |
| fusion | 100 | score_pairs | 900 | 243197.167239 | 0.036458 | 0.037988 | 0.048022 | available | 0.023678 | 331055104 |
| supervised_anomaly_artifact_load | 10 | verified_artifacts | 20 | 51.295703 | 38.374604 | 41.376394 | n/a | insufficient_samples | 1.177469 | 331022336 |
| full_flow_to_alert_pipeline | 10 | persisted_flows | 90 | 1.448437 | 6223.529395 | 6250.653392 | n/a | insufficient_samples | 106.107604 | 318111744 |
| api_health | 100 | http_200_responses | 100 | 1306.086147 | 0.749730 | 0.940726 | 1.070721 | available | 0.523713 | 304037888 |
| api_system_status | 100 | http_200_responses | 100 | 380.679743 | 2.592021 | 3.030854 | 3.190116 | available | 0.247681 | 304496640 |
| api_flows_page | 100 | http_200_responses | 100 | 507.639760 | 1.925146 | 2.322175 | 2.430673 | available | 0.177867 | 294699008 |
| api_alerts_page | 100 | http_200_responses | 100 | 395.780907 | 2.459667 | 2.848869 | 3.093098 | available | 0.233946 | 284442624 |
| api_runtime_status | 100 | http_200_responses | 100 | 302.004363 | 3.231083 | 4.041944 | 4.359068 | available | 0.315676 | 284524544 |
| api_demo_status | 100 | http_200_responses | 100 | 19.009960 | 49.085313 | 55.711665 | 120.148107 | available | 5.303390 | 309870592 |
| api_flow_detail | 100 | http_200_responses | 100 | 964.312808 | 0.998605 | 1.325364 | 1.386708 | available | 0.087964 | 309886976 |
| case_report_export | 10 | versioned_reports | 10 | 51.714955 | 18.458875 | 24.472502 | n/a | insufficient_samples | 0.131533 | 309837824 |

## Memory Scenarios

| Scenario | Samples | Baseline RSS | Peak RSS | Delta RSS | Status | Limitation |
|---|---:|---:|---:|---:|---|---|
| baseline_process_rss | 1 | 309755904 | 309755904 | 0 | available | single point-in-time RSS observation |
| supervised_anomaly_artifact_load_delta | 10 | 331022336 | 331022336 | 0 | available | allocator reuse can reduce the observed incremental RSS |
| warm_inference_peak | 100 | 331022336 | 331055104 | 32768 | available | small controlled feature batch |
| full_sample_replay_peak | 100 | 331022336 | 331055104 | 32768 | available | controlled sample PCAP; not a large-capture capacity claim |
| sample_demo_peak | 10 | 314474496 | 318111744 | 3637248 | available | isolated controlled demo with bounded synthetic input |
| bounded_api_list_peak | 100 | 294617088 | 294699008 | 81920 | available | in-process TestClient; excludes network and browser memory |
| case_report_export_peak | 10 | 309739520 | 309837824 | 98304 | available | bounded controlled case evidence only |

## Artifact Sizes

- anomaly_bundle: 42156 bytes
- explanation_artifact: 36003 bytes
- fusion_policy: 3618 bytes
- supervised_bundle: 1615885 bytes

## Limitations

- The workload is a small controlled synthetic PCAP.
- Host scheduling and thermal state can affect latency.
- RSS sampling can miss peaks shorter than the two-millisecond interval.
- Model and policy evidence is isolated and was not activated globally.
- No frozen test set, model selection, or fusion threshold was reopened.
