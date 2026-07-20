# Flow Feature Dictionary

## Contract

Phase 3 feature schema version is `1.0.0`. The canonical machine-readable source
is [`artifacts/feature_schema.json`](../artifacts/feature_schema.json). Its explicit
43-feature order is mandatory for future training and inference; callers must not
sort names or infer order from unrelated mappings. `behavioral_features` contains
only finite integers/floats. NaN, Infinity, booleans, strings, and nested values
are rejected.

Phase 8 does not change this schema or order. Its benign reference profile,
native/permutation importance reports, and local reference-replacement
contributions bind the same schema version and exact ordered names. Reference
ranges describe observed benign training values; importance and contributions
are non-causal and are not attack confirmation.

Packet size means IPv4 total length or IPv6 base-header plus payload length. It
excludes link-layer bytes. Forward is the first decoded packet's direction. Timing
statistics sort captured timestamps, while TCP handshake evidence retains capture
arrival order. Population standard deviation and linear-interpolation quantiles
are used.

## Volume features

| Order | Feature | Type | Definition | Empty/zero behavior |
| ---: | --- | --- | --- | --- |
| 1 | `total_packets` | integer | Forward plus backward packets | `0` only for an invalid empty state; empty states are not finalized |
| 2 | `total_bytes` | integer | Forward plus backward IP-layer bytes | `0` |
| 3 | `forward_packets` | integer | Packets matching first-packet direction | `0` |
| 4 | `backward_packets` | integer | Packets opposite first-packet direction | `0` |
| 5 | `forward_bytes` | integer | Sum of forward IP-layer sizes | `0` |
| 6 | `backward_bytes` | integer | Sum of backward IP-layer sizes | `0` |
| 7 | `packets_per_second` | number | Total packets divided by duration | `0.0` when duration is zero |
| 8 | `bytes_per_second` | number | Total bytes divided by duration | `0.0` when duration is zero |
| 9 | `forward_backward_packet_ratio` | number | Forward packets divided by backward packets | `0.0` when backward is zero |
| 10 | `forward_backward_byte_ratio` | number | Forward bytes divided by backward bytes | `0.0` when backward is zero |

## Packet-size features

| Order | Feature | Type | Definition | Empty direction behavior |
| ---: | --- | --- | --- | --- |
| 11 | `mean_packet_size` | number | Arithmetic mean | `0.0` |
| 12 | `std_packet_size` | number | Population standard deviation | `0.0` for fewer than two values |
| 13 | `min_packet_size` | number | Minimum | `0.0` |
| 14 | `max_packet_size` | number | Maximum | `0.0` |
| 15 | `median_packet_size` | number | Linear median | `0.0` |
| 16 | `packet_size_q25` | number | Linear 25th percentile | `0.0` |
| 17 | `packet_size_q75` | number | Linear 75th percentile | `0.0` |
| 18 | `forward_mean_packet_size` | number | Forward arithmetic mean | `0.0` |
| 19 | `backward_mean_packet_size` | number | Backward arithmetic mean | `0.0` |

## Timing features

| Order | Feature | Type | Definition | Missing-IAT behavior |
| ---: | --- | --- | --- | --- |
| 20 | `flow_duration` | number | Latest minus earliest captured timestamp, seconds | `0.0` for one/identical timestamp |
| 21 | `mean_inter_arrival_time` | number | Mean adjacent sorted timestamp delta | `0.0` |
| 22 | `std_inter_arrival_time` | number | Population IAT standard deviation | `0.0` |
| 23 | `min_inter_arrival_time` | number | Minimum IAT | `0.0` |
| 24 | `max_inter_arrival_time` | number | Maximum IAT | `0.0` |
| 25 | `median_inter_arrival_time` | number | Median IAT | `0.0` |
| 26 | `iat_q25` | number | Linear 25th percentile IAT | `0.0` |
| 27 | `iat_q75` | number | Linear 75th percentile IAT | `0.0` |
| 28 | `forward_mean_iat` | number | Mean adjacent sorted forward timestamp delta | `0.0` |
| 29 | `backward_mean_iat` | number | Mean adjacent sorted backward timestamp delta | `0.0` |

## TCP evidence features

| Order | Feature | Type/range | Definition |
| ---: | --- | --- | --- |
| 30–35 | `syn_count`, `ack_count`, `fin_count`, `rst_count`, `psh_count`, `urg_count` | integer, >= 0 | Number of packets with each flag bit; all zero for non-TCP |
| 36 | `syn_ratio` | number, 0–1 | SYN count divided by all flow packets |
| 37 | `rst_ratio` | number, 0–1 | RST count divided by all flow packets |
| 38 | `ack_ratio` | number, 0–1 | ACK count divided by all flow packets |
| 39 | `completed_handshake_indicator` | integer, 0/1 | Capture-order evidence of forward SYN, reverse SYN+ACK, then forward ACK |

The handshake indicator is a bounded evidence feature, not proof that a complete
TCP state machine succeeded. Loss, capture position, retransmission, or asymmetric
visibility can change it.

## Basic single-flow behavior features

| Order | Feature | Type/range | Definition |
| ---: | --- | --- | --- |
| 40 | `asymmetry_score` | number, 0–1 | Absolute forward/backward byte difference divided by total bytes |
| 41 | `connection_burst_score` | number, 0–1 | Largest packet share inside any inclusive one-second window |
| 42 | `periodicity_score` | number, 0–1 | `1 / (1 + IAT coefficient of variation)` with at least three IATs and positive mean |
| 43 | `failed_connection_indicator` | integer, 0/1 | TCP has RST, or has SYN without the bounded handshake indicator |

`repeated_destination_indicator`, `repeated_port_indicator`, and
`short_connection_ratio` require cross-flow entity/window state. They are not in
schema `1.0.0` and are not filled with constants. Dataset/window or correlation
phases must define their evidence boundary before adding them in a new schema version.
