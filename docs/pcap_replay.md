# PCAP Replay Contract

## Timing

Replay is based only on capture event time:

```text
wall_sleep = min(max(packet_time - previous_packet_time, 0) / speed, gap_cap)
```

- the first packet is emitted immediately;
- speed must be inside configured minimum/maximum bounds;
- an out-of-order timestamp produces zero delay and increments
  `out_of_order_packets`;
- a delay above the configured cap increments `capped_gaps`;
- sleep is divided into configured quanta so shutdown, pause, heartbeat, and
  resource checks remain responsive;
- replay does not rewrite packet timestamps.

## Packet and flow handling

The runtime reuses `PcapPacketReader`, `parse_packet`, `FlowAggregator`, and
`finalize_network_flow`. Existing bounds on record count, packet size, active
flows, packets per flow, idle timeout, and active timeout remain effective.
Unsupported non-IP packets are counted as skipped. Malformed or truncated
capture framing fails the job safely.

The Phase 2 ingestion capture-session identity is reused. Existing deterministic
flows can therefore be verified and reused rather than duplicated. EOF performs
the normal capture-end flush. Cooperative shutdown deliberately does not flush
partial state.

## Commands

```bash
aegishunt runtime config verify
aegishunt runtime replay create <telemetry-source-uuid> --speed 10
aegishunt runtime jobs list
aegishunt runtime jobs describe <job-uuid>
aegishunt runtime jobs pause <job-uuid>
aegishunt runtime jobs resume <job-uuid>
aegishunt runtime jobs recover <job-uuid>
aegishunt runtime worker run --once --worker-id local-worker
aegishunt runtime worker run --forever --worker-id local-worker
aegishunt runtime workers list
aegishunt runtime workers describe <worker-id>
aegishunt runtime status
aegishunt runtime live-capture
```

`live-capture` reports the safe disabled state. It does not open an interface,
request privileges, or connect to a target.

## Counters

Jobs report two separate counter sets:

- observed captured/decoded/skipped/out-of-order/capped-gap packet counts are
  non-durable live telemetry for the current attempt;
- durable created/reused flow, detection, alert, group, and hypothesis counts
  are supported by committed evidence.

The final completion transaction copies verified end-of-capture packet
observations into final durable counters only after every output batch, final
correlation, and final hypothesis commit succeeds. Before completion, open-flow
packets do not advance the durable packet position. Observed progress is not an
exact cursor, committed checkpoint, or exactly-once claim.
