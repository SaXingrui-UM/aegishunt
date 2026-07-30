# Phase 2 demonstration inputs

These small inputs are deterministic, synthetic, and restricted to IANA
documentation address ranges and the reserved `.test` name. They do not target
or contact any system. AegisHunt only reads the files locally.

- `phase2-benign.pcap` contains one synthetic Ethernet/IPv4/UDP DNS query.
- `phase2-flows.csv` contains two canonical synthetic flow rows.
- `phase12-demo.pcap` contains two small deterministic bidirectional flows
  (UDP and TCP) used by the complete local sample demonstration.
- `phase12-presentation-demo.pcap` is the separate 32-packet presentation
  sample covering documentation-only IPv4/IPv6, TCP, UDP, ICMP/ICMPv6,
  bidirectional DNS-like and web-like exchanges, controlled short
  connections, periodic small flows, and a bounded asymmetric transfer-like
  flow. Its detailed safety and packet inventory is recorded in
  `phase12-presentation-demo.manifest.json`.
- `phase14-attack-like.pcap` and `phase14-benign-like.pcap` are deterministic,
  payload-free captures built from aggregate packet/flow profiles observed in
  the two user-supplied final-delivery PCAPs. All addresses were replaced with
  IANA documentation addresses and no original application payload was copied.
  The names are presentation profiles, not verified labels or ground truth.
  `phase14-sample-provenance.json` records source checksums, transformation
  rules, limitations, and the exact output inventory.
- `manifest.yaml` declares reviewed metadata and SHA-256 checksums.

Regenerate the PCAP explicitly from the project root:

```bash
python scripts/generate_phase2_samples.py --output data/sample/phase2-benign.pcap
python scripts/generate_phase12_demo_pcap.py
python scripts/generate_phase12_presentation_pcap.py
python scripts/generate_phase14_samples.py
```

These samples demonstrate ingestion mechanics only. They are not evidence of
model quality, detection capability, or operational security performance.
The original uploaded Phase 14 captures remain ignored, are not altered by the
generator, and are not part of the distributable release.
