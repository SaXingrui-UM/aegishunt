# Phase 2 demonstration inputs

These small inputs are deterministic, synthetic, and restricted to IANA
documentation address ranges and the reserved `.test` name. They do not target
or contact any system. AegisHunt only reads the files locally.

- `phase2-benign.pcap` contains one synthetic Ethernet/IPv4/UDP DNS query.
- `phase2-flows.csv` contains two canonical synthetic flow rows.
- `manifest.yaml` declares reviewed metadata and SHA-256 checksums.

Regenerate the PCAP explicitly from the project root:

```bash
python scripts/generate_phase2_samples.py --output data/sample/phase2-benign.pcap
```

These samples demonstrate ingestion mechanics only. They are not evidence of
model quality, detection capability, or operational security performance.
