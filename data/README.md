# Data workspace

This directory is reserved for raw, interim, processed, sample, and manifest
data. Generated and sensitive data must remain untracked.

Phase 2 includes only two explicitly reviewed, deterministic synthetic inputs
under `data/sample/`, with checksums in `manifest.yaml`. Runtime uploads remain
ignored under `data/raw/`. The reviewed PCAP is an ingestion fixture, not a
dataset, detection result, or captured operational traffic.
