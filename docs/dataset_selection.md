# Public Dataset Evaluation and Selection

Last evidence review: 2026-07-16. Only provider pages and provider-authored
research references were used for license, format, size, and labeling claims.
No benchmark file was downloaded or mirrored during Phase 4.

## Decision

**CSE-CIC-IDS2018 is the preferred primary public benchmark, conditionally.** Its
official page explicitly permits redistribution with citation, provides raw PCAP
and per-machine CICFlowMeter CSV data, documents seven attack scenarios and the
capture schedule, and says raw captures may be processed with a new extractor.
That makes it the best candidate for using the unchanged AegisHunt Phase 3
feature contract rather than treating similar-looking third-party columns as
equivalent.

The selection is conditional because the official page does not publish a
file-level SHA-256 manifest, the AWS collection is large, and joining Phase 3
flows to official scenario labels still needs validation on operator-acquired
files. Registry status is therefore `manual_required` / `provisional`, not
“downloaded” or “converted.” Phase 5 must not use it until all raw files have
locally recorded checksums, the label join has been audited, group leakage has
passed, and a frozen split manifest exists.

The controlled AegisHunt demo is the only dataset materialized by the automated
Phase 4 verification. It is a synthetic pipeline fixture, not a substitute for
the public benchmark and not evidence of real-world detection performance.

## Evaluation criteria

Candidates were compared on official access and license evidence, benign and
attack coverage, label clarity, raw PCAP or verifiable flows, stable
capture/session/scenario grouping, compatibility with the 43-feature Phase 3
contract, leakage and duplication risk, class imbalance, age, download
reproducibility, and feasibility on a personal Apple Silicon computer. No model
was trained and no test-set or model metric influenced the decision.

## Candidate comparison

| Candidate | Official evidence and access | Formats and scale | Labels / groups | Phase 3 feasibility | Decision |
| --- | --- | --- | --- | --- | --- |
| CSE-CIC-IDS2018 | [UNB/CIC official page](https://www.unb.ca/cic/datasets/ids-2018.html); unsigned AWS S3 workflow; redistribution/republishing/mirroring allowed with citation | Raw per-machine PCAP and logs plus more than 80 CICFlowMeter features in CSV; multi-day, 420 victim machines and 30 servers; no single total size stated on the page | Benign plus brute force, Heartbleed, botnet, DoS, DDoS, web attacks, and infiltration; date, machine, attack schedule, IP, port, and protocol evidence supports grouped labeling | Raw PCAP can use the exact Phase 3 extractor. Published CSV is not assumed equivalent to all 43 local definitions. Label join remains provisional. | **Conditional primary** |
| CIC-IDS2017 | [UNB/CIC official page](https://www.unb.ca/cic/datasets/ids-2017.html); public researcher downloads; CIC license note requires citation | PCAP, labeled flows, and ML CSV; five daily captures total about 51.1 GB from the sizes published on the page | One benign day plus brute force, DoS/DDoS, Heartbleed, web attack, infiltration, botnet, and scanning; day and attack-window grouping | Raw PCAP is compatible in principle. CICFlowMeter CSV has more than 80 features but not a complete semantic match to AegisHunt. No official checksums. | Rejected as primary: older, still large, weaker automated acquisition/checksum story |
| UNSW-NB15 | [UNSW official project page](https://research.unsw.edu.au/projects/unsw-nb15-dataset); free academic research use in perpetuity with citation; commercial use by agreement | About 100 GB PCAP; Bro, Argus, and CSV; 2,540,044 rows in four CSVs plus published 175,341/82,332 train/test files | Normal plus nine attack types; event/ground-truth tables and source files offer provenance, but published row splits do not prove AegisHunt group isolation | Its 49 Argus/Bro-derived fields are not the Phase 3 schema. Raw PCAP processing is possible but resource-heavy. | Rejected as primary: schema mismatch and personal-computer cost |
| TON_IoT | [UNSW official project page](https://research.unsw.edu.au/projects/toniot-datasets); free academic research use in perpetuity with citation; commercial use by agreement | Heterogeneous IoT/IIoT telemetry, Windows/Linux traces, PCAP, Zeek logs, and processed CSV | Normal and multiple cyberattacks; security-event ground truth uses timestamps and attacker IP ranges; multiple modalities and environments | Network PCAP could be extracted, but processed heterogeneous fields cannot be represented as the Phase 3 vector without modality-specific adapters. | Rejected as primary: scope and schema heterogeneity |

UNB's [official dataset FAQ](https://www.unb.ca/cic/datasets/) states that CIC
datasets may be redistributed, republished, and mirrored when the dataset and
listed paper are cited. The more specific CSE-CIC-IDS2018 page repeats that
permission. UNSW's two project pages explicitly distinguish free academic use
from commercial use requiring author agreement.

## Primary benchmark acquisition procedure

The registry deliberately marks CSE-CIC-IDS2018 as manual. An operator must:

1. Read the current official license and citation text.
2. Use the official AWS instructions, currently documented as:
   `aws s3 sync --no-sign-request --region <your-region> s3://cse-cic-ids2018/ <dest-dir>`.
3. Place only the chosen, documented subset below the configured
   `datasets.raw_root/cse-cic-ids2018/2018/`; do not commit it.
4. Run `aegishunt dataset download cse-cic-ids2018 --local-file <file>` to
   compute or verify SHA-256 without copying or changing the file.
5. Record every selected file, locally computed digest, capture date/machine,
   scenario, label source, and exclusion in a dataset manifest.
6. Process PCAP with the Phase 3 extractor and audit the schedule/5-tuple/time
   label join. Do not substitute CICFlowMeter columns for missing Phase 3
   features and do not silently fill unknown labels.
7. Run quality, leakage, and group-exclusive splitting before any later model
   work.

No command automatically accepts a license, downloads the entire collection, or
uses an unofficial mirror. HTTP/AWS failures and checksum mismatches are terminal.

## Raw fields and label mapping constraints

The official CSE-CIC-IDS2018 page documents FlowID, source/destination IP,
source/destination port, protocol, more than 80 traffic statistics, capture
dates/times, attacker/victim hosts, and attack names. These are provenance and
label-join inputs. IPs, ports, timestamps, filenames, machine IDs, scenario IDs,
and labels remain outside the model feature vector.

Only values recalculated by Phase 3 may populate the 43 local features. Mapping
is complete only when every ordered feature is present with identical semantics;
otherwise conversion fails. Original labels are retained and normalized through
`configs/label_mappings/cse-cic-ids2018-v1.yaml`. Unknown labels fail closed.

## Known quality and leakage risks

- Day, source file, machine, scenario window, IP, port, timestamp, and label text
  can reveal the class if used as features or split across partitions.
- Flow tables derived from one capture may contain exact or near duplicates and
  strongly related connection sequences.
- Attack families and benign traffic are not expected to be balanced.
- Provider-generated flow semantics and timeout settings differ from Phase 3.
- Dataset age and synthetic testbed behavior limit operational generalization.
- Large PCAPs and archives require bounded extraction and subset planning on a
  personal computer.

These risks are reported, not repaired through resampling or feature deletion in
Phase 4. Group isolation takes priority over forcing every family into every split.

## Citation information

- Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani, “Toward
  Generating a New Intrusion Detection Dataset and Intrusion Traffic
  Characterization,” ICISSP 2018.
- Nour Moustafa and Jill Slay, “UNSW-NB15: a comprehensive data set for network
  intrusion detection systems,” MilCIS 2015.
- Nour Moustafa, “A new distributed architecture for evaluating AI-based
  security systems at the edge: Network TON_IoT datasets,” 2021.

Provider pages remain the authority for current terms; this document is not a
license grant.
