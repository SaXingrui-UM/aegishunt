"""Generate deterministic thesis figures from committed machine evidence."""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_ROOT = PROJECT_ROOT / "docs" / "assets" / "figures"
PERFORMANCE_SOURCE = (
    PROJECT_ROOT
    / "reports"
    / "hardening"
    / "phase-13"
    / "performance-v1.1"
    / "benchmark-results.json"
)
SAMPLE_SOURCE = PROJECT_ROOT / "data" / "sample" / "phase14-sample-provenance.json"


def _read(path: Path) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return payload


def build_performance_figure() -> Path:
    """Plot measured p50/p95 latency without converting missing p99 to zero."""

    payload = _read(PERFORMANCE_SOURCE)
    raw_results = payload.get("results")
    if not isinstance(raw_results, list):
        raise ValueError("performance source has no result rows")
    selected = [
        row
        for row in raw_results
        if isinstance(row, dict)
        and row.get("component")
        in {
            "pcap_packet_parsing",
            "flow_aggregation_feature_extraction",
            "supervised_warm_inference",
            "anomaly_warm_inference",
            "fusion",
        }
    ]
    names = [str(row["component"]).replace("_", "\n") for row in selected]
    p50 = [float(row["latency_p50_ms"]) for row in selected]
    p95 = [float(row["latency_p95_ms"]) for row in selected]
    positions = range(len(names))
    figure, axis = plt.subplots(figsize=(10, 5.5))
    axis.bar([position - 0.18 for position in positions], p50, width=0.36, label="p50")
    axis.bar([position + 0.18 for position in positions], p95, width=0.36, label="p95")
    axis.set_yscale("log")
    axis.set_ylabel("Latency (ms, log scale)")
    axis.set_title("Phase 13 controlled development-host latency")
    axis.set_xticks(list(positions), names)
    axis.legend()
    axis.grid(axis="y", alpha=0.25)
    figure.text(
        0.5,
        0.01,
        "Controlled synthetic workload; not an SLA, benchmark, or production claim.",
        ha="center",
        fontsize=8,
    )
    destination = OUTPUT_ROOT / "phase13-component-latency.png"
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    figure.tight_layout(rect=(0, 0.04, 1, 1))
    figure.savefig(
        destination,
        dpi=160,
        metadata={"Software": "AegisHunt Phase 14 evidence builder"},
    )
    plt.close(figure)
    return destination


def build_sample_figure() -> Path:
    """Plot only the reviewed source aggregate profile retained by the generator."""

    payload = _read(SAMPLE_SOURCE)
    sources = payload.get("sources")
    if not isinstance(sources, list) or len(sources) != 2:
        raise ValueError("sample provenance source inventory is invalid")
    names = [str(source["filename"]).removesuffix(".pcap") for source in sources]
    packets = [int(source["observed_packet_count"]) for source in sources]
    flows = [int(source["observed_flow_count"]) for source in sources]
    positions = range(len(names))
    figure, primary = plt.subplots(figsize=(8, 5))
    primary.bar([position - 0.18 for position in positions], packets, 0.36, label="Packets")
    secondary = primary.twinx()
    secondary.bar(
        [position + 0.18 for position in positions],
        flows,
        0.36,
        color="#d97706",
        label="Flows",
    )
    primary.set_xticks(list(positions), names)
    primary.set_ylabel("Observed packets")
    secondary.set_ylabel("Observed flows")
    primary.set_title("Uploaded PCAP aggregate profiles used for safe sample derivation")
    handles_a, labels_a = primary.get_legend_handles_labels()
    handles_b, labels_b = secondary.get_legend_handles_labels()
    primary.legend(handles_a + handles_b, labels_a + labels_b, loc="upper right")
    figure.text(
        0.5,
        0.01,
        "Names are unverified presentation profiles, not ground-truth labels.",
        ha="center",
        fontsize=8,
    )
    destination = OUTPUT_ROOT / "phase14-uploaded-sample-profiles.png"
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    figure.tight_layout(rect=(0, 0.04, 1, 1))
    figure.savefig(
        destination,
        dpi=160,
        metadata={"Software": "AegisHunt Phase 14 evidence builder"},
    )
    plt.close(figure)
    return destination


def main() -> None:
    for path in (build_performance_figure(), build_sample_figure()):
        print(path.relative_to(PROJECT_ROOT))


if __name__ == "__main__":
    main()
