"""Fail-closed validation for the committed Phase 14 delivery surface."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any
from uuid import UUID

import yaml

from aegishunt.config import FlowSettings
from aegishunt.flows.registry import FEATURE_DEFINITIONS, FEATURE_SCHEMA_VERSION
from aegishunt.flows.service import PcapFlowProcessor
from aegishunt.metadata import __version__

REQUIRED_FILES = (
    "Dockerfile",
    "compose.yaml",
    "configs/docker.yaml",
    "configs/final-delivery.yaml",
    "data/sample/phase14-attack-like.pcap",
    "data/sample/phase14-benign-like.pcap",
    "data/sample/phase14-sample-provenance.json",
    "docs/assets/feature_schema.json",
    "docs/assets/final-evidence-manifest.json",
    "docs/demo_guide.md",
    "docs/demo_script_3_5_minutes.md",
    "docs/docker_deployment.md",
    "docs/experiment_protocol.md",
    "docs/final_acceptance_report.md",
    "docs/final_experiment_summary.md",
    "docs/final_requirement_traceability.csv",
    "docs/final_requirement_traceability.md",
    "docs/installation.md",
    "docs/installation_linux.md",
    "docs/installation_macos.md",
    "docs/limitations.md",
    "docs/model_cards.md",
    "docs/release_checklist.md",
    "docs/releases/phase-14.md",
    "docs/thesis/artifact_index.md",
    "docs/thesis/contribution_summary.md",
    "docs/thesis/discussion_evidence.md",
    "docs/thesis/implementation_evidence.md",
    "docs/thesis/limitations_future_work.md",
    "docs/thesis/methodology_evidence.md",
    "docs/thesis/reproducibility_statement.md",
    "docs/thesis/research_question_traceability.md",
    "docs/thesis/results_evidence.md",
    "docs/threat_model.md",
    "docs/troubleshooting.md",
)
EXPECTED_SAMPLES = {
    "phase14-attack-like.pcap": (
        "efb3c6334ba5d484b1662fd34df748d90e5ee1208a5edda00adfbd76d7feaca8",
        1_017,
        42,
    ),
    "phase14-benign-like.pcap": (
        "5c93e494e6ebca226d22f4a0b888bda20d2e178c92f6096b40df0dfa75f6a61a",
        571,
        51,
    ),
}
MARKDOWN_LINK = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")


class Phase14ValidationError(ValueError):
    """Raised when final-delivery evidence violates its declared contract."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(65_536):
            digest.update(chunk)
    return digest.hexdigest()


def _load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise Phase14ValidationError(f"invalid JSON: {path}") from exc
    if not isinstance(payload, dict):
        raise Phase14ValidationError(f"JSON root must be an object: {path}")
    return payload


def _validate_required_files(root: Path) -> None:
    missing = [name for name in REQUIRED_FILES if not (root / name).is_file()]
    if missing:
        raise Phase14ValidationError(f"missing delivery files: {', '.join(missing)}")


def _validate_version(root: Path) -> None:
    metadata = (root / "src/aegishunt/metadata.py").read_text(encoding="utf-8")
    dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
    compose = (root / "compose.yaml").read_text(encoding="utf-8")
    if __version__ != "1.0.0" or '__version__ = "1.0.0"' not in metadata:
        raise Phase14ValidationError("application version is not the declared 1.0.0 release")
    if 'org.opencontainers.image.version="1.0.0"' not in dockerfile:
        raise Phase14ValidationError("container image label version is inconsistent")
    if "image: aegishunt:1.0.0" not in compose:
        raise Phase14ValidationError("Compose image version is inconsistent")


def _validate_compose(root: Path) -> None:
    payload = yaml.safe_load((root / "compose.yaml").read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("services"), dict):
        raise Phase14ValidationError("Compose services are invalid")
    services = payload["services"]
    if set(services) != {"init", "api", "worker", "frontend"}:
        raise Phase14ValidationError("Compose service inventory is not exact")
    for name, service in services.items():
        if not isinstance(service, dict):
            raise Phase14ValidationError(f"Compose service {name} is invalid")
        if service.get("privileged") is True or service.get("network_mode") == "host":
            raise Phase14ValidationError(f"Compose service {name} exceeds the local boundary")
        if service.get("user") != "10001:10001":
            raise Phase14ValidationError(f"Compose service {name} must be non-root")
        if service.get("init") is not True or service.get("read_only") is not True:
            raise Phase14ValidationError(f"Compose service {name} lacks process/root hardening")
        if service.get("cap_drop") != ["ALL"]:
            raise Phase14ValidationError(f"Compose service {name} must drop all capabilities")
        security = service.get("security_opt", [])
        if "no-new-privileges:true" not in security:
            raise Phase14ValidationError(f"Compose service {name} allows new privileges")
        for volume in service.get("volumes", []):
            if "/var/run/docker.sock" in str(volume):
                raise Phase14ValidationError("Compose must not mount the Docker socket")
        for port in service.get("ports", []):
            if not str(port).startswith("127.0.0.1:"):
                raise Phase14ValidationError("published Compose ports must bind to loopback")
    networks = payload.get("networks")
    if (
        not isinstance(networks, dict)
        or networks.get("aegishunt-internal", {}).get("internal") is not True
    ):
        raise Phase14ValidationError("Compose application network must be internal")


def _validate_feature_schema(root: Path) -> None:
    exported = _load_json(root / "docs/assets/feature_schema.json")
    runtime = FEATURE_DEFINITIONS
    if exported.get("schema_version") != FEATURE_SCHEMA_VERSION:
        raise Phase14ValidationError("exported feature schema version is stale")
    expected = [item.name for item in runtime]
    records = exported.get("features")
    if not isinstance(records, list):
        raise Phase14ValidationError("exported feature schema records are invalid")
    names = [record.get("name") for record in records if isinstance(record, dict)]
    if names != expected or len(names) != 43:
        raise Phase14ValidationError("exported feature order differs from runtime")


def _validate_evidence_manifest(root: Path) -> None:
    manifest = _load_json(root / "docs/assets/final-evidence-manifest.json")
    for section in ("sources", "outputs"):
        records = manifest.get(section)
        if not isinstance(records, list) or not records:
            raise Phase14ValidationError(f"evidence manifest {section} are invalid")
        for record in records:
            if not isinstance(record, dict) or not isinstance(record.get("path"), str):
                raise Phase14ValidationError("evidence manifest record is invalid")
            path = root / record["path"]
            if not path.is_file() or _sha256(path) != record.get("sha256"):
                raise Phase14ValidationError(f"evidence checksum mismatch: {path}")


def _validate_samples(root: Path) -> None:
    provenance = _load_json(root / "data/sample/phase14-sample-provenance.json")
    transformation = provenance.get("transformation")
    if not isinstance(transformation, dict):
        raise Phase14ValidationError("sample transformation disclosure is missing")
    if transformation.get("copies_source_payload") is not False:
        raise Phase14ValidationError("sample disclosure must reject source payload copying")
    if transformation.get("copies_source_addresses") is not False:
        raise Phase14ValidationError("sample disclosure must reject source address copying")
    outputs = provenance.get("outputs")
    if not isinstance(outputs, dict):
        raise Phase14ValidationError("sample output inventory is invalid")
    for name, (checksum, packet_count, flow_count) in EXPECTED_SAMPLES.items():
        path = root / "data/sample" / name
        if _sha256(path) != checksum:
            raise Phase14ValidationError(f"sample checksum mismatch: {name}")
        record = outputs.get(name)
        if not isinstance(record, dict) or record.get("sha256") != checksum:
            raise Phase14ValidationError(f"sample provenance mismatch: {name}")
        result = PcapFlowProcessor(
            FlowSettings(),
            max_records=2_000,
        ).process(
            path,
            source_id=UUID(int=0),
            capture_session_id=f"phase14-{name}",
        )
        if result.captured_packets != packet_count or len(result.flows) != flow_count:
            raise Phase14ValidationError(f"sample parser profile mismatch: {name}")
        if result.skipped_packets:
            raise Phase14ValidationError(f"sample contains skipped packets: {name}")


def _validate_links(root: Path) -> None:
    missing: list[str] = []
    for document in sorted((root / "docs").rglob("*.md")) + [root / "README.md"]:
        content = document.read_text(encoding="utf-8")
        for raw in MARKDOWN_LINK.findall(content):
            target = raw.split(maxsplit=1)[0].strip("<>")
            if (
                not target
                or target.startswith(("#", "http://", "https://", "mailto:"))
                or "{" in target
            ):
                continue
            resolved = (document.parent / target.split("#", maxsplit=1)[0]).resolve()
            try:
                resolved.relative_to(root.resolve())
            except ValueError:
                missing.append(f"{document.relative_to(root)} -> unsafe {target}")
                continue
            if not resolved.exists():
                missing.append(f"{document.relative_to(root)} -> {target}")
    if missing:
        raise Phase14ValidationError("invalid local documentation links: " + "; ".join(missing))


def _validate_truthfulness(root: Path) -> None:
    corpus = "\n".join(
        (root / name).read_text(encoding="utf-8")
        for name in (
            "README.md",
            "docs/final_experiment_summary.md",
            "docs/limitations.md",
            "docs/model_cards.md",
            "docs/releases/phase-14.md",
        )
    )
    required = (
        "not a public benchmark",
        "production validation",
        "attack probability",
        "Phase 14",
    )
    normalized = corpus.lower()
    for phrase in required:
        if phrase.lower() not in normalized:
            raise Phase14ValidationError(f"truthfulness disclosure is missing: {phrase}")
    if "/Users/" in corpus or "C:\\Users\\" in corpus:
        raise Phase14ValidationError("delivery documentation contains an absolute user path")


def validate(root: Path) -> dict[str, Any]:
    """Validate committed delivery contracts without changing the repository."""

    resolved = root.resolve()
    _validate_required_files(resolved)
    _validate_version(resolved)
    _validate_compose(resolved)
    _validate_feature_schema(resolved)
    _validate_evidence_manifest(resolved)
    _validate_samples(resolved)
    _validate_links(resolved)
    _validate_truthfulness(resolved)
    return {
        "status": "PASS",
        "application_version": __version__,
        "feature_count": len(FEATURE_DEFINITIONS),
        "sample_count": len(EXPECTED_SAMPLES),
        "required_file_count": len(REQUIRED_FILES),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    arguments = parser.parse_args()
    try:
        result = validate(arguments.project_root)
    except (OSError, Phase14ValidationError, yaml.YAMLError) as exc:
        print(f"Phase 14 delivery validation failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
