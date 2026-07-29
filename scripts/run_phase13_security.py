"""Run the auditable Phase 13 dependency, secret, and static-analysis gates."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from collections import Counter
from dataclasses import asdict, dataclass
from importlib.metadata import version
from pathlib import Path
from typing import Any

import yaml
from detect_secrets.core.scan import scan_file
from detect_secrets.settings import default_settings

SECRET_ALLOWLIST = Path("configs/hardening/phase-13-secret-allowlist.yaml")
MAX_HISTORY_BLOB_BYTES = 1_048_576
BLOCKING_BANDIT_SEVERITIES = frozenset({"MEDIUM", "HIGH"})


@dataclass(frozen=True, order=True)
class SecretCandidate:
    """A redacted detect-secrets result suitable for deterministic comparison."""

    path: str
    detector_type: str
    secret_hash: str


def _run(
    command: list[str],
    *,
    cwd: Path,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        check=check,
        capture_output=True,
        text=True,
        timeout=300,
    )


def load_secret_allowlist(path: Path) -> dict[SecretCandidate, dict[str, Any]]:
    """Load an exact, rationale-bearing false-positive allowlist."""

    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("schema_version") != "1.0.0":
        raise ValueError("secret allowlist schema is missing or unsupported")
    raw_candidates = payload.get("candidates")
    if not isinstance(raw_candidates, list):
        raise ValueError("secret allowlist candidates must be a list")
    result: dict[SecretCandidate, dict[str, Any]] = {}
    for raw in raw_candidates:
        if not isinstance(raw, dict):
            raise ValueError("secret allowlist candidate must be a mapping")
        candidate = SecretCandidate(
            path=str(raw.get("path", "")),
            detector_type=str(raw.get("type", "")),
            secret_hash=str(raw.get("secret_hash", "")),
        )
        rationale = raw.get("rationale")
        reviewed_as = raw.get("reviewed_as")
        if (
            not candidate.path
            or not candidate.detector_type
            or len(candidate.secret_hash) != 40
            or not isinstance(rationale, str)
            or not rationale.strip()
            or reviewed_as != "false_positive"
        ):
            raise ValueError("secret allowlist candidate is incomplete")
        if candidate in result:
            raise ValueError(f"duplicate secret allowlist candidate: {candidate.path}")
        result[candidate] = raw
    return result


def _candidate(path: str, potential: Any) -> SecretCandidate:
    return SecretCandidate(
        path=path,
        detector_type=str(potential.type),
        secret_hash=str(potential.secret_hash),
    )


def tracked_secret_candidates(
    project_root: Path,
    *,
    extra_paths: tuple[Path, ...] = (),
) -> tuple[SecretCandidate, ...]:
    """Scan the tracked worktree plus explicitly supplied generated review files."""

    output = _run(["git", "ls-files", "-z"], cwd=project_root).stdout
    paths = [Path(item) for item in output.split("\0") if item]
    paths.extend(path for path in extra_paths if (project_root / path).is_file())
    candidates: set[SecretCandidate] = set()
    with default_settings():
        for relative in sorted(set(paths)):
            if relative == SECRET_ALLOWLIST:
                continue
            absolute = project_root / relative
            if not absolute.is_file():
                continue
            for potential in scan_file(str(absolute)):
                candidates.add(_candidate(relative.as_posix(), potential))
    return tuple(sorted(candidates))


def generated_pr_body_candidates(
    project_root: Path,
) -> tuple[tuple[SecretCandidate, ...], bool]:
    """Scan a local generated body or the GitHub pull-request event body."""

    display_path = Path(".github/generated/phase-13-pr.md")
    local_path = project_root / display_path
    if local_path.is_file():
        with default_settings():
            candidates = tuple(
                sorted(
                    _candidate(display_path.as_posix(), potential)
                    for potential in scan_file(str(local_path))
                )
            )
        return candidates, True

    event_path_value = os.environ.get("GITHUB_EVENT_PATH")
    if not event_path_value:
        return (), False
    try:
        event = json.loads(Path(event_path_value).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("GitHub event payload cannot be read safely") from exc
    pull_request = event.get("pull_request") if isinstance(event, dict) else None
    body = pull_request.get("body") if isinstance(pull_request, dict) else None
    if not isinstance(body, str):
        return (), False
    with tempfile.TemporaryDirectory(prefix="aegishunt-pr-body-") as temp_name:
        temporary = Path(temp_name) / "phase-13-pr.md"
        temporary.write_text(body, encoding="utf-8")
        with default_settings():
            candidates = tuple(
                sorted(
                    _candidate(display_path.as_posix(), potential)
                    for potential in scan_file(str(temporary))
                )
            )
    return candidates, True


def history_secret_candidates(
    project_root: Path,
) -> tuple[tuple[SecretCandidate, ...], dict[str, int]]:
    """Scan every unique bounded text blob reachable from Git history."""

    objects = _run(["git", "rev-list", "--objects", "--all"], cwd=project_root).stdout
    candidates: set[SecretCandidate] = set()
    seen_objects: set[str] = set()
    counts = {
        "unique_text_blobs_scanned": 0,
        "binary_blobs_skipped": 0,
        "oversized_blobs_skipped": 0,
    }
    with tempfile.TemporaryDirectory(prefix="aegishunt-secret-history-") as temp_name:
        temp_root = Path(temp_name)
        with default_settings():
            for entry in objects.splitlines():
                parts = entry.split(" ", 1)
                if len(parts) != 2:
                    continue
                object_id, raw_path = parts
                if object_id in seen_objects:
                    continue
                seen_objects.add(object_id)
                if (
                    _run(["git", "cat-file", "-t", object_id], cwd=project_root)
                    .stdout.strip()
                    != "blob"
                ):
                    continue
                size = int(
                    _run(["git", "cat-file", "-s", object_id], cwd=project_root).stdout
                )
                if size > MAX_HISTORY_BLOB_BYTES:
                    counts["oversized_blobs_skipped"] += 1
                    continue
                content = subprocess.run(
                    ["git", "cat-file", "blob", object_id],
                    cwd=project_root,
                    check=True,
                    capture_output=True,
                    timeout=30,
                ).stdout
                if b"\0" in content:
                    counts["binary_blobs_skipped"] += 1
                    continue
                relative = Path(raw_path)
                if relative == SECRET_ALLOWLIST:
                    continue
                target = temp_root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
                counts["unique_text_blobs_scanned"] += 1
                for potential in scan_file(str(target)):
                    candidates.add(_candidate(relative.as_posix(), potential))
                target.unlink()
    return tuple(sorted(candidates)), counts


def evaluate_secret_candidates(
    *,
    tracked: tuple[SecretCandidate, ...],
    history: tuple[SecretCandidate, ...],
    allowlist: dict[SecretCandidate, dict[str, Any]],
) -> dict[str, Any]:
    """Fail closed on every scanner result that lacks an exact reviewed entry."""

    observed = set(tracked) | set(history)
    unreviewed = sorted(observed - set(allowlist))
    stale = sorted(set(allowlist) - observed)
    return {
        "status": "PASS" if not unreviewed and not stale else "FAIL",
        "tracked_candidates": len(tracked),
        "history_candidates": len(history),
        "reviewed_false_positives": len(observed & set(allowlist)),
        "confirmed_secrets": len(unreviewed),
        "unreviewed": [asdict(item) for item in unreviewed],
        "stale_allowlist_entries": [asdict(item) for item in stale],
        "redaction": "candidate values are never emitted; only one-way hashes are recorded",
    }


def evaluate_pip_audit(payload: dict[str, Any]) -> dict[str, Any]:
    """Evaluate pip-audit JSON without treating missing or malformed data as success."""

    dependencies = payload.get("dependencies")
    if not isinstance(dependencies, list):
        raise ValueError("pip-audit JSON does not contain dependencies")
    findings: list[dict[str, Any]] = []
    for dependency in dependencies:
        if not isinstance(dependency, dict):
            raise ValueError("pip-audit dependency entry is invalid")
        for vulnerability in dependency.get("vulns", []):
            if not isinstance(vulnerability, dict) or not vulnerability.get("id"):
                raise ValueError("pip-audit vulnerability entry is invalid")
            findings.append(
                {
                    "dependency": dependency.get("name"),
                    "installed_version": dependency.get("version"),
                    "advisory_id": vulnerability["id"],
                    "fix_versions": vulnerability.get("fix_versions", []),
                    "severity": vulnerability.get("severity", "not_reported_by_tool"),
                }
            )
    return {
        "status": "PASS" if not findings else "FAIL",
        "dependency_count": len(dependencies),
        "finding_count": len(findings),
        "findings": findings,
    }


def evaluate_bandit(payload: dict[str, Any]) -> dict[str, Any]:
    """Block Medium/High Bandit findings and retain sanitized Low counts."""

    results = payload.get("results")
    errors = payload.get("errors")
    if not isinstance(results, list) or not isinstance(errors, list):
        raise ValueError("Bandit JSON is malformed")
    if errors:
        return {"status": "FAIL", "errors": len(errors), "findings": len(results)}
    severities = Counter(str(item.get("issue_severity", "UNKNOWN")) for item in results)
    blocking = sum(severities[level] for level in BLOCKING_BANDIT_SEVERITIES)
    return {
        "status": "PASS" if blocking == 0 else "FAIL",
        "errors": 0,
        "findings": len(results),
        "severity_counts": dict(sorted(severities.items())),
        "blocking_findings": blocking,
        "suppressions": int(payload.get("metrics", {}).get("_totals", {}).get("nosec", 0)),
    }


def run_dependency_scan(project_root: Path, temp_root: Path) -> dict[str, Any]:
    pip_check = _run([sys.executable, "-m", "pip", "check"], cwd=project_root, check=False)
    audit_path = temp_root / "pip-audit.json"
    audit = _run(
        [
            sys.executable,
            "-m",
            "pip_audit",
            "--format",
            "json",
            "--output",
            str(audit_path),
        ],
        cwd=project_root,
        check=False,
    )
    if not audit_path.is_file():
        raise RuntimeError("pip-audit did not produce JSON output")
    result = evaluate_pip_audit(json.loads(audit_path.read_text(encoding="utf-8")))
    result.update(
        {
            "tool": "pip-audit",
            "tool_version": version("pip-audit"),
            "python_version": sys.version.split()[0],
            "pip_check_status": "PASS" if pip_check.returncode == 0 else "FAIL",
            "network_status": "available" if audit_path.is_file() else "unavailable",
        }
    )
    if pip_check.returncode != 0 or audit.returncode != 0:
        result["status"] = "FAIL"
    return result


def run_bandit_scan(project_root: Path, temp_root: Path) -> dict[str, Any]:
    output_path = temp_root / "bandit.json"
    completed = _run(
        [
            sys.executable,
            "-m",
            "bandit",
            "-r",
            "src/aegishunt",
            "scripts",
            "-f",
            "json",
            "-o",
            str(output_path),
        ],
        cwd=project_root,
        check=False,
    )
    if not output_path.is_file():
        raise RuntimeError("Bandit did not produce JSON output")
    result = evaluate_bandit(json.loads(output_path.read_text(encoding="utf-8")))
    result.update({"tool": "bandit", "tool_version": version("bandit")})
    if completed.returncode not in {0, 1}:
        result["status"] = "FAIL"
    return result


def run_secret_scan(project_root: Path) -> dict[str, Any]:
    allowlist = load_secret_allowlist(project_root / SECRET_ALLOWLIST)
    tracked = tracked_secret_candidates(project_root)
    generated, generated_scanned = generated_pr_body_candidates(project_root)
    tracked = tuple(sorted(set(tracked) | set(generated)))
    history, counts = history_secret_candidates(project_root)
    result = evaluate_secret_candidates(
        tracked=tracked,
        history=history,
        allowlist=allowlist,
    )
    result.update(
        {
            "tool": "detect-secrets",
            "tool_version": version("detect-secrets"),
            "history_included": True,
            "generated_pr_body_scanned": generated_scanned,
            **counts,
        }
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/test-reports/phase-13/security-summary.json"),
    )
    arguments = parser.parse_args()
    project_root = Path(__file__).resolve().parents[1]
    output_path = (
        arguments.output
        if arguments.output.is_absolute()
        else project_root / arguments.output
    )
    with tempfile.TemporaryDirectory(prefix="aegishunt-security-gate-") as temp_name:
        temp_root = Path(temp_name)
        result: dict[str, Any] = {
            "schema_version": "1.0.0",
            "dependency": run_dependency_scan(project_root, temp_root),
            "secrets": run_secret_scan(project_root),
            "static": run_bandit_scan(project_root, temp_root),
        }
    result["status"] = (
        "PASS"
        if all(result[name]["status"] == "PASS" for name in ("dependency", "secrets", "static"))
        else "FAIL"
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "status": result["status"],
                "dependency_findings": result["dependency"]["finding_count"],
                "confirmed_secrets": result["secrets"]["confirmed_secrets"],
                "bandit_findings": result["static"]["findings"],
                "bandit_blocking": result["static"]["blocking_findings"],
            },
            sort_keys=True,
        )
    )
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
