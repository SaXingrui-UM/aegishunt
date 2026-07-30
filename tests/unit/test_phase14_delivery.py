"""Final-delivery static contract tests."""

from pathlib import Path

import yaml

from aegishunt.config import load_settings
from scripts.validate_phase14_delivery import validate

ROOT = Path(__file__).parents[2]


def test_phase14_delivery_validator_passes_committed_surface() -> None:
    result = validate(ROOT)

    assert result == {
        "status": "PASS",
        "application_version": "1.0.0",
        "feature_count": 43,
        "sample_count": 2,
        "required_file_count": 35,
    }


def test_final_delivery_config_does_not_rewrite_historical_default() -> None:
    historical = load_settings(ROOT / "configs/application.yaml")
    final_delivery = load_settings(ROOT / "configs/final-delivery.yaml")

    assert historical.web.demo_sample_ids == ("phase12-demo-pcap",)
    assert historical.web.demo_namespace == "phase12-controlled-demo"
    assert final_delivery.web.demo_sample_ids == (
        "phase14-attack-like-pcap",
        "phase14-benign-like-pcap",
    )
    assert final_delivery.web.demo_namespace == "phase14-controlled-demo"


def test_phase14_compose_keeps_application_non_root_and_loopback_only() -> None:
    compose = yaml.safe_load((ROOT / "compose.yaml").read_text(encoding="utf-8"))

    assert set(compose["services"]) == {"init", "api", "worker", "frontend"}
    for service in compose["services"].values():
        assert service["user"] == "10001:10001"
        assert service["init"] is True
        assert service["read_only"] is True
        assert service["cap_drop"] == ["ALL"]
        assert "no-new-privileges:true" in service["security_opt"]
        assert service.get("privileged") is not True
        assert service.get("network_mode") != "host"
    assert compose["services"]["api"]["ports"] == ["127.0.0.1:8000:8000"]
    assert compose["services"]["frontend"]["ports"] == ["127.0.0.1:8501:8501"]
    assert compose["networks"]["aegishunt-internal"] == {"driver": "bridge"}


def test_phase14_docker_ci_waits_for_services_after_restart() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    assert "restart api worker frontend" in workflow
    assert "service health did not recover after restart" in workflow
    assert '"http://127.0.0.1:8501/_stcore/health"' in workflow
    assert "sleep 10" not in workflow


def test_phase14_dockerfile_uses_wheel_and_non_root_runtime() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert "python -m build --wheel" in dockerfile
    assert "pip install --no-cache-dir /tmp/*.whl" in dockerfile
    assert "USER 10001:10001" in dockerfile
    assert "PYTHONPATH" not in dockerfile


def test_phase14_docker_gate_runs_full_analyst_feedback_chain() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    assert '"/demo/sample"' in workflow
    assert '"create_case": True' in workflow
    assert 'f"/cases/{case_id}/notes"' in workflow
    assert '"verdict": "needs_more_information"' in workflow
    assert 'f"/cases/{case_id}/feedback"' in workflow
    assert 'case["notes"] and case["feedback"]' in workflow
    assert "--create-case" not in workflow
