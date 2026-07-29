"""Phase 12 Streamlit architecture and truthful-state tests."""

from __future__ import annotations

import inspect
import shutil
from pathlib import Path
from typing import Any, cast
from unittest.mock import Mock, call

import httpx
import pytest
import yaml
from fastapi.testclient import TestClient
from streamlit.testing.v1 import AppTest

from aegishunt.api.app import create_app
from aegishunt.config import CaseFeedbackSettings
from aegishunt.frontend import app
from aegishunt.frontend.client import AegisHuntApiClient
from aegishunt.frontend.components import markdown_table
from aegishunt.frontend.pages.overview import _active_alert_count
from aegishunt.storage import Database
from tests.e2e.test_phase_12_api_frontend import _settings

EXPECTED_PAGES = {
    "Overview",
    "Data Ingestion",
    "Traffic Explorer",
    "Alerts",
    "Threat Hunts",
    "Cases",
    "Model Lab",
    "Evaluation",
    "System Health",
}


def _button(test_app: AppTest, label: str) -> Any:
    matches = [item for item in test_app.button if item.label == label]
    assert len(matches) == 1, f"expected one button labelled {label!r}"
    return matches[0]


def test_frontend_exposes_nine_api_backed_pages() -> None:
    assert set(app.PAGES) == EXPECTED_PAGES
    source = inspect.getsource(app)
    assert "AegisHuntApiClient" in source
    assert "Database(" not in source
    assert "sqlalchemy" not in source
    assert "repositories" not in source
    assert "Session" not in source
    assert "phase/13-hardening" not in source


def test_streamlit_uses_only_the_explicit_nine_page_navigation() -> None:
    configuration = (
        Path(app.__file__).parents[3] / ".streamlit/config.toml"
    ).read_text(encoding="utf-8")
    assert "showSidebarNavigation = false" in configuration


def test_frontend_table_escapes_untrusted_markdown_without_arrow() -> None:
    rendered = markdown_table(
        (
            {
                "filename": "../../outside.pcap",
                "note": "[link](https://example.test) <script>alert(1)</script>",
            },
        )
    )
    assert r"\.\./\.\./outside\.pcap" in rendered
    assert r"\[link\]\(https://example\.test\)" in rendered
    assert r"\<script\>" in rendered
    assert "<script>" not in rendered
    source = inspect.getsource(
        __import__(
            "aegishunt.frontend.components",
            fromlist=["table"],
        ).table
    )
    assert "dataframe" not in source
    assert "unsafe_allow_html=False" in source


def test_frontend_page_modules_do_not_open_database_or_artifact_paths() -> None:
    pages_root = Path(app.__file__).with_name("pages")
    content = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted(pages_root.glob("*.py"))
    )
    forbidden = (
        "sqlalchemy",
        "Database(",
        "Repository(",
        "open(",
        "read_text(",
        "read_bytes(",
        "pickle",
        "joblib",
    )
    assert all(token not in content for token in forbidden)
    assert "attack probability" in content
    assert "public benchmark" in content
    assert "not a fact" in content
    assert "non-causal" in content


def test_all_primary_list_pages_use_bounded_pagination_controls() -> None:
    pages_root = Path(app.__file__).with_name("pages")
    for name in (
        "alerts.py",
        "cases.py",
        "evaluation.py",
        "hunts.py",
        "ingestion.py",
        "models.py",
        "system.py",
        "traffic.py",
    ):
        content = (pages_root / name).read_text(encoding="utf-8")
        assert "pagination_offset(" in content, name
        assert "paginated_table(" in content, name


def test_pagination_controls_move_between_bounded_pages() -> None:
    script = """
import streamlit as st
from aegishunt.api.contracts import Page
from aegishunt.frontend.components import paginated_table, pagination_offset

offset = pagination_offset("component-test")
page = Page[int](
    items=[offset],
    total=3,
    limit=2,
    offset=offset,
    next_offset=2 if offset == 0 else None,
)
paginated_table(
    page,
    ({"offset": offset},),
    key="component-test",
    empty_message="empty",
)
"""
    test_app = AppTest.from_string(script)
    test_app.run()
    assert not test_app.exception
    assert "Page 1 of 2" in test_app.caption[0].value
    next_button = [item for item in test_app.button if item.label == "Next"][0]
    next_button.click().run()
    assert not test_app.exception
    assert "Page 2 of 2" in test_app.caption[0].value
    previous = [item for item in test_app.button if item.label == "Previous"][0]
    assert not previous.disabled


def test_overview_active_alerts_include_open_and_acknowledged() -> None:
    client = Mock(spec=AegisHuntApiClient)
    client.alerts.side_effect = (Mock(total=2), Mock(total=3))

    assert _active_alert_count(cast(AegisHuntApiClient, client)) == 5
    assert client.alerts.call_args_list == [
        call(limit=1, alert_status="open"),
        call(limit=1, alert_status="acknowledged"),
    ]


def test_frontend_starts_with_truthful_api_unavailable_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable(
        self: httpx.Client,
        method: str,
        url: str,
        **kwargs: object,
    ) -> httpx.Response:
        del self, method, url, kwargs
        raise httpx.ConnectError("controlled unavailable API")

    monkeypatch.setattr(httpx.Client, "request", unavailable)
    test_app = AppTest.from_file(app.__file__, default_timeout=5.0)
    test_app.run(timeout=10.0)
    assert not test_app.exception
    assert any("API is unavailable" in item.value for item in test_app.error)
    rendered = "\n".join(
        item.value
        for collection in (
            test_app.title,
            test_app.caption,
            test_app.info,
            test_app.warning,
            test_app.error,
        )
        for item in collection
    )
    assert "Research prototype only" in rendered
    assert "Phase 13 hardening: Implementation complete — awaiting PR review" in rendered
    assert "Phase 14: Not started" in rendered
    assert "authentication/RBAC not implemented" in rendered


def test_all_frontend_pages_render_real_populated_api_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise all nine GET-backed views against the actual FastAPI contracts."""

    settings = _settings(tmp_path)
    artifact_root = Path("tmp") / f"phase12-ui-{tmp_path.name}"
    policy_payload = yaml.safe_load(
        (Path(__file__).parents[2] / "configs/case_feedback.yaml").read_text(
            encoding="utf-8"
        )
    )
    assert isinstance(policy_payload, dict)
    policy_payload.update(
        {
            "export_root": str(artifact_root / "feedback"),
            "report_root": str(artifact_root / "cases"),
            "candidate_root": str(artifact_root / "candidates"),
        }
    )
    policy_path = tmp_path / "case-feedback.yaml"
    policy_path.write_text(
        yaml.safe_dump(policy_payload, sort_keys=False),
        encoding="utf-8",
    )
    settings = settings.model_copy(
        update={"case_feedback": CaseFeedbackSettings(policy_path=policy_path)}
    )
    database = Database(settings.database)
    api = TestClient(create_app(settings, database))
    api.__enter__()
    demo_root = (
        Path(__file__).parents[2]
        / settings.web.demo_artifact_root
        / f"{settings.web.demo_namespace}-{settings.web.demo_operation_version}"
    )
    try:
        demo = api.post(
            "/demo/sample",
            json={
                "actor": "frontend-test",
                "reason": "populate all API-backed frontend views",
                "confirm": True,
                "sample_id": "phase12-demo-pcap",
                "create_case": True,
            },
        )
        assert demo.status_code == 200, demo.text
        demo_payload = demo.json()

        class ApiTransport(httpx.BaseTransport):
            def handle_request(self, request: httpx.Request) -> httpx.Response:
                path = request.url.path
                if request.url.query:
                    path = f"{path}?{request.url.query.decode()}"
                response = api.request(
                    request.method,
                    path,
                    content=request.content,
                    headers=dict(request.headers),
                )
                return httpx.Response(
                    response.status_code,
                    content=response.content,
                    headers=dict(response.headers),
                    request=request,
                )

        original_init = AegisHuntApiClient.__init__

        def configured_init(
            self: AegisHuntApiClient,
            base_url: str,
            **kwargs: object,
        ) -> None:
            kwargs["transport"] = ApiTransport()
            original_init(self, base_url, **kwargs)

        monkeypatch.setattr(AegisHuntApiClient, "__init__", configured_init)
        test_app = AppTest.from_file(app.__file__, default_timeout=10.0)
        test_app.run(timeout=20.0)
        assert not test_app.exception
        overview_metrics = {item.label: item.value for item in test_app.metric}
        assert overview_metrics["Processed flows"] == "2"
        assert overview_metrics["Active alerts"] == "2"
        assert overview_metrics["Open hypotheses"] == "1"
        assert overview_metrics["Open cases"] == "1"
        assert float(overview_metrics["Observed runtime p95 (ms)"]) >= 0
        assert overview_metrics["Latency observations (n)"] == "1"

        test_app.text_area[0].set_value("explicit idempotent demo rerun")
        test_app.checkbox[1].check()
        _button(test_app, "Run controlled demo").click().run(timeout=20.0)
        assert not test_app.exception
        assert test_app.success

        test_app.radio[0].set_value("Data Ingestion").run(timeout=20.0)
        test_app.selectbox[1].set_value("phase2-benign-pcap")
        test_app.text_area[1].set_value("explicit packaged sample ingestion")
        test_app.checkbox[1].check()
        _button(test_app, "Ingest sample").click().run(timeout=20.0)
        assert not test_app.exception
        assert test_app.success
        assert any(item.label == "Run one worker" for item in test_app.button)

        test_app.radio[0].set_value("Traffic Explorer").run(timeout=20.0)
        assert not test_app.exception
        traffic_tabs = {item.label for item in test_app.tabs}
        assert {
            "Flow detail",
            "Behavioral features",
            "Traffic distribution",
            "Detection",
            "Alert",
        } <= traffic_tabs
        assert any("Page 1 of 1" in item.value for item in test_app.caption)

        test_app.radio[0].set_value("Alerts").run(timeout=20.0)
        alert_tabs = {item.label for item in test_app.tabs}
        assert "Related investigations" in alert_tabs
        assert "Reasons and entities" in alert_tabs
        assert "Limitations" in alert_tabs
        test_app.text_area[0].set_value("explicit analyst verdict")
        test_app.checkbox[0].check()
        _button(test_app, "Update verdict").click().run(timeout=20.0)
        assert not test_app.exception
        assert test_app.success

        test_app.radio[0].set_value("Threat Hunts").run(timeout=20.0)
        test_app.text_area[0].set_value("explicit hypothesis review")
        test_app.checkbox[0].check()
        _button(test_app, "Apply").click().run(timeout=20.0)
        assert not test_app.exception
        assert test_app.success

        test_app.radio[0].set_value("Cases").run(timeout=20.0)
        assert "Audit History" in {item.label for item in test_app.tabs}
        test_app.text_input[0].set_value("investigating")
        test_app.text_area[0].set_value("explicit case status update")
        test_app.checkbox[0].check()
        _button(test_app, "Update case").click().run(timeout=20.0)
        assert not test_app.exception
        assert test_app.success

        test_app.text_area[1].set_value("Reviewed the controlled flow evidence.")
        test_app.text_area[2].set_value("append analyst note")
        test_app.checkbox[1].check()
        _button(test_app, "Add note").click().run(timeout=20.0)
        assert not test_app.exception
        assert test_app.success

        test_app.text_input[3].set_value(demo_payload["flow_ids"][0])
        test_app.text_area[3].set_value("Controlled sample NetworkFlow reference.")
        test_app.text_area[4].set_value("append immutable evidence reference")
        test_app.checkbox[2].check()
        _button(test_app, "Add evidence reference").click().run(timeout=20.0)
        assert not test_app.exception
        assert test_app.success

        test_app.selectbox[1].set_value("verdict")
        test_app.text_input[0].set_value("true_positive")
        test_app.text_area[0].set_value("record explicit case verdict")
        test_app.checkbox[0].check()
        _button(test_app, "Update case").click().run(timeout=20.0)
        assert not test_app.exception
        assert test_app.success

        test_app.text_area[5].set_value("Human-supplied controlled feedback.")
        test_app.text_area[6].set_value("record analyst feedback")
        test_app.slider[0].set_value(0.9)
        test_app.checkbox[3].check()
        _button(test_app, "Record feedback").click().run(timeout=20.0)
        assert not test_app.exception
        assert test_app.success, [item.value for item in test_app.error]

        test_app.text_area[7].set_value("Controlled case review completed.")
        test_app.text_area[8].set_value("explicit case closure")
        test_app.checkbox[4].check()
        _button(test_app, "Close case").click().run(timeout=20.0)
        assert not test_app.exception
        assert test_app.success

        test_app.text_input[9].set_value("1.0.0")
        test_app.text_area[9].set_value("generate versioned case report")
        test_app.checkbox[5].check()
        _button(test_app, "Generate verified report").click().run(timeout=20.0)
        assert not test_app.exception
        assert test_app.success
        assert test_app.get("download_button")

        test_app.text_input[11].set_value("1.0.0")
        test_app.text_area[10].set_value("create reviewed feedback export")
        test_app.checkbox[6].check()
        _button(test_app, "Create data-only artifact").click().run(timeout=20.0)
        assert not test_app.exception
        assert test_app.success

        test_app.radio[0].set_value("Model Lab").run(timeout=20.0)
        test_app.text_input[0].set_value("9.9.9")
        test_app.text_input[1].set_value("unapproved:9.9.9")
        test_app.text_area[0].set_value("verify approved dataset gate")
        test_app.checkbox[0].check()
        _button(test_app, "Train verified candidate").click().run(timeout=20.0)
        assert not test_app.exception
        assert any("approved" in item.value for item in test_app.error)

        test_app.radio[0].set_value("Evaluation").run(timeout=20.0)
        assert not test_app.exception
        test_app.radio[0].set_value("System Health").run(timeout=20.0)
        assert not test_app.exception

        visible = "\n".join(
            item.value
            for collection in (
                test_app.title,
                test_app.caption,
                test_app.info,
                test_app.warning,
                test_app.error,
            )
            for item in collection
        )
        assert "System Health" in visible
        assert "Live capture: disabled" in visible
        assert "Automatic recovery: disabled" in visible
        health_metrics = {item.label: item.value for item in test_app.metric}
        assert int(health_metrics["PID"]) > 0
        assert int(health_metrics["Process RSS bytes"]) > 0
        assert int(health_metrics["Active threads"]) > 0
        assert health_metrics["Observations (n)"] == "1"
    finally:
        api.__exit__(None, None, None)
        database.dispose()
        if demo_root.is_dir() and not demo_root.is_symlink():
            shutil.rmtree(demo_root)
        generated_root = Path(__file__).parents[2] / artifact_root
        if generated_root.is_dir() and not generated_root.is_symlink():
            shutil.rmtree(generated_root)
