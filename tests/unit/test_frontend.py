"""Phase 12 Streamlit architecture and truthful-state tests."""

from __future__ import annotations

import inspect
import shutil
from pathlib import Path

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
    assert "Phase 13: Not started" in rendered
    assert "authentication/RBAC not implemented" in rendered
    assert "awaiting PR review" not in rendered


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
        assert demo.status_code == 200
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

        test_app.text_area[0].set_value("explicit idempotent demo rerun")
        test_app.checkbox[1].check()
        test_app.button[0].click().run(timeout=20.0)
        assert not test_app.exception
        assert test_app.success

        test_app.radio[0].set_value("Data Ingestion").run(timeout=20.0)
        test_app.selectbox[1].set_value("phase2-benign-pcap")
        test_app.text_area[1].set_value("explicit packaged sample ingestion")
        test_app.checkbox[1].check()
        test_app.button[1].click().run(timeout=20.0)
        assert not test_app.exception
        assert test_app.success

        test_app.radio[0].set_value("Traffic Explorer").run(timeout=20.0)
        assert not test_app.exception

        test_app.radio[0].set_value("Alerts").run(timeout=20.0)
        test_app.text_area[0].set_value("explicit analyst verdict")
        test_app.checkbox[0].check()
        test_app.button[0].click().run(timeout=20.0)
        assert not test_app.exception
        assert test_app.success

        test_app.radio[0].set_value("Threat Hunts").run(timeout=20.0)
        test_app.text_area[0].set_value("explicit hypothesis review")
        test_app.checkbox[0].check()
        test_app.button[0].click().run(timeout=20.0)
        assert not test_app.exception
        assert test_app.success

        test_app.radio[0].set_value("Cases").run(timeout=20.0)
        test_app.text_input[0].set_value("investigating")
        test_app.text_area[0].set_value("explicit case status update")
        test_app.checkbox[0].check()
        test_app.button[0].click().run(timeout=20.0)
        assert not test_app.exception
        assert test_app.success

        test_app.text_area[1].set_value("Reviewed the controlled flow evidence.")
        test_app.text_area[2].set_value("append analyst note")
        test_app.checkbox[1].check()
        test_app.button[1].click().run(timeout=20.0)
        assert not test_app.exception
        assert test_app.success

        test_app.text_input[3].set_value(demo_payload["flow_ids"][0])
        test_app.text_area[3].set_value("Controlled sample NetworkFlow reference.")
        test_app.text_area[4].set_value("append immutable evidence reference")
        test_app.checkbox[2].check()
        test_app.button[2].click().run(timeout=20.0)
        assert not test_app.exception
        assert test_app.success

        test_app.selectbox[1].set_value("verdict")
        test_app.text_input[0].set_value("true_positive")
        test_app.text_area[0].set_value("record explicit case verdict")
        test_app.checkbox[0].check()
        test_app.button[0].click().run(timeout=20.0)
        assert not test_app.exception
        assert test_app.success

        test_app.text_area[5].set_value("Human-supplied controlled feedback.")
        test_app.text_area[6].set_value("record analyst feedback")
        test_app.slider[0].set_value(0.9)
        test_app.checkbox[3].check()
        test_app.button[3].click().run(timeout=20.0)
        assert not test_app.exception
        assert test_app.success, [item.value for item in test_app.error]

        test_app.text_area[7].set_value("Controlled case review completed.")
        test_app.text_area[8].set_value("explicit case closure")
        test_app.checkbox[4].check()
        test_app.button[4].click().run(timeout=20.0)
        assert not test_app.exception
        assert test_app.success

        test_app.text_input[7].set_value("1.0.0")
        test_app.text_area[9].set_value("generate versioned case report")
        test_app.checkbox[5].check()
        test_app.button[5].click().run(timeout=20.0)
        assert not test_app.exception
        assert test_app.success
        assert test_app.get("download_button")

        test_app.text_input[9].set_value("1.0.0")
        test_app.text_area[10].set_value("create reviewed feedback export")
        test_app.checkbox[6].check()
        test_app.button[6].click().run(timeout=20.0)
        assert not test_app.exception
        assert test_app.success

        test_app.radio[0].set_value("Model Lab").run(timeout=20.0)
        test_app.text_input[0].set_value("9.9.9")
        test_app.text_input[1].set_value("unapproved:9.9.9")
        test_app.text_area[0].set_value("verify approved dataset gate")
        test_app.checkbox[0].check()
        test_app.button[0].click().run(timeout=20.0)
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
        assert any(item.value == "Unavailable" for item in test_app.metric)
    finally:
        api.__exit__(None, None, None)
        database.dispose()
        if demo_root.is_dir() and not demo_root.is_symlink():
            shutil.rmtree(demo_root)
        generated_root = Path(__file__).parents[2] / artifact_root
        if generated_root.is_dir() and not generated_root.is_symlink():
            shutil.rmtree(generated_root)
