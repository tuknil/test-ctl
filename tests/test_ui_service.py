"""The demo UI is a separate service configured by API_ENDPOINT."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from control_translation.config import Settings
from control_translation_ui.config import UISettings

REPO_ROOT = Path(__file__).resolve().parents[1]
UI_DIR = REPO_ROOT / "ui"


@pytest.fixture
def ui_client(monkeypatch):
    """Build the UI app against explicit settings, bypassing the env cache.

    The static mount is bound at import time, so only the request-time
    settings (the API endpoint) are meaningfully overridable here; static-dir
    behavior is covered through `UISettings` directly.
    """
    import control_translation_ui.app as ui_app

    def build(**overrides) -> TestClient:
        monkeypatch.setattr(
            ui_app, "_SETTINGS", UISettings(static_dir=UI_DIR, **overrides)
        )
        return TestClient(ui_app.app)

    return build


# ---------------------------------------------------------------------------
# UI service
# ---------------------------------------------------------------------------


def test_ui_service_serves_the_demo_page(ui_client):
    response = ui_client().get("/")

    assert response.status_code == 200
    assert 'id="runsDashboard"' in response.text
    assert 'id="runsTableBody"' in response.text
    assert "Stored runs and translations" in response.text


def test_ui_service_renders_the_diagnostic_log(ui_client):
    response = ui_client().get("/app.js")

    assert response.status_code == 200
    assert "Diagnostic log" in response.text
    assert "Root cause" in response.text
    assert "server/container log" in response.text


def test_ui_service_renders_candidate_artifact_and_limitations(ui_client):
    response = ui_client().get("/app.js")

    assert response.status_code == 200
    assert "candidate.candidate_artifact.content_ref" in response.text
    assert "candidate.limitations" in response.text


def test_config_js_publishes_the_configured_api_endpoint(ui_client):
    response = ui_client(api_endpoint="https://api.example.com/").get("/config.js")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/javascript")
    # A stale endpoint after a repoint would be silent, so never cache it.
    assert response.headers["cache-control"] == "no-store"
    assert (
        'window.CONTROL_TRANSLATION_CONFIG = Object.freeze('
        '{"apiEndpoint": "https://api.example.com"});' in response.text
    )


def test_config_js_escapes_the_endpoint_value(ui_client):
    # The value is operator-supplied, but it lands inside a script tag.
    response = ui_client(api_endpoint='https://x/";alert(1);x').get("/config.js")

    # The quote is escaped, so it cannot terminate the JS string literal.
    assert '\\";alert(1);x' in response.text
    assert '/";alert(1);x' not in response.text


def test_empty_endpoint_means_same_origin(ui_client):
    response = ui_client(api_endpoint="").get("/config.js")

    assert '{"apiEndpoint": ""}' in response.text


def test_ui_readiness_reports_the_resolved_endpoint(ui_client):
    response = ui_client(api_endpoint="https://api.example.com").get("/ready")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ready",
        "api_endpoint": "https://api.example.com",
    }


def test_ui_health_needs_no_configuration(ui_client):
    assert ui_client(api_endpoint="not-a-url").get("/health").json() == {
        "status": "ok"
    }


@pytest.mark.parametrize(
    "endpoint",
    ["not-a-url", "ftp://api.example.com", "https://", "https://api/x?a=1"],
)
def test_misconfigured_endpoint_fails_readiness(ui_client, endpoint: str):
    response = ui_client(api_endpoint=endpoint).get("/ready")

    assert response.status_code == 503
    assert response.json()["detail"]["configuration_errors"]


def test_missing_static_directory_fails_readiness():
    settings = UISettings(
        api_endpoint="https://api.example.com",
        static_dir=REPO_ROOT / "does-not-exist",
    )

    assert not settings.ready
    assert any("is not a directory" in item for item in settings.configuration_errors)


def test_ui_service_holds_no_capability_configuration():
    # A UI deployment must not be reachable by a credential it cannot use.
    fields = set(UISettings.model_fields)

    assert fields == {"api_endpoint", "host", "port", "static_dir"}


# ---------------------------------------------------------------------------
# Static assets
# ---------------------------------------------------------------------------


def test_pages_load_the_generated_runtime_config_before_using_it():
    index = (UI_DIR / "index.html").read_text()
    demo = (UI_DIR / "demo.html").read_text()

    assert index.index('src="/config.js"') < index.index('src="/app.js"')
    assert 'src="/config.js"' in demo


def test_no_asset_calls_the_api_on_a_hardcoded_same_origin_path():
    sources = {
        path.name: path.read_text()
        for path in (UI_DIR / "app.js", UI_DIR / "demo.html")
    }

    for name, source in sources.items():
        assert not re.search(r"""fetch\(\s*[`'"]/""", source), (
            f"{name} still calls the API on a same-origin path"
        )


# ---------------------------------------------------------------------------
# API service
# ---------------------------------------------------------------------------


def _api_client() -> TestClient:
    from control_translation.api import app

    return TestClient(app)


def test_api_service_no_longer_serves_the_ui():
    response = _api_client().get("/")

    assert response.status_code == 200
    payload = response.json()
    assert payload["service"] == "control-translation"
    assert payload["role"] == "api"
    assert "<html" not in response.text.lower()


def test_api_does_not_serve_ui_assets():
    assert _api_client().get("/app.js").status_code == 404


def test_cors_is_closed_by_default():
    assert Settings().cors_allowed_origins == ()


@pytest.mark.parametrize(
    "origins",
    [("*",), ("http://ui.example/app",), ("ui.example",), ("ftp://ui.example",)],
)
def test_unsafe_or_malformed_cors_origins_fail_readiness(origins: tuple[str, ...]):
    settings = Settings(cors_allowed_origins=origins)

    assert not settings.ready
    assert any("CORS_ALLOWED_ORIGINS" in item for item in settings.configuration_errors)


def test_configured_cors_origin_is_accepted():
    settings = Settings(cors_allowed_origins=("http://127.0.0.1:8080",))

    assert not [
        item for item in settings.configuration_errors if "CORS" in item
    ]


# ---------------------------------------------------------------------------
# Packaging
# ---------------------------------------------------------------------------


def test_ui_requirements_match_pyproject():
    """The UI image installs a hand-listed subset; keep the pins honest."""
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())
    declared = {
        re.split(r"[><=\[]", item, 1)[0].strip(): item
        for item in pyproject["project"]["dependencies"]
    }
    listed = [
        line.strip()
        for line in (REPO_ROOT / "ui-requirements.txt").read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]

    assert listed, "the UI image must declare its dependencies"
    for requirement in listed:
        name = re.split(r"[><=\[]", requirement, 1)[0].strip()
        assert name in declared, f"{name} is not a project dependency"
        assert requirement == declared[name], (
            f"{name} constraint drifted from pyproject.toml"
        )


def test_both_services_are_packaged():
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())
    packages = pyproject["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"]

    assert "src/control_translation" in packages
    assert "src/control_translation_ui" in packages


def test_api_image_does_not_ship_the_ui():
    dockerfile = (REPO_ROOT / "Dockerfile").read_text()

    assert "COPY ui" not in dockerfile
    assert (REPO_ROOT / "Dockerfile.ui").exists()
