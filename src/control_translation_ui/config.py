"""Typed settings for the demo UI service.

The UI service is deliberately tiny: it needs to know where the capability
API lives and where its own static assets are. It holds no model, Databricks,
or callback configuration, so a UI deployment can never be given a
credential it has no use for.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv
from pydantic import BaseModel

load_dotenv(override=False)

DEFAULT_API_ENDPOINT = "http://127.0.0.1:8000"


class UISettings(BaseModel):
    # Published to the browser, which calls the API cross-origin. Must be a
    # URL the *browser* can resolve, not an internal service DNS name.
    api_endpoint: str = DEFAULT_API_ENDPOINT
    host: str = "0.0.0.0"
    port: int = 8080
    static_dir: Path = Path(__file__).resolve().parents[2] / "ui"

    @property
    def normalized_api_endpoint(self) -> str:
        """The API base URL without a trailing slash.

        An empty value means "same origin", which is only useful when the UI
        is fronted by a gateway that also routes the API paths.
        """
        return self.api_endpoint.strip().rstrip("/")

    @property
    def configuration_errors(self) -> list[str]:
        errors: list[str] = []
        endpoint = self.normalized_api_endpoint
        if endpoint:
            parsed = urlparse(endpoint)
            if parsed.scheme not in {"http", "https"}:
                errors.append("API_ENDPOINT must be an http or https URL.")
            elif not parsed.netloc:
                errors.append("API_ENDPOINT must include a host.")
            elif parsed.query or parsed.fragment:
                errors.append("API_ENDPOINT must not carry a query or fragment.")
        if not 1 <= self.port <= 65535:
            errors.append("UI_PORT must be between 1 and 65535.")
        if not self.static_dir.is_dir():
            errors.append(f"UI_STATIC_DIR '{self.static_dir}' is not a directory.")
        return errors

    @property
    def ready(self) -> bool:
        return not self.configuration_errors


@lru_cache
def get_ui_settings() -> UISettings:
    return UISettings(
        api_endpoint=os.getenv("API_ENDPOINT", DEFAULT_API_ENDPOINT),
        host=os.getenv("UI_HOST", "0.0.0.0"),
        port=int(os.getenv("UI_PORT", "8080")),
        static_dir=Path(
            os.getenv(
                "UI_STATIC_DIR",
                str(Path(__file__).resolve().parents[2] / "ui"),
            )
        ),
    )
