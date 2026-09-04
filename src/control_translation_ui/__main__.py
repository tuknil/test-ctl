"""Environment-configured process entry point for the UI container."""

from __future__ import annotations

import uvicorn

from control_translation_ui.config import get_ui_settings


def main() -> None:
    settings = get_ui_settings()
    uvicorn.run(
        "control_translation_ui.app:app",
        host=settings.host,
        port=settings.port,
        proxy_headers=True,
    )


if __name__ == "__main__":
    main()
