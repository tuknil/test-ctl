"""Environment-configured process entry point for container deployments."""

from __future__ import annotations

import uvicorn

from control_translation.config import get_settings


def main() -> None:
    settings = get_settings()
    uvicorn.run(
        "control_translation.api:app",
        host=settings.host,
        port=settings.port,
        proxy_headers=True,
    )


if __name__ == "__main__":
    main()
