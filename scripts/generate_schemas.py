"""One-off script: emit JSON schemas for the request/result envelopes into
`schemas/`. Run with: `uv run python scripts/generate_schemas.py`.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import TypeAdapter

from control_translation.contracts import InvokeAPIRequest, ResultEnvelope


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    schemas_dir = root / "schemas"
    schemas_dir.mkdir(exist_ok=True)

    (schemas_dir / "request.schema.json").write_text(
        json.dumps(TypeAdapter(InvokeAPIRequest).json_schema(), indent=2)
    )
    (schemas_dir / "result.schema.json").write_text(
        json.dumps(ResultEnvelope.model_json_schema(), indent=2)
    )
    print(f"Wrote schemas to {schemas_dir}")


if __name__ == "__main__":
    main()
