import hashlib
import json

import httpx
import pytest

from control_translation.api import app
from control_translation.contracts import DatabricksResultReference
from control_translation.upstream import UpstreamResolutionError
from control_translation.workflow_lab import WorkflowLabClient, workflow_lab_result_ref


def test_result_reference_preserves_production_shape() -> None:
    reference = DatabricksResultReference(
        system="databricks",
        catalog="36889_janus_dev",
        schema="control_translation",
        table="control_translation_results",
        key="control-translation-result:1",
    )
    assert reference.model_dump(mode="json", by_alias=True) == {
        "system": "databricks",
        "catalog": "36889_janus_dev",
        "schema": "control_translation",
        "table": "control_translation_results",
        "key": "control-translation-result:1",
    }
    assert workflow_lab_result_ref("control-translation-result:1").model_dump(
        mode="json", by_alias=True
    ) == {
        "system": "workflow-lab",
        "contract_id": "workflow-lab-result-reference@1.0",
        "namespace": "immutable-results",
        "key": "control-translation-result:1",
    }


def test_workflow_lab_routes_are_additive() -> None:
    paths = app.openapi()["paths"]
    for path, method in (
        ("/v1/workflow-lab/readyz", "get"),
        ("/v1/workflow-lab/runs", "post"),
        ("/v1/workflow-lab/runs/{run_id}", "get"),
        ("/v1/workflow-lab/runs/{run_id}/result", "get"),
        ("/v1/workflow-lab/runs/{run_id}/cancel", "post"),
    ):
        assert method in paths[path]
    assert "post" in paths["/v1/control-translation-runs"]


def test_client_rejects_physical_integrity_mismatch() -> None:
    locator = {
        "capability": "bypass-validation",
        "contract_id": "bypass-validation@2.0",
        "request_id": "request-1",
        "correlation_id": "correlation-1",
        "run_id": "run-1",
        "result_id": "bypass-validation-result:1",
        "terminal_state": "no-bypass-found",
        "status": "completed",
        "result_ref": workflow_lab_result_ref("bypass-validation-result:1").model_dump(mode="json"),
        "evidence_refs": [],
        "content_sha256": "sha256:" + "1" * 64,
        "size_bytes": 10,
        "created_at": "2026-09-20T00:00:00Z",
    }
    raw = b'{"value":1}'
    digest = hashlib.sha256(raw).hexdigest()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            requested = json.loads(request.content)["locator"]
            return httpx.Response(
                200,
                json={
                    "locator": requested,
                    "representation": "authoritative-result",
                    "object": {"digest": f"sha256:{digest}", "size_bytes": len(raw) + 1},
                    "json_pointer": "",
                    "download_path": f"/v1/objects/sha256/{digest}",
                },
            )
        return httpx.Response(200, content=raw)

    client = WorkflowLabClient("http://workflow-lab.test", timeout_seconds=1, max_bytes=1024)
    client.client.close()
    client.client = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(UpstreamResolutionError, match="physical object integrity"):
        client.resolve(locator)


def test_client_rejects_duplicate_json_resolution() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b'{"locator":{},"locator":{}}')

    client = WorkflowLabClient("http://workflow-lab.test", timeout_seconds=1, max_bytes=1024)
    client.client.close()
    client.client = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(UpstreamResolutionError, match="strict JSON"):
        client.resolve({})
