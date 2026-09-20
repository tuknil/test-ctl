import hashlib
import json

import httpx
import pytest

from control_translation.api import app
from control_translation.contracts import DatabricksResultReference
from control_translation.upstream import UpstreamResolutionError
from control_translation.workflow_lab import (
    WorkflowLabClient,
    WorkflowLabPublicationError,
    workflow_lab_result_ref,
)


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


@pytest.mark.parametrize(
    ("timeout", "maximum"),
    [(301, 1024), (1, 256 * 1024 * 1024 + 1)],
)
def test_client_rejects_excessive_replay_limits(timeout: float, maximum: int) -> None:
    with pytest.raises(ValueError, match="allowed range"):
        WorkflowLabClient(
            "http://workflow-lab.test",
            timeout_seconds=timeout,
            max_bytes=maximum,
        )


def _publication_document() -> dict:
    return {
        "capability": "control-translation",
        "contract_id": "control-translation-result@2.0",
        "request_id": "request-1",
        "correlation_id": "correlation-1",
        "run_id": "run-1",
        "result_id": "control-translation-result:1",
        "terminal_state": "translated",
        "status": "completed",
        "result_ref": workflow_lab_result_ref("control-translation-result:1").model_dump(mode="json"),
        "content_sha256": "sha256:" + "1" * 64,
        "size_bytes": 1,
        "created_at": "2026-09-20T00:00:00Z",
    }


@pytest.mark.parametrize(
    ("mode", "retryable", "code"),
    [
        ("absent", True, "publication_ambiguous"),
        ("conflict", False, "publication_conflict"),
    ],
)
def test_publication_classifies_absence_and_conflict(mode, retryable, code) -> None:
    uploaded = b""

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal uploaded
        if request.url.path == "/v1/objects":
            uploaded = request.content
            digest = hashlib.sha256(uploaded).hexdigest()
            return httpx.Response(201, json={"digest": f"sha256:{digest}", "size_bytes": len(uploaded), "media_type": "application/json", "logical_type": "control-translation-authoritative-result"})
        if request.url.path == "/v1/resolver/results/register":
            return httpx.Response(409 if mode == "conflict" else 201, json={"status": "registered"})
        if request.url.path == "/v1/resolver/results/resolve":
            return httpx.Response(404, json={"detail": "absent"})
        raise AssertionError(request.url)

    client = WorkflowLabClient("http://workflow-lab.test", timeout_seconds=1, max_bytes=1024 * 1024)
    client.client.close()
    client.client = httpx.Client(transport=httpx.MockTransport(handler))

    with pytest.raises(WorkflowLabPublicationError) as raised:
        client.publish(_publication_document())
    assert raised.value.code == code
    assert raised.value.retryable is retryable


def test_exact_existing_publication_reconciles_idempotently() -> None:
    uploaded = b""
    locator = None

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal uploaded, locator
        if request.url.path == "/v1/objects":
            if uploaded and uploaded != request.content:
                raise AssertionError("publication bytes changed")
            uploaded = request.content
            digest = hashlib.sha256(uploaded).hexdigest()
            return httpx.Response(201, json={"digest": f"sha256:{digest}", "size_bytes": len(uploaded), "media_type": "application/json", "logical_type": "control-translation-authoritative-result"})
        if request.url.path == "/v1/resolver/results/register":
            locator = json.loads(request.content)["locator"]
            return httpx.Response(201, json={"status": "registered"})
        if request.url.path == "/v1/resolver/results/resolve":
            digest = hashlib.sha256(uploaded).hexdigest()
            return httpx.Response(200, json={"locator": locator, "representation": "authoritative-result", "object": {"digest": f"sha256:{digest}", "size_bytes": len(uploaded)}, "json_pointer": "", "download_path": f"/v1/objects/sha256/{digest}"})
        if request.url.path.startswith("/v1/objects/sha256/"):
            return httpx.Response(200, content=uploaded)
        raise AssertionError(request.url)

    client = WorkflowLabClient("http://workflow-lab.test", timeout_seconds=1, max_bytes=1024 * 1024)
    client.client.close()
    client.client = httpx.Client(transport=httpx.MockTransport(handler))

    client.publish(_publication_document())
    first = uploaded
    client.publish(_publication_document())
    assert uploaded == first
