from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256

import pytest

from control_translation.contracts import (
    DatabricksResultReference,
    OrchestrationUpstreamInput,
)
from control_translation.upstream import UpstreamResolutionError
from control_translation.upstream_databricks import (
    DatabricksUpstreamResultResolver,
    _producer_integrity,
    _read_files_response,
)


class FakeCursor:
    def __init__(self, rows):
        self.rows = rows
        self.operation = None
        self.parameters = None

    def execute(self, operation, parameters=None):
        self.operation = operation
        self.parameters = parameters

    def fetchall(self):
        return self.rows

    def close(self):
        pass


class FakeConnection:
    def __init__(self, rows):
        self.cursor_instance = FakeCursor(rows)

    def cursor(self):
        return self.cursor_instance

    def close(self):
        pass


def _reference(**overrides):
    values = {
        "system": "databricks",
        "catalog": "36889_janus_dev",
        "schema": "bypass_validation",
        "table": "bypass_validation_results",
        "key": "bypass-validation-result:1",
    }
    values.update(overrides)
    return DatabricksResultReference.model_validate(values)


def _resolver(rows, *, volume_reader=None):
    return DatabricksUpstreamResultResolver(
        server_hostname="adb.example.azuredatabricks.net",
        http_path="/sql/1.0/warehouses/example",
        connection_factory=lambda: FakeConnection(rows),
        volume_reader=volume_reader,
    )


def _canonical(value: dict) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()


def _valid_bypass_row() -> tuple[tuple, OrchestrationUpstreamInput]:
    result_ref = _reference().model_dump(mode="json", by_alias=True)
    result = {
        "contract_id": "bypass-validation@1.0",
        "result_id": "bypass-validation-result:1",
        "run_id": "bypass-run-1",
        "result_ref": result_ref,
        "produced_at": "2026-09-03T12:00:00Z",
        "terminal_state": "no-bypass-found",
        "correlation_id": "corr-1",
    }
    content = _canonical(result)
    digest = f"sha256:{sha256(content).hexdigest()}"
    completion = {
        "capability": "bypass-validation",
        "contract_id": "capability-completion@1.0",
        "request_id": "bypass-request-1",
        "correlation_id": "corr-1",
        "run_id": "bypass-run-1",
        "result_id": "bypass-validation-result:1",
        "status": "completed",
        "terminal_state": "no-bypass-found",
        "result_ref": result_ref,
        "evidence_refs": [],
        "content_sha256": digest,
        "size_bytes": len(content),
        "created_at": "2026-09-03T12:00:00Z",
    }
    row = (
        "bypass-run-1",
        "bypass-validation-result:1",
        "bypass-request-1",
        "corr-1",
        "bypass-validation",
        "capability-completion@1.0",
        "no-bypass-found",
        "completed",
        "{}",
        content.decode(),
        json.dumps(completion),
        digest,
        len(content),
        datetime(2026, 9, 3, 12, tzinfo=UTC),
    )
    locator = OrchestrationUpstreamInput.model_validate(completion)
    return row, locator


def test_upstream_resolver_rejects_unapproved_coordinates():
    resolver = _resolver([])

    with pytest.raises(ValueError, match="approved table"):
        resolver.fetch(_reference(schema="other_schema"))


def test_upstream_resolver_requires_exactly_one_row():
    row, _ = _valid_bypass_row()
    resolver = _resolver([row, row])

    with pytest.raises(UpstreamResolutionError, match="multiple rows"):
        resolver.fetch(_reference())


def test_upstream_resolver_reads_the_exact_parameterized_result():
    row, locator = _valid_bypass_row()
    connection = FakeConnection([row])
    resolver = DatabricksUpstreamResultResolver(
        server_hostname="adb.example.azuredatabricks.net",
        http_path="/sql/1.0/warehouses/example",
        connection_factory=lambda: connection,
    )

    record = resolver.fetch(_reference(), immutable_locator=locator)

    assert record is not None
    assert record.result_id == "bypass-validation-result:1"
    assert connection.cursor_instance.parameters == ("bypass-validation-result:1",)
    assert "LIMIT 2" in connection.cursor_instance.operation


def test_upstream_resolver_rejects_tampered_locator_digest():
    row, locator = _valid_bypass_row()
    tampered = locator.model_copy(
        update={"content_sha256": "sha256:" + "f" * 64}
    )

    with pytest.raises(UpstreamResolutionError, match="content_sha256"):
        _resolver([row]).fetch(_reference(), immutable_locator=tampered)


def test_upstream_resolver_rejects_tampered_result_identity():
    row, locator = _valid_bypass_row()
    values = list(row)
    result = json.loads(values[9])
    result["run_id"] = "different-run"
    content = _canonical(result)
    values[9] = content.decode()
    values[11] = f"sha256:{sha256(content).hexdigest()}"
    values[12] = len(content)

    with pytest.raises(UpstreamResolutionError, match="result run_id"):
        _resolver([tuple(values)]).fetch(
            _reference(), immutable_locator=locator
        )


def test_upstream_resolver_lazily_hydrates_strict_volume_manifest():
    row, locator = _valid_bypass_row()
    values = list(row)
    content = values[9].encode()
    digest = sha256(content).hexdigest()
    manifest = {
        "contract_type": "janus-volume-payload-manifest",
        "contract_version": "1.0",
        "reference": f"payload://sha256/{digest}",
        "media_type": "application/json",
        "encoding": "identity",
        "content_sha256": f"sha256:{digest}",
        "size_bytes": len(content),
        "volume": {
            "catalog": "36889_janus_dev",
            "schema": "bypass_validation",
            "name": "payloads",
        },
    }
    values[9] = json.dumps(manifest)
    paths: list[str] = []

    def read_volume(path: str, max_bytes: int) -> bytes:
        assert max_bytes >= len(content)
        paths.append(path)
        return content

    record = _resolver(
        [tuple(values)], volume_reader=read_volume
    ).fetch(_reference(), immutable_locator=locator)

    assert record is not None
    assert record.result_id == locator.result_id
    assert paths == [
        (
            "/Volumes/36889_janus_dev/bypass_validation/payloads/sha256/"
            f"{digest[:2]}/{digest[2:4]}/{digest}"
        )
    ]


def test_upstream_resolver_rejects_manifest_outside_producer_volume():
    row, locator = _valid_bypass_row()
    values = list(row)
    content = values[9].encode()
    digest = sha256(content).hexdigest()
    values[9] = json.dumps(
        {
            "contract_type": "janus-volume-payload-manifest",
            "contract_version": "1.0",
            "reference": f"payload://sha256/{digest}",
            "media_type": "application/json",
            "encoding": "identity",
            "content_sha256": f"sha256:{digest}",
            "size_bytes": len(content),
            "volume": {
                "catalog": "36889_janus_dev",
                "schema": "other",
                "name": "payloads",
            },
        }
    )

    with pytest.raises(UpstreamResolutionError, match="manifest is invalid"):
        _resolver([tuple(values)], volume_reader=lambda *_: content).fetch(
            _reference(), immutable_locator=locator
        )


def test_direct_reference_keeps_inline_compatibility_with_strict_verification():
    row, _ = _valid_bypass_row()

    record = _resolver([row]).fetch(_reference())

    assert record is not None
    assert record.result_id == "bypass-validation-result:1"


def test_mitigation_integrity_matches_go_producer_shape_and_omitempty():
    result = {
        "capability": "mitigation-check",
        "contract_id": "mitigation-check@1.0",
        "request_id": "mc-request-1",
        "run_id": "mc-run-1",
        "result_id": "mitigation-check-result:1",
        "terminal_state": "blocked",
        "status": "completed",
        "evidence_refs": [],
        "request_sha256": "sha256:" + "a" * 64,
        "upstream_inputs": [],
        "input_provenance": {
            "route_policy": "registered-waf-route-v1",
            "selected_test_basis_id": "basis-1",
            "verification": "physical-and-logical-sha256-verified",
        },
        "match": True,
        "expected": {
            "classification": "true-positive",
            "blocked": True,
            "status_code": 403,
        },
        "actual": {
            "blocked": True,
            "status_code": 403,
            "reached_app": False,
            "detail": "blocked",
        },
        "substrate": {"image": "fixture", "ready": True},
        "steps": [],
        "prose_summary": "Blocked.",
        "limitations": [],
        "created_at": "2026-09-03T12:00:00Z",
    }
    expected_document = dict(result)
    expected_document.pop("limitations")
    expected = json.dumps(
        expected_document,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode()

    digest, size = _producer_integrity("mitigation", result)

    assert digest == f"sha256:{sha256(expected).hexdigest()}"
    assert size == len(expected)


def test_files_api_response_reader_closes_stream():
    class Stream:
        closed = False

        def read(self, _size):
            return b"{}"

        def close(self):
            self.closed = True

    stream = Stream()

    response = type("Response", (), {"contents": stream})()

    assert _read_files_response(response, 10) == b"{}"
    assert stream.closed is True
