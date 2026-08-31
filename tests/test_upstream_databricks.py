from __future__ import annotations

import pytest

from control_translation.contracts import DatabricksResultReference
from control_translation.upstream import UpstreamResolutionError
from control_translation.upstream_databricks import DatabricksUpstreamResultResolver


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


def _resolver(rows):
    return DatabricksUpstreamResultResolver(
        server_hostname="adb.example.azuredatabricks.net",
        http_path="/sql/1.0/warehouses/example",
        connection_factory=lambda: FakeConnection(rows),
    )


def test_upstream_resolver_rejects_unapproved_coordinates():
    resolver = _resolver([])

    with pytest.raises(ValueError, match="approved table"):
        resolver.fetch(_reference(schema="other_schema"))


def test_upstream_resolver_requires_exactly_one_row():
    row = (
        "bypass-validation-result:1",
        "no-bypass-found",
        "corr-1",
        "{}",
        '{"contract_id":"bypass-validation@1.0"}',
    )
    resolver = _resolver([row, row])

    with pytest.raises(UpstreamResolutionError, match="multiple rows"):
        resolver.fetch(_reference())


def test_upstream_resolver_reads_the_exact_parameterized_result():
    row = (
        "bypass-validation-result:1",
        "no-bypass-found",
        "corr-1",
        "{}",
        '{"contract_id":"bypass-validation@1.0"}',
    )
    connection = FakeConnection([row])
    resolver = DatabricksUpstreamResultResolver(
        server_hostname="adb.example.azuredatabricks.net",
        http_path="/sql/1.0/warehouses/example",
        connection_factory=lambda: connection,
    )

    record = resolver.fetch(_reference())

    assert record is not None
    assert record.result_id == "bypass-validation-result:1"
    assert connection.cursor_instance.parameters == ("bypass-validation-result:1",)
    assert "LIMIT 2" in connection.cursor_instance.operation
