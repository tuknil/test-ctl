"""Workflow Lab resolver and result publisher for the replay execution plane."""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx
import rfc8785

from control_translation.cancellation import CancellationSignal, check_cancelled
from control_translation.contracts import (
    DatabricksResultReference,
    InvocationRequest,
    OrchestrationUpstreamInput,
    ResultEnvelope,
    SharedContractV2UpstreamInput,
)
from control_translation.persistence import PersistenceError, SQLiteRunRepository
from control_translation.persistence.base import canonical_result_bytes
from control_translation.upstream import UpstreamRecord, UpstreamResolutionError
from control_translation.upstream_databricks import (
    _check_generation_logical_bytes,
    _producer_integrity_bytes,
)

logger = logging.getLogger(__name__)
_OBJECT_PATH = re.compile(r"^/v1/objects/sha256/([a-f0-9]{64})$")


def workflow_lab_result_ref(result_id: str) -> DatabricksResultReference:
    return DatabricksResultReference(
        system="workflow-lab",
        contract_id="workflow-lab-result-reference@1.0",
        namespace="immutable-results",
        key=result_id,
    )


def _strict_object(raw: bytes, label: str) -> dict[str, Any]:
    def reject_duplicates(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate key: {key}")
            value[key] = item
        return value

    try:
        value = json.loads(raw, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise UpstreamResolutionError(f"{label} is not strict JSON") from exc
    if not isinstance(value, dict):
        raise UpstreamResolutionError(f"{label} is not a JSON object")
    return value


def _same_locator(left: dict[str, Any], right: dict[str, Any]) -> bool:
    if set(left) != set(right):
        return False
    for key, value in right.items():
        if key != "created_at":
            if left.get(key) != value:
                return False
            continue
        try:
            actual = datetime.fromisoformat(str(left.get(key)))
            expected = datetime.fromisoformat(str(value))
        except ValueError:
            return False
        if actual != expected:
            return False
    return True


class WorkflowLabClient:
    def __init__(self, base_url: str, *, timeout_seconds: float, max_bytes: int) -> None:
        parsed = httpx.URL(base_url.strip().rstrip("/"))
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.host
            or parsed.userinfo
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("WORKFLOW_LAB_URL must be an absolute credential-free HTTP URL")
        if timeout_seconds <= 0 or max_bytes <= 0:
            raise ValueError("Workflow Lab timeout and byte limit must be positive")
        self.base_url = str(parsed).rstrip("/")
        self.max_bytes = max_bytes
        self.client = httpx.Client(
            timeout=timeout_seconds,
            follow_redirects=False,
            trust_env=True,
        )

    def close(self) -> None:
        self.client.close()

    def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        if not path.startswith("/") or path.startswith("//"):
            raise UpstreamResolutionError("Workflow Lab returned an invalid path")
        last: Exception | None = None
        for attempt in range(3):
            if attempt:
                time.sleep(0.25 * attempt)
            try:
                response = self.client.request(method, self.base_url + path, **kwargs)
            except httpx.RequestError as exc:
                last = exc
                continue
            if response.status_code in {408, 429} or response.status_code >= 500:
                last = RuntimeError(f"HTTP {response.status_code}")
                continue
            if response.status_code == 404:
                raise UpstreamResolutionError("Workflow Lab replay data is not imported")
            if response.status_code == 409:
                raise UpstreamResolutionError("Workflow Lab case requires authoritative-result enrichment")
            if not 200 <= response.status_code < 300:
                raise UpstreamResolutionError(f"Workflow Lab returned HTTP {response.status_code}")
            if len(response.content) > self.max_bytes:
                raise UpstreamResolutionError("Workflow Lab response exceeds the configured byte limit")
            return response
        raise ConnectionError("Workflow Lab is unavailable") from last

    def _download(self, path: str) -> bytes:
        if not path.startswith("/") or path.startswith("//"):
            raise UpstreamResolutionError("Workflow Lab returned an invalid object path")
        last: Exception | None = None
        for attempt in range(3):
            if attempt:
                time.sleep(0.25 * attempt)
            try:
                with self.client.stream("GET", self.base_url + path) as response:
                    if response.status_code in {408, 429} or response.status_code >= 500:
                        last = RuntimeError(f"HTTP {response.status_code}")
                        continue
                    if not 200 <= response.status_code < 300:
                        raise UpstreamResolutionError(
                            f"Workflow Lab object download returned HTTP {response.status_code}"
                        )
                    content = bytearray()
                    for chunk in response.iter_bytes():
                        content.extend(chunk)
                        if len(content) > self.max_bytes:
                            raise UpstreamResolutionError(
                                "Workflow Lab object exceeds the configured byte limit"
                            )
                    return bytes(content)
            except httpx.RequestError as exc:
                last = exc
        raise ConnectionError("Workflow Lab object download is unavailable") from last

    def publication_ready(self) -> bool:
        try:
            value = _strict_object(
                self._request("GET", "/v1/resolver/publication-readiness").content,
                "Workflow Lab readiness",
            )
            return value.get("status") == "ready"
        except (ConnectionError, UpstreamResolutionError):
            logger.exception("Workflow Lab publication readiness failed")
            return False

    def resolve(self, locator: SharedContractV2UpstreamInput | OrchestrationUpstreamInput | dict[str, Any]) -> bytes:
        source_locator = (
            locator
            if isinstance(locator, dict)
            else locator.model_dump(mode="json", by_alias=True, exclude_none=True)
        )
        locator_data = {
            key: source_locator[key]
            for key in (
                "capability",
                "contract_id",
                "request_id",
                "correlation_id",
                "run_id",
                "result_id",
                "terminal_state",
                "status",
                "result_ref",
                "content_sha256",
                "size_bytes",
                "created_at",
            )
            if key in source_locator
        }
        response = self._request(
            "POST",
            "/v1/resolver/results/resolve",
            json={"locator": locator_data, "minimum_representation": "authoritative-result"},
        )
        resolved = _strict_object(response.content, "Workflow Lab resolution")
        resolved_locator = resolved.get("locator")
        if (
            not isinstance(resolved_locator, dict)
            or not _same_locator(resolved_locator, locator_data)
            or resolved.get("representation") != "authoritative-result"
        ):
            raise UpstreamResolutionError("Workflow Lab returned a different immutable locator")
        obj = resolved.get("object")
        path = resolved.get("download_path")
        match = _OBJECT_PATH.fullmatch(path) if isinstance(path, str) else None
        if not isinstance(obj, dict) or match is None or obj.get("digest") != f"sha256:{match.group(1)}":
            raise UpstreamResolutionError("Workflow Lab returned an invalid object identity")
        raw = self._download(path)
        if obj.get("size_bytes") != len(raw) or obj.get("digest") != f"sha256:{hashlib.sha256(raw).hexdigest()}":
            raise UpstreamResolutionError("Workflow Lab physical object integrity differs")
        pointer = resolved.get("json_pointer") or ""
        if pointer:
            value: Any = _strict_object(raw, "Workflow Lab object")
            try:
                for encoded in pointer.removeprefix("/").split("/"):
                    part = encoded.replace("~1", "/").replace("~0", "~")
                    value = value[int(part)] if isinstance(value, list) else value[part]
            except (KeyError, IndexError, TypeError, ValueError) as exc:
                raise UpstreamResolutionError("Workflow Lab JSON pointer does not resolve") from exc
            raw = rfc8785.dumps(value)
        return raw

    def publish(self, canonical_result: dict[str, Any]) -> None:
        raw = json.dumps(
            canonical_result,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        if len(raw) > self.max_bytes:
            raise PersistenceError("Control Translation result exceeds Workflow Lab byte limit")
        uploaded = _strict_object(
            self._request(
                "POST",
                "/v1/objects?logical_type=control-translation-authoritative-result",
                content=raw,
                headers={"Content-Type": "application/json"},
            ).content,
            "Workflow Lab upload",
        )
        digest = f"sha256:{hashlib.sha256(raw).hexdigest()}"
        if uploaded.get("digest") != digest or uploaded.get("size_bytes") != len(raw):
            raise PersistenceError("Workflow Lab upload identity differs")
        locator = {
            key: canonical_result[key]
            for key in (
                "capability", "contract_id", "request_id", "correlation_id", "run_id",
                "result_id", "terminal_state", "status", "result_ref", "content_sha256",
                "size_bytes", "created_at",
            )
        }
        self._request(
            "POST",
            "/v1/resolver/results/register",
            json={
                "locator": locator,
                "object": uploaded,
                "json_pointer": "",
                "representation": "authoritative-result",
            },
        )
        if self.resolve(locator) == raw:
            return
        raise PersistenceError("Workflow Lab result readback differs")


class WorkflowLabUpstreamResultResolver:
    def __init__(self, client: WorkflowLabClient) -> None:
        self.client = client

    def healthcheck(self) -> bool:
        return self.client.publication_ready()

    def fetch(
        self,
        reference: DatabricksResultReference,
        *,
        immutable_locator: OrchestrationUpstreamInput | SharedContractV2UpstreamInput | None = None,
        cancellation_signal: CancellationSignal | None = None,
    ) -> UpstreamRecord | None:
        check_cancelled(cancellation_signal)
        if reference.system != "workflow-lab" or immutable_locator is None:
            raise UpstreamResolutionError("Workflow Lab replay requires a complete Workflow Lab locator")
        raw = self.client.resolve(immutable_locator)
        document = _strict_object(raw, f"{immutable_locator.capability} result")
        capability = immutable_locator.capability
        shape = {
            "check-generation": "check",
            "defense-generation": "defense",
            "mitigation-check": "mitigation",
            "bypass-validation": "bypass",
        }[capability]
        if shape == "check":
            nested = document.get("run_result")
            if (
                document.get("capability") == "check-generation"
                and document.get("contract_id") == "check-generation-result@1.0"
                and isinstance(nested, dict)
            ):
                authenticated = rfc8785.dumps(
                    {
                        key: value
                        for key, value in document.items()
                        if key not in {"content_sha256", "size_bytes"}
                    }
                )
                binding = {
                    key: value
                    for key, value in document.items()
                    if key not in {"content_sha256", "size_bytes"}
                }
                binding["run_result"] = dict(nested)
                binding["run_result"]["_verified_characterization_revision_id"] = (
                    document.get("characterization_revision_id")
                )
                payload_raw = rfc8785.dumps(binding)
            else:
                authenticated = _check_generation_logical_bytes(document, immutable_locator)
                payload_raw = rfc8785.dumps(nested) if isinstance(nested, dict) else None
        elif shape == "bypass":
            authenticated = rfc8785.dumps(
                {
                    key: value
                    for key, value in document.items()
                    if key not in {"content_sha256", "size_bytes"}
                }
            )
            payload_raw = None
        else:
            authenticated = _producer_integrity_bytes(shape, document)
            payload_raw = None
        digest = f"sha256:{hashlib.sha256(authenticated).hexdigest()}"
        if digest != immutable_locator.content_sha256 or len(authenticated) != immutable_locator.size_bytes:
            raise UpstreamResolutionError(f"{capability} logical result integrity differs")
        return UpstreamRecord(
            result_id=immutable_locator.result_id,
            terminal_state=immutable_locator.terminal_state,
            correlation_id=immutable_locator.correlation_id,
            subject_record_revision_id=None,
            request={},
            result=document,
            raw_result=raw,
            payload_raw_result=payload_raw,
            authenticated_content=authenticated,
            authenticated_content_sha256=digest,
            authenticated_content_size=len(authenticated),
        )


class WorkflowLabResultSink(SQLiteRunRepository):
    """Publish first, then retain the legacy envelope for local diagnostics."""

    def __init__(self, database_path: str | Path, client: WorkflowLabClient) -> None:
        super().__init__(database_path)
        self.client = client

    def initialize(self) -> None:
        super().initialize()
        if not self.client.publication_ready():
            raise PersistenceError("Workflow Lab publication is not ready")

    def save_completed_run(
        self,
        request: InvocationRequest,
        result: ResultEnvelope,
        *,
        request_hash: str,
        started_at: datetime,
        canonical_result: dict | None = None,
    ) -> None:
        if canonical_result is None:
            raise PersistenceError("Workflow Lab publication requires the canonical result")
        expected = canonical_result_bytes(canonical_result)
        if (
            canonical_result.get("content_sha256") != f"sha256:{hashlib.sha256(expected).hexdigest()}"
            or canonical_result.get("size_bytes") != len(expected)
        ):
            raise PersistenceError("Control Translation logical result integrity differs")
        self.client.publish(canonical_result)
        super().save_completed_run(
            request,
            result,
            request_hash=request_hash,
            started_at=started_at,
            canonical_result=canonical_result,
        )
