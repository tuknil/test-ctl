"""Offline verification and WAF-first translation for shared contracts v2.

The v2 path is deliberately isolated from the retained three-result path. It
accepts only authenticated immutable CG, DG, MC, and BV records, verifies the
complete join before translation, and never performs network schema lookup.
"""

from __future__ import annotations

import itertools
import json
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from hashlib import sha256 as hashlib_sha256
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote

import rfc8785
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from control_translation.agents.translation_agent import TranslationProposal
from control_translation.cancellation import (
    CancellationSignal,
    OperationCancelled,
    check_cancelled,
)
from control_translation.contracts import (
    CoverageAccounting,
    PreTranslationVerification,
    ProofLoopTranslationRequirements,
    ProvenMitigationPattern,
    SharedContractV2InvokeRequest,
    TargetTranslationArtifact,
    TargetTranslationDirective,
    TranslationMapping,
    shared_waf_primary_artifact_id,
)
from control_translation.policy_reader.base import PolicySnapshot
from control_translation.upstream import (
    UpstreamRecord,
    UpstreamResolutionError,
    UpstreamResultResolver,
    UpstreamTransportError,
)


def _path_segment_escape(value: str) -> str:
    """Match Go net/url.PathEscape used by the authoritative MC resolver."""
    return quote(value, safe="$&+,:=@")

SCHEMA_ROOT = Path(__file__).resolve().parent / "contracts" / "shared-attack-contracts"
BV_PROFILE_ROOT = SCHEMA_ROOT / "profiles"
AMS_SCHEMA_ID = "https://schemas.janus.internal/contracts/attack-match-semantics/attack-match-semantics-2.0.schema.json"
BUNDLE_SCHEMA_ID = "https://schemas.janus.internal/contracts/candidate-bundle/candidate-bundle-1.0.schema.json"
MAX_RESULT_BYTES = 200 * 1024 * 1024
LEGACY_CT_PROFILE_ID = "waf-standard@1"
CT_PROFILE_ID = "waf-standard@2"
SHARED_CONTRACT_VERSION = "2.0"
SCHEMA_BUNDLE_VERSION = "shared-attack-contracts-phase-1-ct@2026-09-12"
SCHEMA_BUNDLE_DIGEST = (
    "sha256:b58597c7dfc061d92e7d8c0771ff33d67411e3942c3636e9b3f72357864034b3"
)
SCHEMA_IDS = {AMS_SCHEMA_ID, BUNDLE_SCHEMA_ID, "https://schemas.janus.internal/contracts/common/janus-contract-common-1.0.schema.json"}
MC_RESOLVER_ID = "mc-approved-route-adapter"
LEGACY_MC_RESOLVER_PROFILE_DIGEST = "sha256:e28f9574b07194222a317dfc4f03293beafb6e3613b87452a4191652fd6b6b1a"
MC_PROFILE_FILE_DIGEST = "sha256:a49bc4e962985f5bd6aa117228e44002a1a617e62544fb87757aa261d4a6f404"
MC_PROFILE_BYTE_LENGTH = 441
MC_RESOLVER_PROFILE_DIGEST = "sha256:01f6033b5b09db48056adc8a0d47083f4020cf18d71913c69e283f644ec41a94"
BV_RESOLVER_ID = "bv-approved-route-adapter"
LEGACY_BV_PROFILE_FILE_DIGEST = "sha256:e32674808bc8691021f26683aaa44bdd313a25875ea57168ddb4e0a2a6c1e2bc"
LEGACY_BV_PROFILE_BYTE_LENGTH = 3745
LEGACY_BV_RESOLVER_PROFILE_DIGEST = "sha256:46f4d0dd59e1464acc1ef19ef68d0134a4be554cc203da653192f057aa82e577"
BV_PROFILE_FILE_DIGEST = "sha256:9373f61caafa9fcede696e9c01e7d146235994b35faed4c9ada147b3f78396a6"
BV_PROFILE_BYTE_LENGTH = 6251
BV_RESOLVER_PROFILE_DIGEST = "sha256:749b4773b1f479e0b5ce00868a99a148076be87952640b41408d9dd3dc3f14f9"


def _expected_profiles(ct_profile_id: str) -> tuple[str, str, str, str]:
    if ct_profile_id == LEGACY_CT_PROFILE_ID:
        return (
            LEGACY_CT_PROFILE_ID,
            LEGACY_MC_RESOLVER_PROFILE_DIGEST,
            "waf-bypass@2",
            LEGACY_BV_RESOLVER_PROFILE_DIGEST,
        )
    if ct_profile_id == CT_PROFILE_ID:
        return CT_PROFILE_ID, MC_RESOLVER_PROFILE_DIGEST, "waf-bypass@3", BV_RESOLVER_PROFILE_DIGEST
    raise SharedContractV2Error("ct-profile-invalid", "unapproved Control Translation profile")


class SharedContractV2Error(ValueError):
    """Permanent fail-closed verification or translation failure."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


def _reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SharedContractV2Error("duplicate-json-key", f"duplicate JSON key: {key}")
        result[key] = value
    return result


def strict_json_bytes(raw: bytes, *, context: str) -> dict[str, Any]:
    if not raw or len(raw) > MAX_RESULT_BYTES:
        raise SharedContractV2Error("invalid-result-size", f"{context} bytes are empty or exceed the bound")
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
        )
    except SharedContractV2Error:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise SharedContractV2Error("invalid-json", f"{context} is not strict JSON") from exc
    if not isinstance(value, dict):
        raise SharedContractV2Error("invalid-json", f"{context} must be one JSON object")
    return value


def canonical_bytes(value: Any) -> bytes:
    try:
        return rfc8785.dumps(value)
    except (TypeError, ValueError, UnicodeError) as exc:
        raise SharedContractV2Error("canonical-json-invalid", "value cannot be serialized under RFC 8785") from exc


def digest(value: Any) -> str:
    return "sha256:" + hashlib_sha256(canonical_bytes(value)).hexdigest()


def digest_without(document: dict[str, Any], *fields: str) -> str:
    clone = deepcopy(document)
    for field in fields:
        clone.pop(field, None)
    return digest(clone)


def _shared_terminal_state_from_cg(value: Any) -> Any:
    return "no-checkable-signal" if value == "no-checkable-artifact" else value


def _same_timestamp(left: Any, right: Any) -> bool:
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    try:
        def parse(value: str) -> datetime:
            parsed = datetime.fromisoformat(value)
            return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)
        return parse(left) == parse(right)
    except ValueError:
        return False


def _same_locator_document(actual: Any, locator: Any) -> bool:
    if not isinstance(actual, dict):
        return False
    expected = locator.model_dump(mode="json", by_alias=True)
    exact_fields = (
        "capability", "contract_id", "request_id", "correlation_id", "run_id",
        "result_id", "terminal_state", "status", "result_ref", "content_sha256",
        "size_bytes",
    )
    if any(actual.get(field) != expected.get(field) for field in exact_fields):
        return False
    if actual.get("evidence_refs", []) != expected.get("evidence_refs", []):
        return False
    return _same_timestamp(actual.get("created_at"), expected.get("created_at"))


def _resolve_result_internal_content(enclosing: dict[str, Any], locator: dict[str, Any]) -> bytes:
    uri = locator.get("uri")
    if not isinstance(uri, str) or not uri.startswith("janus-result-internal:"):
        raise SharedContractV2Error("result-internal-locator-invalid", "CG artifact locator is not result-internal")
    identity, separator, pointer = uri.removeprefix("janus-result-internal:").partition("#")
    if not separator or unquote(identity) != enclosing.get("result_id") or not pointer.startswith("/"):
        raise SharedContractV2Error("result-internal-locator-invalid", "CG artifact locator identity or pointer differs")
    current: Any = enclosing
    try:
        for raw_token in pointer.removeprefix("/").split("/"):
            token = raw_token.replace("~1", "/").replace("~0", "~")
            current = current[int(token)] if isinstance(current, list) else current[token]
    except (IndexError, KeyError, TypeError, ValueError) as exc:
        raise SharedContractV2Error("result-internal-locator-invalid", "CG artifact locator does not resolve exactly") from exc
    content = current.encode("utf-8") if isinstance(current, str) else canonical_bytes(current)
    if (
        locator.get("immutable") is not True
        or locator.get("byte_length") != len(content)
        or locator.get("digest") != "sha256:" + hashlib_sha256(content).hexdigest()
    ):
        raise SharedContractV2Error("result-internal-locator-integrity-failed", "CG artifact locator bytes differ")
    return content


class OfflineSchemaCatalog:
    """Integrity-checked local-only schema registry."""

    def __init__(self, root: Path = SCHEMA_ROOT) -> None:
        self.root = root.resolve()
        manifest = strict_json_bytes((self.root / "manifest.json").read_bytes(), context="schema manifest")
        if (
            set(manifest)
            != {
                "manifest_version",
                "bundle_version",
                "architecture_commit",
                "digest_profile",
                "bundle_digest",
                "schemas",
            }
            or manifest.get("manifest_version") != 1
            or manifest.get("bundle_version") != SCHEMA_BUNDLE_VERSION
            or manifest.get("digest_profile")
            != "sha256-tab-delimited-schema-catalog-v1"
            or manifest.get("bundle_digest") != SCHEMA_BUNDLE_DIGEST
        ):
            raise SharedContractV2Error("schema-manifest-invalid", "unsupported schema manifest")
        schemas: dict[str, dict[str, Any]] = {}
        rows: list[str] = []
        for entry in manifest.get("schemas", []):
            if not isinstance(entry, dict):
                raise SharedContractV2Error("schema-manifest-invalid", "schema entry is not an object")
            path = (self.root / str(entry.get("relative_path", ""))).resolve()
            if self.root not in path.parents:
                raise SharedContractV2Error("schema-manifest-invalid", "schema path escapes embedded bundle")
            raw = path.read_bytes()
            file_digest = "sha256:" + hashlib_sha256(raw).hexdigest()
            if entry.get("sha256") != file_digest or entry.get("byte_length") != len(raw):
                raise SharedContractV2Error("schema-integrity-failed", f"embedded schema differs: {path.name}")
            schema = strict_json_bytes(raw, context=path.name)
            if schema.get("$id") != entry.get("$id"):
                raise SharedContractV2Error("schema-integrity-failed", f"embedded schema ID differs: {path.name}")
            if schema["$id"] in schemas:
                raise SharedContractV2Error("schema-manifest-invalid", "duplicate embedded schema ID")
            schemas[str(schema["$id"])] = schema
            rows.append(f"{schema['$id']}\t{file_digest}\t{len(raw)}\n")
        catalog_digest = "sha256:" + hashlib_sha256("".join(sorted(rows)).encode()).hexdigest()
        if catalog_digest != SCHEMA_BUNDLE_DIGEST or set(schemas) != SCHEMA_IDS:
            raise SharedContractV2Error("schema-bundle-integrity-failed", "offline schema catalog digest differs")
        self.schemas = schemas
        self.registry = Registry().with_resources(
            (schema_id, Resource.from_contents(schema)) for schema_id, schema in schemas.items()
        )

    def validate(self, schema_id: str, document: Any) -> None:
        schema = self.schemas.get(schema_id)
        if schema is None:
            raise SharedContractV2Error("unknown-schema", f"schema is not embedded: {schema_id}")
        errors = sorted(
            Draft202012Validator(schema, registry=self.registry).iter_errors(document),
            key=lambda error: list(error.absolute_path),
        )
        if errors:
            error = errors[0]
            path = "/" + "/".join(str(item) for item in error.absolute_path)
            raise SharedContractV2Error("schema-invalid", f"{schema_id} at {path}: {error.message}")


def _index(items: Any, key: str, code: str) -> dict[str, dict[str, Any]]:
    if not isinstance(items, list):
        raise SharedContractV2Error(code, f"{key} collection is absent")
    indexed: dict[str, dict[str, Any]] = {}
    for item in items:
        identity = item.get(key) if isinstance(item, dict) else None
        if not isinstance(identity, str) or not identity or identity in indexed:
            raise SharedContractV2Error(code, f"duplicate or invalid {key}")
        indexed[identity] = item
    return indexed


def _ref_ids(
    refs: Any,
    *,
    kind: str,
    scope: str,
    known: Mapping[str, Any],
    code: str,
    allow_empty: bool = False,
) -> list[str]:
    if not isinstance(refs, list) or (not refs and not allow_empty):
        raise SharedContractV2Error(code, "typed references must be a nonempty array")
    result: list[str] = []
    for ref in refs:
        identity = ref.get("id") if isinstance(ref, dict) else None
        if (
            not isinstance(ref, dict)
            or set(ref) != {"kind", "scope", "id"}
            or ref.get("kind") != kind
            or ref.get("scope") != scope
            or not isinstance(identity, str)
            or identity not in known
            or identity in result
        ):
            raise SharedContractV2Error(code, "typed reference is invented, duplicated, or has the wrong scope")
        result.append(identity)
    return result


def _record_document(record: UpstreamRecord, *, context: str) -> dict[str, Any]:
    if record.raw_result is not None:
        document = strict_json_bytes(record.raw_result, context=context)
        if document != record.result:
            raise SharedContractV2Error("decoded-result-mismatch", f"{context} decoded object differs from authenticated bytes")
        return document
    # Tests and in-process resolvers may supply already-decoded records. Round-trip
    # through RFC 8785 so duplicate-key and non-finite-number behavior remains strict.
    return strict_json_bytes(canonical_bytes(record.result), context=context)


def _verify_locator(record: UpstreamRecord, locator: Any, *, capability: str) -> dict[str, Any]:
    document = _record_document(record, context=f"{capability} result")
    if (
        record.result_id != locator.result_id
        or record.terminal_state != locator.terminal_state
        or record.correlation_id != locator.correlation_id
        or locator.result_ref.key != locator.result_id
    ):
        raise SharedContractV2Error("locator-identity-mismatch", f"{capability} result identity differs")
    expected = {
        "run_id": locator.run_id,
        "result_id": locator.result_id,
        "correlation_id": locator.correlation_id,
    }
    payload = document
    context: dict[str, Any] | None = None
    run_result: dict[str, Any] | None = None
    if capability == "check-generation":
        raw_run_result = document.get("run_result")
        canonical_temporal = (
            document.get("capability") == "check-generation"
            and document.get("contract_id") == "check-generation-result@1.0"
        )
        if canonical_temporal:
            if not isinstance(raw_run_result, dict):
                raise SharedContractV2Error("cg-wrapper-invalid", "CG canonical result is incomplete")
            context = {
                "request_id": document.get("request_id"),
                "correlation_id": document.get("correlation_id"),
                "upstream_result_refs": document.get("upstream_result_refs"),
                "inherited_evidence_refs": document.get("evidence_refs") or [],
                "new_evidence_refs": [],
                "result_created_at": document.get("created_at"),
            }
        else:
            if document.get("contract_type") != "check-generation-persisted-result" or document.get("contract_version") != "1.0":
                raise SharedContractV2Error("cg-wrapper-identity-invalid", "expected authenticated Check Generation result")
            raw_context = document.get("temporal_context")
            if not isinstance(raw_context, dict) or not isinstance(raw_run_result, dict):
                raise SharedContractV2Error("cg-wrapper-invalid", "CG wrapper is incomplete")
            context = raw_context
        run_result = raw_run_result
        expected = {"run_id": locator.run_id}
        if document.get("result_id") != locator.result_id:
            raise SharedContractV2Error(
                "cg-wrapper-identity-invalid", "CG wrapper result identity differs"
            )
        if context.get("correlation_id") != locator.correlation_id or context.get("request_id") != locator.request_id:
            raise SharedContractV2Error("cg-wrapper-identity-invalid", "CG temporal identity differs")
        payload = run_result
    if capability == "bypass-validation":
        expected = {"run_id": locator.run_id, "result_id": locator.result_id}
    if any(payload.get(key) != value for key, value in expected.items()):
        raise SharedContractV2Error("locator-identity-mismatch", f"{capability} payload identity differs")
    if capability == "check-generation":
        assert context is not None
        assert run_result is not None
        inherited = context.get("inherited_evidence_refs", [])
        new = context.get("new_evidence_refs", [])
        upstreams = context.get("upstream_result_refs", [])
        if not isinstance(inherited, list) or not isinstance(new, list) or not isinstance(upstreams, list) or len(upstreams) != 1:
            raise SharedContractV2Error("cg-wrapper-invalid", "CG temporal context is incomplete")
        upstream = upstreams[0]
        if not isinstance(upstream, dict):
            raise SharedContractV2Error("cg-wrapper-invalid", "CG upstream lineage is invalid")
        advertised_digest = (
            document.get("content_sha256")
            if canonical_temporal
            else document.get("temporal_result_content_sha256")
        )
        if advertised_digest != locator.content_sha256:
            raise SharedContractV2Error("outer-locator-integrity-failed", "CG wrapper digest differs")
    elif capability != "bypass-validation" and (
        document.get("content_sha256") != locator.content_sha256
        or document.get("size_bytes") != locator.size_bytes
    ):
        raise SharedContractV2Error(
            "outer-locator-integrity-failed",
            f"{capability} advertised integrity differs",
        )
    authenticated = record.authenticated_content
    authenticated_digest = (
        "sha256:" + hashlib_sha256(authenticated).hexdigest()
        if authenticated is not None
        else None
    )
    if (
        authenticated is None
        or record.authenticated_content_sha256 != authenticated_digest
        or record.authenticated_content_size != len(authenticated)
        or authenticated_digest != locator.content_sha256
        or len(authenticated) != locator.size_bytes
    ):
        raise SharedContractV2Error(
            "outer-locator-integrity-failed",
            f"{capability} producer-authenticated bytes differ from the immutable locator",
        )
    return payload


def _coverage_members(ref: dict[str, Any], semantics: dict[str, Any]) -> set[str]:
    components = _index(semantics["components"], "component_id", "components-invalid")
    groups = _index(semantics["coverage"]["groups"], "group_id", "coverage-invalid")
    visiting: set[str] = set()

    def walk(current: dict[str, Any]) -> set[str]:
        if current.get("scope") != semantics["semantics_id"]:
            raise SharedContractV2Error("coverage-scope-mismatch", "coverage scope differs")
        if current.get("kind") == "component":
            component = components.get(str(current.get("id")))
            if component is None:
                raise SharedContractV2Error("coverage-reference-invalid", "unknown coverage component")
            return {item["id"] for item in component["source_member_refs"]}
        identity = current.get("id")
        if current.get("kind") != "coverage-group" or identity not in groups or identity in visiting:
            raise SharedContractV2Error("coverage-reference-invalid", "invalid or cyclic coverage group")
        visiting.add(str(identity))
        members = set().union(*(walk(child) for child in groups[str(identity)]["member_refs"]))
        visiting.remove(str(identity))
        if members != {item["id"] for item in groups[str(identity)]["source_member_refs"]}:
            raise SharedContractV2Error("coverage-ancestry-mismatch", "coverage source ancestry differs")
        return members

    return walk(ref)


def _validate_cg(cg: dict[str, Any], catalog: OfflineSchemaCatalog) -> dict[str, Any]:
    if cg.get("contract_id") != "check-generation@2.1" or not cg.get("result_id"):
        raise SharedContractV2Error("cg-identity-invalid", "expected final check-generation@2.1 result")
    if ("content_digest" in cg or "digest_profile" in cg) and (
        cg.get("digest_profile") != "rfc8785-sha256-exclude-content_digest-v1"
        or cg.get("content_digest") != digest_without(cg, "content_digest")
    ):
        raise SharedContractV2Error("cg-content-digest-mismatch", "CG final content digest differs")
    semantics = cg.get("attack_match_semantics")
    if not isinstance(semantics, dict):
        raise SharedContractV2Error("semantics-absent", "CG semantics are absent")
    catalog.validate(AMS_SCHEMA_ID, semantics)
    if semantics.get("semantics_digest") != digest_without(semantics, "semantics_digest"):
        raise SharedContractV2Error("semantics-digest-mismatch", "embedded semantics digest differs")
    binding = semantics["source_binding"]["check_generation"]
    projection = {key: cg[key] for key in ("artifacts", "input_membership", "member_results", "test_inputs")}
    if (
        binding.get("contract_id") != cg.get("contract_id")
        or binding.get("result_id") != cg.get("result_id")
        or binding.get("revision") != cg.get("revision")
        or binding.get("source_projection_digest") != digest(projection)
    ):
        raise SharedContractV2Error("source-projection-mismatch", "CG source projection or identity differs")
    members = _index(semantics["source_binding"]["members"], "member_id", "source-members-invalid")
    outer_members = _index(cg["member_results"], "member_id", "cg-members-invalid")
    artifacts = _index(semantics["source_binding"]["artifacts"], "artifact_id", "source-artifacts-invalid")
    outer_artifacts = _index(cg["artifacts"], "artifact_id", "cg-artifacts-invalid")
    inputs = _index(semantics["test_inputs"], "input_id", "semantics-inputs-invalid")
    outer_inputs = _index(cg["test_inputs"], "input_id", "cg-inputs-invalid")
    obligations = _index(semantics["obligations"], "obligation_id", "obligations-invalid")
    membership = _index(cg.get("input_membership", {}).get("members"), "member_id", "cg-input-membership-invalid")
    if (
        set(members) != set(outer_members)
        or set(members) != set(membership)
        or set(artifacts) != set(outer_artifacts)
        or not set(inputs) <= set(outer_inputs)
    ):
        raise SharedContractV2Error("cg-completeness-mismatch", "CG embedded and outer identity sets differ")
    if binding.get("member_count") != len(members) or binding.get("artifact_count") != len(artifacts):
        raise SharedContractV2Error("cg-count-mismatch", "CG source binding counts differ")
    represented: set[str] = set()
    for member_id, member in members.items():
        outer = outer_members[member_id]
        declared = membership[member_id]
        if (
            member.get("signal_id") != outer.get("signal_id")
            or member.get("affected_artifact_id") != outer.get("affected_artifact_id")
            or member.get("terminal_state")
            != _shared_terminal_state_from_cg(outer.get("terminal_state"))
            or any(member.get(key) != declared.get(key) for key in ("signal_id", "affected_artifact_id"))
        ):
            raise SharedContractV2Error("cg-member-identity-mismatch", f"CG member differs: {member_id}")
        refs = _ref_ids(member.get("artifact_refs"), kind="source-artifact", scope=semantics["semantics_id"], known=artifacts, code="source-member-artifacts-invalid", allow_empty=True)
        if set(refs) != set(outer.get("artifact_refs", [])) or bool(refs) != (member["terminal_state"] in {"verified", "signal-produced"}):
            raise SharedContractV2Error("cg-member-cardinality-invalid", f"CG member artifact cardinality differs: {member_id}")
    for artifact_id, artifact in artifacts.items():
        outer = outer_artifacts[artifact_id]
        member_ids = _ref_ids(artifact["member_refs"], kind="source-member", scope=semantics["semantics_id"], known=members, code="source-artifact-members-invalid")
        content = artifact.get("content")
        if not isinstance(content, dict):
            raise SharedContractV2Error("cg-artifact-lineage-mismatch", f"CG artifact content is absent: {artifact_id}")
        if str(content.get("uri", "")).startswith("janus-result-internal:"):
            resolved = _resolve_result_internal_content(cg, content)
            expected_content = (
                outer.get("check_artifact", {}).get("candidate")
                if isinstance(outer.get("check_artifact"), dict)
                else outer.get("mitigation_checkable_signal", {}).get("stimulus")
                if isinstance(outer.get("mitigation_checkable_signal"), dict)
                else None
            )
            content_matches = expected_content is not None and resolved == canonical_bytes(expected_content)
        else:
            content_matches = outer.get("content_hash") == content.get("digest")
        if (
            set(member_ids) != set(outer.get("member_ids", []))
            or artifact.get("artifact_kind") != outer.get("artifact_kind")
            or set(artifact.get("signal_ids", [])) != set(outer.get("signal_ids", []))
            or set(artifact.get("affected_artifact_ids", [])) != set(outer.get("affected_artifact_ids", []))
            or not content_matches
        ):
            raise SharedContractV2Error("cg-artifact-lineage-mismatch", f"CG artifact differs: {artifact_id}")
    for input_id, item in inputs.items():
        input_members = _ref_ids(item["source_member_refs"], kind="source-member", scope=semantics["semantics_id"], known=members, code="input-members-invalid")
        represented.update(input_members)
        outer = outer_inputs[input_id]
        source_artifact = _ref_ids([item["source_artifact_ref"]], kind="source-artifact", scope=semantics["semantics_id"], known=artifacts, code="input-artifact-invalid")
        if set(input_members) != set(outer.get("member_ids", [])) or source_artifact != [outer.get("artifact_id")]:
            raise SharedContractV2Error("cg-input-lineage-mismatch", f"CG test input differs: {input_id}")
    unsupported: set[str] = set()
    unsupported_inputs: set[str] = set()
    for item in semantics["unsupported_dimensions"]:
        unsupported.update(_ref_ids(item["source_member_refs"], kind="source-member", scope=semantics["semantics_id"], known=members, code="unsupported-members-invalid", allow_empty=True))
        unsupported_inputs.update(
            _ref_ids(
                item.get("source_input_refs", []),
                kind="test-input",
                scope=semantics["semantics_id"],
                known=outer_inputs,
                code="unsupported-inputs-invalid",
                allow_empty=True,
            )
        )
    if represented & unsupported or represented | unsupported != set(members):
        raise SharedContractV2Error("source-member-partition-incomplete", "represented and unsupported source members are not a complete disjoint partition")
    if set(inputs) & unsupported_inputs or set(inputs) | unsupported_inputs != set(outer_inputs):
        raise SharedContractV2Error(
            "cg-input-partition-incomplete",
            "represented and unsupported CG inputs are not a complete disjoint partition",
        )
    if any(obligation.get("required") is not True for obligation in obligations.values()):
        raise SharedContractV2Error("optional-obligation", "all shared-contract obligations must be required")
    for obligation in obligations.values():
        _coverage_members(obligation["coverage_ref"], semantics)
        _ref_ids(obligation["required_input_refs"], kind="test-input", scope=semantics["semantics_id"], known=inputs, code="obligation-inputs-invalid")
    return semantics


def _resolve_artifact_contents(
    dg: dict[str, Any],
    bundle: dict[str, Any],
    exact_contents: Mapping[str, bytes] | None,
) -> dict[str, bytes]:
    raw_contents = dg.get("candidate_artifact_contents")
    if not isinstance(raw_contents, dict):
        raise SharedContractV2Error("candidate-artifacts-absent", "DG result has no candidate_artifact_contents")
    artifacts = _index(bundle["primary_candidate"]["artifacts"], "artifact_id", "candidate-artifacts-invalid")
    if set(raw_contents) != set(artifacts):
        raise SharedContractV2Error("candidate-artifact-partition-incomplete", "candidate artifact content set differs")
    contents: dict[str, bytes] = {}
    for artifact_id, value in raw_contents.items():
        raw = (
            exact_contents[artifact_id]
            if exact_contents is not None and artifact_id in exact_contents
            else canonical_bytes(value)
        )
        if strict_json_bytes(raw, context=f"candidate artifact {artifact_id}") != value:
            raise SharedContractV2Error(
                "candidate-artifact-integrity-failed",
                f"candidate artifact decodes differently: {artifact_id}",
            )
        locator = artifacts[artifact_id]["content"]
        if locator.get("digest") != "sha256:" + hashlib_sha256(raw).hexdigest() or locator.get("byte_length") != len(raw) or locator.get("immutable") is not True:
            raise SharedContractV2Error("candidate-artifact-integrity-failed", f"candidate artifact differs: {artifact_id}")
        contents[artifact_id] = raw
    return contents


def _validate_bundle(bundle: dict[str, Any], semantics: dict[str, Any], cg: dict[str, Any], cg_raw: bytes | None, dg: dict[str, Any], artifact_raw_results: Mapping[str, bytes] | None, catalog: OfflineSchemaCatalog) -> tuple[dict[str, Any], dict[str, bytes]]:
    catalog.validate(BUNDLE_SCHEMA_ID, bundle)
    candidate = bundle["primary_candidate"]
    if candidate.get("selected_control_class") != "waf":
        raise SharedContractV2Error("candidate-control-class-invalid", "WAF-first requires a WAF candidate")
    if candidate.get("candidate_digest") != digest_without(candidate, "candidate_digest"):
        raise SharedContractV2Error("candidate-digest-mismatch", "candidate digest differs")
    bundle_preimage = deepcopy(bundle)
    bundle_preimage.pop("bundle_digest", None)
    bundle_preimage["primary_candidate"].pop("candidate_digest", None)
    if bundle.get("bundle_digest") != digest(bundle_preimage):
        raise SharedContractV2Error("bundle-digest-mismatch", "bundle digest differs")
    binding = bundle["semantics_binding"]
    if any(binding.get(key) != semantics.get(key) for key in ("contract_id", "semantics_id", "semantics_revision", "semantics_digest")):
        raise SharedContractV2Error("bound-semantics-mismatch", "DG semantics binding differs")
    locator = binding["locator"]
    exact_cg = cg_raw or canonical_bytes(cg)
    decoded_cg = strict_json_bytes(exact_cg, context="bound CG result")
    bound_cg = decoded_cg.get("run_result", decoded_cg)
    if isinstance(bound_cg, dict):
        bound_cg = {
            key: value
            for key, value in bound_cg.items()
            if key != "_verified_characterization_revision_id"
        }
    if bound_cg != cg:
        raise SharedContractV2Error("bound-cg-locator-mismatch", "DG bound CG bytes decode differently")
    if locator.get("digest") != "sha256:" + hashlib_sha256(exact_cg).hexdigest() or locator.get("byte_length") != len(exact_cg):
        raise SharedContractV2Error("bound-cg-locator-mismatch", "DG does not bind the exact CG final result")
    artifacts = _index(candidate["artifacts"], "artifact_id", "candidate-artifacts-invalid")
    directives = _index(candidate["directives"], "directive_id", "candidate-directives-invalid")
    if [item.get("order") for item in candidate["artifacts"]] != list(range(len(artifacts))):
        raise SharedContractV2Error("candidate-artifact-order-invalid", "candidate artifact order is not contiguous")
    contents = _resolve_artifact_contents(dg, bundle, artifact_raw_results)
    application_ids = _ref_ids(bundle["application_unit"]["artifact_refs"], kind="artifact", scope=bundle["bundle_id"], known=artifacts, code="application-unit-invalid")
    if set(application_ids) != set(artifacts) or any(bundle["application_unit"].get(key) != expected for key, expected in {"apply": "all-or-nothing", "rollback": "all-or-nothing", "remove": "all-or-nothing", "readback": "verify-every-artifact-or-rollback"}.items()):
        raise SharedContractV2Error("application-unit-incomplete", "DG complete application unit differs")
    atomic_groups = _index(bundle["atomic_groups"], "atomic_group_id", "atomic-groups-invalid")
    for artifact in artifacts.values():
        group_ids = _ref_ids([artifact["application_group_ref"]], kind="atomic-group", scope=bundle["bundle_id"], known=atomic_groups, code="artifact-atomic-group-invalid")
        _ref_ids(artifact["depends_on"], kind="artifact", scope=bundle["bundle_id"], known=artifacts, code="artifact-dependency-invalid", allow_empty=True)
        group = atomic_groups[group_ids[0]]
        group_members = _ref_ids(group["artifact_refs"], kind="artifact", scope=bundle["bundle_id"], known=artifacts, code="atomic-group-artifacts-invalid")
        if artifact["artifact_id"] not in group_members:
            raise SharedContractV2Error("artifact-atomic-group-invalid", "artifact is absent from its atomic group")
    obligations = _index(semantics["obligations"], "obligation_id", "obligations-invalid")
    mappings = _index(candidate["obligation_mappings"], "obligation_id", "candidate-mappings-invalid")
    if set(mappings) != set(obligations):
        raise SharedContractV2Error("obligation-id-incomplete", "DG mapping IDs differ from required CG IDs")
    members = _index(semantics["source_binding"]["members"], "member_id", "source-members-invalid")
    for obligation_id, mapping in mappings.items():
        obligation = obligations[obligation_id]
        if mapping.get("coverage") != "exact" or mapping.get("semantics_refs") != [obligation["coverage_ref"]]:
            raise SharedContractV2Error("obligation-semantics-mismatch", f"DG semantics mapping differs: {obligation_id}")
        mapped_members = _ref_ids(mapping["source_member_refs"], kind="source-member", scope=semantics["semantics_id"], known=members, code="obligation-members-invalid")
        if set(mapped_members) != _coverage_members(obligation["coverage_ref"], semantics):
            raise SharedContractV2Error("obligation-source-ancestry-mismatch", f"DG source-member mapping differs: {obligation_id}")
        _ref_ids(mapping["artifact_refs"], kind="artifact", scope=bundle["bundle_id"], known=artifacts, code="obligation-artifacts-invalid")
        _ref_ids(mapping["directive_refs"], kind="directive", scope=bundle["bundle_id"], known=directives, code="obligation-directives-invalid")
    attestation = {key: source[key] for source, keys in ((bundle, ("bundle_id", "bundle_revision", "bundle_digest")), (candidate, ("candidate_id", "candidate_revision", "candidate_digest"))) for key in keys}
    return attestation, contents


def _accounting(
    semantics: dict[str, Any],
    *,
    required_work: int,
    disposed_work: int,
) -> CoverageAccounting:
    members = {item["member_id"] for item in semantics["source_binding"]["members"]}
    represented = {ref["id"] for item in semantics["test_inputs"] for ref in item["source_member_refs"]}
    unsupported = {ref["id"] for item in semantics["unsupported_dimensions"] for ref in item["source_member_refs"]}
    if represented & unsupported or represented | unsupported != members:
        raise SharedContractV2Error("source-member-partition-incomplete", "source member partition differs")
    if disposed_work > required_work:
        raise SharedContractV2Error("coverage-accounting-invalid", "disposed work exceeds required work")
    count = len(semantics["obligations"])
    return CoverageAccounting(
        required_obligation_count=count,
        accounted_obligation_count=count,
        unaccounted_required_obligation_count=0,
        source_member_count=len(members),
        represented_source_member_count=len(represented),
        unsupported_source_member_count=len(unsupported),
        unaccounted_source_member_count=0,
        required_work_item_count=required_work,
        disposed_work_item_count=disposed_work,
        unaccounted_required_work_item_count=required_work - disposed_work,
    )


def _expected_template_resolution(
    item: dict[str, Any],
    *,
    resolver_id: str,
    profile_id: str,
    profile_digest: str,
    route: Mapping[str, str],
) -> dict[str, Any]:
    template = item["input"]
    rendered = deepcopy(template)
    rendered.pop("path_key", None)
    path_payload = rendered.pop("path_payload", None)
    path = route["path"]
    if path_payload is not None:
        if not isinstance(path_payload, str) or not path_payload:
            raise SharedContractV2Error(
                "mc-template-resolution-invalid",
                f"CG path payload is invalid: {item['input_id']}",
            )
        path = path.rstrip("/") + "/" + _path_segment_escape(path_payload)
    rendered.update(
        modality="http-request",
        scheme=route["scheme"],
        authority=route["authority"],
        path=path,
    )
    return {
        "template_id": item["input_id"],
        "path_key": template["path_key"],
        "resolver_id": resolver_id,
        "profile_id": profile_id,
        "resolver_profile_digest": profile_digest,
        "rendered_request": rendered,
    }


def _validate_mc_evidence(case: dict[str, Any], *, obligation_id: str) -> None:
    evidence = case.get("evidence")
    disposition = case["disposition"]
    if not isinstance(evidence, dict) or not evidence or not set(evidence) <= {
        "blocked", "status_code", "reached_app", "matched_rule_id", "detail"
    }:
        raise SharedContractV2Error("mc-case-evidence-invalid", f"MC evidence differs: {obligation_id}")
    if not isinstance(evidence.get("detail"), str) or not evidence["detail"]:
        raise SharedContractV2Error("mc-case-evidence-invalid", f"MC evidence detail is absent: {obligation_id}")
    if disposition == "blocked":
        valid = (
            evidence.get("blocked") is True
            and evidence.get("status_code") == 403
            and "reached_app" not in evidence
            and isinstance(evidence.get("matched_rule_id"), str)
            and bool(evidence["matched_rule_id"])
        )
    elif disposition == "not-blocked":
        valid = (
            "blocked" not in evidence
            and type(evidence.get("status_code")) is int
            and 100 <= evidence["status_code"] <= 599
            and evidence.get("reached_app") is True
            and "matched_rule_id" not in evidence
        )
    else:
        valid = set(evidence) == {"detail"}
    if not valid:
        raise SharedContractV2Error("mc-case-evidence-invalid", f"MC evidence contradicts disposition: {obligation_id}")


def _validate_mc_resolution(case: dict[str, Any], item: dict[str, Any], *, obligation_id: str, profile_id: str, profile_digest: str) -> None:
    template = item["input"]
    resolution = case.get("resolution")
    if template.get("modality") != "http-request-template":
        if resolution is not None:
            raise SharedContractV2Error("mc-template-resolution-invalid", f"MC invented a template resolution: {obligation_id}")
        return
    routes = {
        "inventory-item-detail": {"scheme": "https", "authority": "approved-mc-target.internal", "path": "/inventory/items/42"},
    }
    if profile_id == CT_PROFILE_ID:
        raw = (BV_PROFILE_ROOT / "mc-http-route-profile-v2.json").read_bytes()
        if len(raw) != MC_PROFILE_BYTE_LENGTH or "sha256:" + hashlib_sha256(raw).hexdigest() != MC_PROFILE_FILE_DIGEST:
            raise SharedContractV2Error("mc-profile-integrity-failed", "embedded waf-standard@2 profile bytes differ")
        profile = strict_json_bytes(raw, context="waf-standard@2 profile")
        if profile.get("profile_id") != CT_PROFILE_ID or profile.get("resolver_id") != MC_RESOLVER_ID or digest(profile) != profile_digest:
            raise SharedContractV2Error("mc-profile-integrity-failed", "embedded waf-standard@2 profile identity differs")
        routes = profile.get("routes", {})
    route = routes.get(template.get("path_key"))
    if route is None:
        raise SharedContractV2Error("mc-template-resolution-invalid", f"MC accepted an unknown path key: {obligation_id}")
    expected = _expected_template_resolution(
        item,
        resolver_id=MC_RESOLVER_ID,
        profile_id=profile_id,
        profile_digest=profile_digest,
        route=route,
    )
    if resolution != expected:
        raise SharedContractV2Error("mc-template-resolution-invalid", f"MC template resolution differs: {obligation_id}")


def _validate_mc(
    mc: dict[str, Any],
    semantics: dict[str, Any],
    bundle: dict[str, Any],
    locators: Mapping[str, Any],
    *,
    profile_id: str = LEGACY_CT_PROFILE_ID,
    profile_digest: str = LEGACY_MC_RESOLVER_PROFILE_DIGEST,
) -> None:
    if mc.get("capability") != "mitigation-check" or mc.get("contract_id") != "mitigation-check@1.0" or mc.get("terminal_state") != "blocked" or mc.get("status") != "completed" or mc.get("profile_id") != profile_id:
        raise SharedContractV2Error("mc-identity-invalid", "MC identity, state, or profile differs")
    if mc.get("match") is not True:
        raise SharedContractV2Error(
            "mc-aggregate-outcome-invalid",
            "MC blocked aggregate must report match true",
        )
    provenance = mc.get("input_provenance")
    if (
        not isinstance(provenance, dict)
        or provenance.get("route_policy") != "shared-attack-contracts-v2"
        or provenance.get("verification") not in {
            "physical-and-logical-sha256-verified",
            "workflow-lab-physical-and-logical-sha256-verified",
        }
    ):
        raise SharedContractV2Error("mc-chain-provenance-mismatch", "MC chain provenance differs")
    for key, capability in (("check_result", "check-generation"), ("defense_result", "defense-generation")):
        if not _same_locator_document(provenance.get(key), locators[capability]):
            raise SharedContractV2Error("mc-chain-provenance-mismatch", f"MC {key} differs")
    expected_artifacts = [item["id"] for item in bundle["application_unit"]["artifact_refs"]]
    if mc.get("application_unit") != {"application_unit_id": bundle["application_unit"]["application_unit_id"], "artifact_ids": expected_artifacts, "readback_verified": True}:
        raise SharedContractV2Error("mc-application-attestation-mismatch", "MC complete application unit differs")
    obligations = _index(semantics["obligations"], "obligation_id", "obligations-invalid")
    results = _index(mc.get("obligation_results"), "obligation_id", "mc-obligation-results-invalid")
    if set(results) != set(obligations):
        raise SharedContractV2Error("mc-obligation-accounting-invalid", "MC obligation IDs differ")
    inputs = _index(semantics["test_inputs"], "input_id", "semantics-inputs-invalid")
    work = 0
    for obligation_id, obligation in obligations.items():
        cases = _index(results[obligation_id].get("case_results"), "input_id", "mc-case-results-invalid")
        expected = {item["id"] for item in obligation["required_input_refs"]}
        if set(cases) != expected or any(
            not set(case) <= {"input_id", "disposition", "resolution", "evidence"}
            or not {"input_id", "disposition", "evidence"} <= set(case)
            or case.get("disposition") != "blocked"
            for case in cases.values()
        ):
            raise SharedContractV2Error(
                "mc-translation-outcome-invalid",
                f"MC required cases must all be blocked: {obligation_id}",
            )
        for input_id, case in cases.items():
            _validate_mc_evidence(case, obligation_id=obligation_id)
            _validate_mc_resolution(case, inputs[input_id], obligation_id=obligation_id, profile_id=profile_id, profile_digest=profile_digest)
        work += len(cases)
    if mc.get("accounting") != _accounting(
        semantics,
        required_work=work,
        disposed_work=work,
    ).model_dump(mode="json"):
        raise SharedContractV2Error("mc-accounting-invalid", "MC CoverageAccounting differs")


@lru_cache(maxsize=2)
def _bv_profile(profile_id: str) -> dict[str, Any]:
    metadata = {
        "waf-bypass@2": ("bv-http-route-profile.json", LEGACY_BV_PROFILE_BYTE_LENGTH, LEGACY_BV_PROFILE_FILE_DIGEST, LEGACY_BV_RESOLVER_PROFILE_DIGEST),
        "waf-bypass@3": ("bv-http-route-profile-v3.json", BV_PROFILE_BYTE_LENGTH, BV_PROFILE_FILE_DIGEST, BV_RESOLVER_PROFILE_DIGEST),
    }
    if profile_id not in metadata:
        raise SharedContractV2Error("bv-profile-integrity-failed", "unapproved embedded BV profile")
    filename, byte_length, file_digest, profile_digest = metadata[profile_id]
    if profile_id == "waf-bypass@3":
        manifest = strict_json_bytes(
            (BV_PROFILE_ROOT / "manifest-v3.json").read_bytes(),
            context="waf-bypass@3 manifest",
        )
        expected_manifest = {
            "manifest_version": 1,
            "profile_id": profile_id,
            "resolver_id": BV_RESOLVER_ID,
            "registry_id": "janus-approved-test-routes",
            "relative_path": filename,
            "sha256": file_digest,
            "byte_length": byte_length,
            "resolver_profile_digest": profile_digest,
        }
        if manifest != expected_manifest:
            raise SharedContractV2Error(
                "bv-profile-integrity-failed",
                "embedded waf-bypass@3 manifest metadata differs",
            )
    raw = (BV_PROFILE_ROOT / filename).read_bytes()
    if len(raw) != byte_length or "sha256:" + hashlib_sha256(raw).hexdigest() != file_digest:
        raise SharedContractV2Error("bv-profile-integrity-failed", f"embedded {profile_id} profile bytes differ")
    profile = strict_json_bytes(raw, context=f"{profile_id} profile")
    if (
        profile.get("profile_id") != profile_id
        or profile.get("resolver_id") != BV_RESOLVER_ID
        or digest(profile) != profile_digest
        or not isinstance(profile.get("routes"), dict)
        or not isinstance(profile.get("bypass_dimensions"), dict)
    ):
        raise SharedContractV2Error("bv-profile-integrity-failed", f"embedded {profile_id} profile identity differs")
    return profile


def _coverage_component_ids(ref: dict[str, Any], semantics: dict[str, Any]) -> list[str]:
    groups = _index(semantics["coverage"]["groups"], "group_id", "coverage-invalid")
    result: list[str] = []
    visiting: set[str] = set()

    def walk(current: dict[str, Any]) -> None:
        if current.get("kind") == "component":
            if current.get("id") not in result:
                result.append(current["id"])
            return
        identity = current.get("id")
        if current.get("kind") != "coverage-group" or identity not in groups or identity in visiting:
            raise SharedContractV2Error("coverage-reference-invalid", "invalid or cyclic coverage group")
        visiting.add(identity)
        for child in groups[identity]["member_refs"]:
            walk(child)
        visiting.remove(identity)

    walk(ref)
    return result


def _component_carrier(component: dict[str, Any]) -> str:
    return {
        "http-query": "query",
        "http-header": "header",
        "http-cookie": "cookie",
        "http-method": "method",
        "http-body-raw": "body-raw",
        "http-body-structured": "body-json",
        "http-path": "path",
    }.get(component["location"].get("kind"), "unsupported")


def _component_target_label(component: dict[str, Any]) -> str:
    location = component["location"]
    kind = str(location["kind"])
    if kind in {"http-query", "http-header", "http-cookie"}:
        return f"{kind}:{location['name']}:{location.get('occurrence', 0)}"
    if kind == "http-body-structured":
        if location.get("selector_type") == "any-field":
            return "http-body-structured:*"
        return f"{kind}:{location['selector']}"
    if kind == "http-path":
        return "http-path:path-payload"
    return kind


def _component_target_label_matches(component: dict[str, Any], label: str) -> bool:
    location = component["location"]
    kind = str(location["kind"])
    if kind in {"http-query", "http-header", "http-cookie"} and location.get("name") == "*":
        prefix = f"{kind}:"
        name, separator, occurrence = label.removeprefix(prefix).rpartition(":")
        return label.startswith(prefix) and bool(separator and name) and occurrence.isdecimal()
    if kind == "http-body-structured" and location.get("selector_type") == "any-field":
        return label.startswith("http-body-structured:/")
    return label == _component_target_label(component)


def _expected_grammar_labels(component: dict[str, Any]) -> list[str]:
    grammar = component.get("grammar")
    if not isinstance(grammar, dict):
        return ["grammar:exact"]
    segments = grammar.get("segments")
    raw_slots = grammar.get("slots")
    if not isinstance(segments, list) or not isinstance(raw_slots, list) or not raw_slots:
        return ["grammar:exact"]
    slots = _index(raw_slots, "slot_id", "grammar-slots-invalid")

    def render(overrides: Mapping[str, Any]) -> Any:
        if (
            len(segments) == 1
            and isinstance(segments[0], dict)
            and segments[0].get("kind") == "slot"
        ):
            ref = segments[0].get("slot_ref")
            if isinstance(ref, dict) and ref.get("id") in slots:
                slot_id = ref["id"]
                return overrides.get(slot_id, slots[slot_id].get("sample"))
        parts: list[str] = []
        for segment in segments:
            if isinstance(segment, dict) and segment.get("kind") == "literal":
                parts.append(str(segment.get("value", "")))
                continue
            ref = segment.get("slot_ref") if isinstance(segment, dict) else None
            slot_id = ref.get("id") if isinstance(ref, dict) else None
            if slot_id not in slots:
                raise SharedContractV2Error(
                    "grammar-slot-ref-invalid", "grammar slot reference differs"
                )
            parts.append(str(overrides.get(slot_id, slots[slot_id].get("sample"))))
        return "".join(parts)

    domains: list[tuple[str, list[Any]]] = []
    for slot in raw_slots:
        domain = slot.get("allowed_domain")
        values = domain.get("values") if isinstance(domain, dict) else None
        if domain is not None and domain.get("kind") == "enum":
            if not isinstance(values, list) or not values:
                raise SharedContractV2Error(
                    "grammar-enum-invalid", "grammar enum domain is invalid"
                )
            domains.append((slot["slot_id"], values))
        else:
            domains.append((slot["slot_id"], [slot.get("sample")]))
    labels: list[str] = []
    seen: set[bytes] = set()
    for ordinal, combination in enumerate(
        itertools.product(*(domain for _, domain in domains))
    ):
        overrides = {
            slot_id: value
            for (slot_id, _), value in zip(domains, combination, strict=True)
        }
        rendered = render(overrides)
        key = canonical_bytes(rendered)
        if key in seen:
            continue
        seen.add(key)
        labels.append(
            "grammar:sample"
            if all(
                overrides[slot_id] == slots[slot_id].get("sample")
                for slot_id in overrides
            )
            else f"grammar:product:{ordinal}"
        )
    return labels


def _expected_bv_dimensions(obligation: dict[str, Any], semantics: dict[str, Any], *, profile_id: str = "waf-bypass@2") -> list[dict[str, Any]]:
    profile = _bv_profile(profile_id)
    components = _index(semantics["components"], "component_id", "components-invalid")
    component_ids = _coverage_component_ids(obligation["coverage_ref"], semantics)
    expected: list[dict[str, Any]] = []
    for input_ref in obligation["required_input_refs"]:
        input_id = input_ref["id"]
        for component_id in component_ids:
            component = components[component_id]
            if input_id not in {ref["id"] for ref in component["input_refs"]}:
                continue
            carrier = _component_carrier(component)
            chain_labels: list[str] = []
            transformations = list(component["transformations"])
            if transformations:
                chain_labels.append("cg:" + ":".join(step["operation"] for step in transformations))
            for index, chain in enumerate(profile["bypass_dimensions"].get(carrier, [])):
                bv_label = f"bv:{carrier}:{index}:" + ":".join(step["operation"] for step in chain)
                chain_labels.append(bv_label)
                if (
                    transformations
                    and chain
                    and transformations[-1].get("output_stage")
                    == chain[0].get("input_stage")
                ):
                    chain_labels.append("cg+" + bv_label)
            if not chain_labels:
                chain_labels.append("baseline:identity")
            grammar_labels = (
                _expected_grammar_labels(component)
                if profile_id == "waf-bypass@3"
                else ["grammar:exact"]
            )
            for grammar_label in grammar_labels:
                for chain_label in chain_labels:
                    label = (
                        chain_label
                        if grammar_label == "grammar:exact"
                        else f"{grammar_label}|{chain_label}"
                    )
                    expected.append({
                        "carrier": carrier,
                        "transformation": label,
                        "input_id": input_id,
                        "component_id": component_id,
                    })
    return expected


def _v3_challenge_attribution(
    attribution: str,
    *,
    actual: dict[str, Any],
    component: dict[str, Any],
    producer_attributions: set[str],
    challenges: dict[str, dict[str, Any]],
) -> None:
    fields = attribution.split("|")
    if (
        len(fields) not in {4, 5}
        or not fields[0].startswith("challenge:")
        or fields[1] != f"component:{actual['component_id']}"
        or fields[2] != f"carrier:{actual['carrier']}"
        or not fields[3].startswith("transformation:")
        or (
            len(fields) == 5
            and not _component_target_label_matches(
                component, fields[4].removeprefix("target:")
            )
        )
    ):
        raise SharedContractV2Error(
            "bv-dimension-invalid", f"BV challenge attribution shape differs: {attribution}"
        )
    challenge_label = fields[0].removeprefix("challenge:")
    transformation = fields[3].removeprefix("transformation:")
    if challenge_label == "source:authenticated-representation":
        producer_chains = {
            label.split("|", 1)[1] if label.startswith("grammar:") else label
            for label in producer_attributions
        }
        producer_chains.add("baseline:authenticated-source")
        if transformation not in producer_chains:
            raise SharedContractV2Error(
                "bv-dimension-invalid",
                "BV authenticated source representation has an unexpected transformation",
            )
        return
    matching_ids = [
        challenge_id
        for challenge_id in challenges
        if challenge_label.startswith(f"{challenge_id}:")
    ]
    if not matching_ids:
        raise SharedContractV2Error(
            "bv-dimension-invalid", "BV challenge attribution is not profile-approved"
        )
    challenge_id = max(matching_ids, key=len)
    challenge = challenges[challenge_id]
    if actual["carrier"] not in challenge.get("carriers", []):
        raise SharedContractV2Error(
            "bv-dimension-invalid", "BV challenge carrier is not profile-approved"
        )
    grammar = component.get("grammar")
    slots = grammar.get("slots") if isinstance(grammar, dict) else None
    if not isinstance(slots, list):
        raise SharedContractV2Error(
            "bv-dimension-invalid", "BV challenge component has no declared slots"
        )
    challenge_suffix = challenge_label[len(challenge_id) + 1 :]
    matching_slots = [
        slot
        for slot in slots
        if isinstance(slot, dict)
        and isinstance(slot.get("slot_id"), str)
        and (
            challenge_suffix == slot["slot_id"]
            or challenge_suffix.startswith(f"{slot['slot_id']}:")
        )
    ]
    if not matching_slots:
        raise SharedContractV2Error(
            "bv-dimension-invalid", "BV challenge names an unknown component slot"
        )
    slot = max(matching_slots, key=lambda item: len(item["slot_id"]))
    ordinal_suffix = challenge_suffix[len(slot["slot_id"]) :]
    ordinal: int | None = None
    if ordinal_suffix:
        raw_ordinal = ordinal_suffix.removeprefix(":")
        if not raw_ordinal.isdecimal():
            raise SharedContractV2Error(
                "bv-dimension-invalid", "BV challenge ordinal is malformed"
            )
        ordinal = int(raw_ordinal)
        if ordinal >= challenge.get("maximum_values", 0):
            raise SharedContractV2Error(
                "bv-dimension-invalid", "BV challenge ordinal exceeds its profile bound"
            )
    domain = slot.get("allowed_domain")
    if (
        slot.get("value_type") not in challenge.get("value_types", [])
        or not isinstance(domain, dict)
        or domain.get("kind") not in challenge.get("domain_kinds", [])
    ):
        raise SharedContractV2Error(
            "bv-dimension-invalid", "BV challenge is inapplicable to its declared slot"
        )
    if actual.get("supported") is False:
        if transformation != "unsupported":
            raise SharedContractV2Error(
                "bv-dimension-invalid", "BV unsupported challenge attribution differs"
            )
        return
    if ordinal is None:
        raise SharedContractV2Error(
            "bv-dimension-invalid", "BV supported challenge has no bounded ordinal"
        )
    if challenge.get("strategy") == "representation":
        expected_transformation = f"authenticated-encode-{challenge.get('codec')}"
        if transformation != expected_transformation:
            raise SharedContractV2Error(
                "bv-dimension-invalid", "BV representation challenge transformation differs"
            )
        return
    producer_chains = {
        label.split("|", 1)[1] if label.startswith("grammar:") else label
        for label in producer_attributions
    }
    if component.get("transformations"):
        producer_chains.add("baseline:authenticated-source")
    if transformation not in producer_chains:
        raise SharedContractV2Error(
            "bv-dimension-invalid", "BV challenge transformation is not producer-derived"
        )


def _validate_bv_v3_dimensions(
    dimensions: list[Any],
    obligation: dict[str, Any],
    semantics: dict[str, Any],
    *,
    obligation_id: str,
) -> None:
    components = _index(semantics["components"], "component_id", "components-invalid")
    producer_by_target: dict[tuple[str, str, str], set[str]] = {}
    for expected in _expected_bv_dimensions(
        obligation, semantics, profile_id="waf-bypass@3"
    ):
        target = (
            expected["input_id"],
            expected["component_id"],
            expected["carrier"],
        )
        producer_by_target.setdefault(target, set()).add(expected["transformation"])
    transformed_targets = {
        target
        for target in producer_by_target
        if components[target[1]].get("transformations")
    }
    profile_challenges = _bv_profile("waf-bypass@3").get("positive_challenges")
    if not isinstance(profile_challenges, list):
        raise SharedContractV2Error(
            "bv-profile-integrity-failed", "embedded waf-bypass@3 challenges are absent"
        )
    challenges = _index(profile_challenges, "challenge_id", "bv-profile-integrity-failed")
    seen_dimensions: set[bytes] = set()
    seen_attributions: set[tuple[tuple[str, str, str], str]] = set()
    observed_producers: dict[tuple[str, str, str], set[str]] = {
        target: set() for target in producer_by_target
    }
    observed_authenticated_source: set[tuple[str, str, str]] = set()
    for actual in dimensions:
        if not isinstance(actual, dict):
            raise SharedContractV2Error(
                "bv-dimension-invalid", f"BV dimension is malformed: {obligation_id}"
            )
        input_id = actual.get("input_id")
        component_id = actual.get("component_id")
        carrier = actual.get("carrier")
        if (
            not isinstance(input_id, str)
            or not input_id
            or not isinstance(component_id, str)
            or not component_id
            or not isinstance(carrier, str)
            or not carrier
        ):
            raise SharedContractV2Error(
                "bv-dimension-invalid",
                f"BV dimension identity fields are absent: {obligation_id}",
            )
        target: tuple[str, str, str] = (input_id, component_id, carrier)
        producer_attributions = producer_by_target.get(target)
        if producer_attributions is None:
            raise SharedContractV2Error(
                "bv-dimension-invalid",
                f"BV dimension is unreachable from its obligation: {obligation_id}",
            )
        component = components[target[1]]
        if (
            target[0] not in {ref["id"] for ref in obligation["required_input_refs"]}
            or target[0] not in {ref["id"] for ref in component["input_refs"]}
            or target[2] != _component_carrier(component)
        ):
            raise SharedContractV2Error(
                "bv-dimension-invalid",
                f"BV dimension input, component, or carrier differs: {obligation_id}",
            )
        transformation = actual.get("transformation")
        if not isinstance(transformation, str) or not transformation:
            raise SharedContractV2Error(
                "bv-dimension-invalid", f"BV dimension label is absent: {obligation_id}"
            )
        dimension_key = canonical_bytes(
            {
                "carrier": target[2],
                "transformation": transformation,
                "input_id": target[0],
                "component_id": target[1],
            }
        )
        if dimension_key in seen_dimensions:
            raise SharedContractV2Error(
                "bv-dimension-invalid", f"BV dimension is duplicated: {obligation_id}"
            )
        seen_dimensions.add(dimension_key)
        attributions = transformation.split("||attribution:")
        if any(not attribution for attribution in attributions) or len(attributions) != len(
            set(attributions)
        ):
            raise SharedContractV2Error(
                "bv-dimension-invalid", f"BV dimension attributions are invalid: {obligation_id}"
            )
        if actual.get("supported") is False and any(
            not attribution.startswith("challenge:") for attribution in attributions
        ):
            raise SharedContractV2Error(
                "bv-dimension-invalid",
                f"BV unsupported label is not an approved challenge: {obligation_id}",
            )
        for attribution in attributions:
            attribution_key = (target, attribution)
            if attribution_key in seen_attributions:
                raise SharedContractV2Error(
                    "bv-dimension-invalid",
                    f"BV attribution is duplicated across dimensions: {obligation_id}",
                )
            seen_attributions.add(attribution_key)
            producer_attribution = attribution
            base_attribution, separator, target_label = producer_attribution.rpartition(
                "|target:"
            )
            if separator and _component_target_label_matches(component, target_label):
                producer_attribution = base_attribution
            if producer_attribution in producer_attributions:
                observed_producers[target].add(producer_attribution)
                continue
            _v3_challenge_attribution(
                attribution,
                actual=actual,
                component=component,
                producer_attributions=producer_attributions,
                challenges=challenges,
            )
            if attribution.startswith("challenge:source:authenticated-representation|"):
                observed_authenticated_source.add(target)
    if any(
        (
            target in transformed_targets
            and target not in observed_authenticated_source
            and observed_producers[target] != expected
        )
        or (
            target not in transformed_targets
            and observed_producers[target] != expected
        )
        for target, expected in producer_by_target.items()
    ):
        raise SharedContractV2Error(
            "bv-dimension-invalid",
            f"BV campaign omitted required producer baseline work: {obligation_id}",
        )


def _validate_bv_resolution(
    resolution: Any,
    *,
    item: dict[str, Any],
    component: dict[str, Any],
    obligation_id: str,
    profile_id: str,
    profile_digest: str,
) -> None:
    profile = _bv_profile(profile_id)
    template = item["input"]
    route = profile["routes"].get(template.get("path_key"))
    if not isinstance(route, dict):
        raise SharedContractV2Error("bv-template-resolution-invalid", f"BV accepted an unknown path key: {obligation_id}")
    base = _expected_template_resolution(
        item,
        resolver_id=BV_RESOLVER_ID,
        profile_id=profile_id,
        profile_digest=profile_digest,
        route=route,
    )
    if not isinstance(resolution, dict) or set(resolution) != set(base) or any(
        resolution[key] != value for key, value in base.items() if key != "rendered_request"
    ):
        raise SharedContractV2Error("bv-template-resolution-invalid", f"BV template resolution identity differs: {obligation_id}")
    rendered = resolution.get("rendered_request")
    expected_rendered = base["rendered_request"]
    location_kind = component["location"].get("kind")
    expected_keys = set(expected_rendered)
    if location_kind == "http-path":
        expected_keys.add("path_payload")
    if not isinstance(rendered, dict) or set(rendered) != expected_keys:
        raise SharedContractV2Error("bv-template-resolution-invalid", f"BV rendered request shape differs: {obligation_id}")
    mutable_field = {
        "http-query": "query", "http-header": "headers", "http-cookie": "cookies",
        "http-method": "method", "http-path": "path", "http-body-raw": "body",
        "http-body-structured": "body",
    }.get(location_kind)
    mutable_fields = {mutable_field}
    if location_kind == "http-path":
        mutable_fields.add("path_payload")
    if mutable_field is None or any(
        rendered[key] != value for key, value in expected_rendered.items() if key not in mutable_fields
    ):
        raise SharedContractV2Error("bv-template-resolution-invalid", f"BV changed a nonselected template field: {obligation_id}")


def _validate_bv(bv: dict[str, Any], semantics: dict[str, Any], attestation: dict[str, Any], locators: Mapping[str, Any], *, profile_id: str, profile_digest: str) -> CoverageAccounting:
    if (
        bv.get("contract_id") != "bypass-validation@2.0"
        or bv.get("profile_id") != profile_id
        or bv.get("terminal_state") != "no-bypass-found"
    ):
        raise SharedContractV2Error(
            "bv-identity-invalid", "BV identity, state, or profile differs"
        )
    if bv.get("candidate_attestation") != attestation:
        raise SharedContractV2Error("bv-candidate-attestation-mismatch", "BV candidate attestation differs")
    bindings = bv.get("input_bindings")
    if not isinstance(bindings, dict):
        raise SharedContractV2Error("bv-chain-provenance-mismatch", "BV input bindings are absent")
    upstreams = bindings.get("shared_contract_locators")
    if (
        not isinstance(upstreams, list)
        or len(upstreams) != 3
        or any(
            not _same_locator_document(actual, locators[name])
            for actual, name in zip(
                upstreams,
                ("check-generation", "defense-generation", "mitigation-check"),
                strict=True,
            )
        )
        or bindings.get("bypass_profile_id") != profile_id
        or not isinstance(bindings.get("validation_substrate_id"), str)
        or not bindings["validation_substrate_id"]
    ):
        raise SharedContractV2Error("bv-chain-provenance-mismatch", "BV does not bind exact CG, DG, and MC locators")
    obligations = _index(semantics["obligations"], "obligation_id", "obligations-invalid")
    campaigns = _index(bv.get("campaign_results"), "obligation_id", "bv-campaign-results-invalid")
    if set(campaigns) != set(obligations):
        raise SharedContractV2Error("bv-campaign-accounting-invalid", "BV campaign IDs differ from required obligations")
    inputs = _index(semantics["test_inputs"], "input_id", "semantics-inputs-invalid")
    components = _index(semantics["components"], "component_id", "components-invalid")
    nested_resolutions: list[dict[str, Any]] = []
    planned_work = 0
    executed_work = 0
    unsupported_work = 0
    attempted_families: set[str] = set()
    planned_governed_families: set[str] = set()
    executed_governed_families: set[str] = set()
    unsupported_governed_families: set[str] = set()
    all_attempt_ids: set[str] = set()
    for obligation_id, campaign in campaigns.items():
        dimensions = campaign.get("attempted_dimensions")
        expected_dimensions = _expected_bv_dimensions(obligations[obligation_id], semantics, profile_id=profile_id)
        if not isinstance(dimensions, list) or not dimensions:
            raise SharedContractV2Error("bv-empty-campaign", f"BV campaign has no attempted dimensions: {obligation_id}")
        if profile_id == "waf-bypass@3":
            _validate_bv_v3_dimensions(
                dimensions,
                obligations[obligation_id],
                semantics,
                obligation_id=obligation_id,
            )
            dimension_pairs = ((actual, None) for actual in dimensions)
        else:
            if len(dimensions) != len(expected_dimensions):
                raise SharedContractV2Error("bv-empty-campaign", f"BV campaign has no attempted dimensions: {obligation_id}")
            dimension_pairs = zip(dimensions, expected_dimensions, strict=True)
        planned_work += len(dimensions)
        supported_attempt_ids: list[str] = []
        expected_resolutions: list[tuple[dict[str, Any], dict[str, Any]]] = []
        for actual, expected in dimension_pairs:
            allowed = {
                "carrier",
                "transformation",
                "input_id",
                "component_id",
                "family",
                "supported",
                "detail",
                "attempt_id",
                "disposition",
            }
            if (
                not isinstance(actual, dict)
                or not set(actual) <= allowed
                or (
                    expected is not None
                    and any(actual.get(key) != value for key, value in expected.items())
                )
            ):
                raise SharedContractV2Error("bv-dimension-invalid", f"BV dimension is bogus or out of order: {obligation_id}")
            attempted_families.add(actual["transformation"])
            family = actual.get("family")
            if family is not None and (not isinstance(family, str) or not family):
                raise SharedContractV2Error(
                    "bv-dimension-invalid", f"BV governed family is invalid: {obligation_id}"
                )
            if isinstance(family, str):
                planned_governed_families.add(family)
            supported = actual.get("supported")
            if supported is True:
                if isinstance(family, str):
                    executed_governed_families.add(family)
                if not isinstance(actual.get("attempt_id"), str) or not actual["attempt_id"] or actual.get("disposition") not in {"blocked", "bypassed", "safety-stop"} or actual.get("detail") is not None:
                    raise SharedContractV2Error("bv-dimension-invalid", f"BV supported dimension evidence differs: {obligation_id}")
                if actual["disposition"] == "bypassed":
                    raise SharedContractV2Error(
                        "bv-translation-outcome-invalid",
                        f"BV no-bypass aggregate contains a bypassed dimension: {obligation_id}",
                    )
                supported_attempt_ids.append(actual["attempt_id"])
                item = inputs[actual["input_id"]]
                if item["input"].get("modality") == "http-request-template":
                    expected_resolutions.append((item, components[actual["component_id"]]))
            elif supported is False:
                if isinstance(family, str):
                    unsupported_governed_families.add(family)
                if actual.get("attempt_id") is not None or actual.get("disposition") is not None or not isinstance(actual.get("detail"), str) or not actual["detail"]:
                    raise SharedContractV2Error("bv-dimension-invalid", f"BV unsupported dimension evidence differs: {obligation_id}")
                unsupported_work += 1
            else:
                raise SharedContractV2Error("bv-dimension-invalid", f"BV dimension support state is absent: {obligation_id}")
        if campaign.get("attempt_refs") != supported_attempt_ids:
            raise SharedContractV2Error("bv-attempt-accounting-invalid", f"BV attempts do not bind dimensions: {obligation_id}")
        campaign_attempt_ids = set(supported_attempt_ids)
        if len(campaign_attempt_ids) != len(supported_attempt_ids) or campaign_attempt_ids & all_attempt_ids:
            raise SharedContractV2Error(
                "bv-attempt-accounting-invalid",
                f"BV attempt IDs are not globally unique: {obligation_id}",
            )
        all_attempt_ids.update(campaign_attempt_ids)
        executed_work += len(supported_attempt_ids)
        resolutions = campaign.get("resolution_refs")
        if not isinstance(resolutions, list) or len(resolutions) != len(expected_resolutions):
            raise SharedContractV2Error("bv-template-resolution-invalid", f"BV resolutions do not bind template attempts: {obligation_id}")
        for resolution, (item, component) in zip(resolutions, expected_resolutions, strict=True):
            _validate_bv_resolution(
                resolution,
                item=item,
                component=component,
                obligation_id=obligation_id,
                profile_id=profile_id,
                profile_digest=profile_digest,
            )
            nested_resolutions.append(resolution)
        if campaign.get("disposition") != "no-bypass":
            raise SharedContractV2Error(
                "bv-translation-outcome-invalid",
                f"BV required campaign must report no-bypass: {obligation_id}",
            )
        mapping = campaign.get("candidate_mapping")
        dg_mapping = next(item for item in locators["candidate_bundle"]["primary_candidate"]["obligation_mappings"] if item["obligation_id"] == obligation_id)
        if mapping != dg_mapping:
            raise SharedContractV2Error("bv-candidate-mapping-mismatch", f"BV candidate mapping differs: {obligation_id}")
    if bv.get("counterexamples") != [] or bv.get("feedback") != []:
        raise SharedContractV2Error(
            "bv-translation-outcome-invalid",
            "BV no-bypass aggregate cannot contain counterexamples or feedback",
        )
    counterexamples = _index(bv.get("counterexamples"), "attempt_id", "bv-counterexamples-invalid")
    feedback = bv.get("feedback")
    if not isinstance(feedback, list):
        raise SharedContractV2Error("bv-feedback-invalid", "BV feedback must be plural")
    feedback_refs = [item.get("counterexample_ref") for item in feedback if isinstance(item, dict)]
    if len(feedback_refs) != len(set(feedback_refs)) or set(feedback_refs) != set(counterexamples):
        raise SharedContractV2Error("bv-feedback-accounting-invalid", "BV feedback and counterexamples differ")
    for campaign in campaigns.values():
        refs = campaign["attempt_refs"]
        if campaign["disposition"] == "bypass-found" and not set(refs) & set(counterexamples):
            raise SharedContractV2Error("bv-counterexample-missing", "bypass-found campaign lacks a counterexample")
    unique_resolutions: list[dict[str, Any]] = []
    seen: set[bytes] = set()
    for resolution in nested_resolutions:
        key = canonical_bytes(resolution)
        if key not in seen:
            seen.add(key)
            unique_resolutions.append(resolution)
    if bv.get("resolutions") != unique_resolutions:
        raise SharedContractV2Error("bv-template-resolution-invalid", "BV top-level resolutions differ from campaign resolutions")
    disposed_work = executed_work + unsupported_work
    if disposed_work != planned_work:
        raise SharedContractV2Error(
            "bv-attempt-accounting-invalid",
            "BV planned dimensions contain a silent non-executed disposition",
        )
    search_bounds = bv.get("search_bounds")
    expected_attempted = sorted(attempted_families)
    if planned_governed_families:
        expected_attempted = sorted(executed_governed_families)
    if (
        not isinstance(search_bounds, dict)
        or search_bounds.get("attempt_budget") != planned_work
        or search_bounds.get("attempts_executed") != executed_work
        or search_bounds.get("variant_families_attempted") != expected_attempted
    ):
        raise SharedContractV2Error(
            "bv-attempt-accounting-invalid",
            "BV search bounds differ from authenticated campaign dimensions",
        )
    if planned_governed_families:
        enabled = ["baseline", "case-normalization", "encoding", "semantic-domain"]
        governed = {
            "variant_families_requested": enabled,
            "variant_families_enabled": enabled,
            "variant_families_planned": sorted(planned_governed_families),
            "variant_families_generated": sorted(executed_governed_families),
            "variant_families_executed": sorted(executed_governed_families),
            "variant_families_budget_skipped": [],
            "variant_families_unsupported": sorted(unsupported_governed_families),
            "variant_families_out_of_scope": sorted(
                set(enabled) - planned_governed_families
            ),
        }
        if any(search_bounds.get(key) != value for key, value in governed.items()):
            raise SharedContractV2Error(
                "bv-attempt-accounting-invalid",
                "BV governed family accounting differs from authenticated dimensions",
            )
    accounting = _accounting(
        semantics,
        required_work=planned_work,
        disposed_work=disposed_work,
    )
    if bv.get("accounting") != accounting.model_dump(mode="json"):
        raise SharedContractV2Error("bv-accounting-invalid", "BV CoverageAccounting differs")
    return accounting


@dataclass(frozen=True)
class VerifiedSharedContractV2:
    semantics: dict[str, Any]
    bundle: dict[str, Any]
    artifact_contents: dict[str, bytes]
    verification: PreTranslationVerification
    accounting: CoverageAccounting
    vulnerability_id: str
    profile_id: str


def verify_four_result_join(
    records: Mapping[str, UpstreamRecord],
    locators: Mapping[str, Any],
    *,
    catalog: OfflineSchemaCatalog | None = None,
    expected_profile_id: str = LEGACY_CT_PROFILE_ID,
) -> VerifiedSharedContractV2:
    required = {"check-generation", "defense-generation", "mitigation-check", "bypass-validation"}
    if set(records) != required or set(locators) != required:
        raise SharedContractV2Error("upstream-set-invalid", "v2 requires exactly four unique upstream inputs")
    documents = {name: _verify_locator(records[name], locators[name], capability=name) for name in required}
    correlation_ids = {locators[name].correlation_id for name in required}
    if len(correlation_ids) != 1:
        raise SharedContractV2Error("correlation-lineage-mismatch", "upstream correlation lineage differs")
    catalog = catalog or OfflineSchemaCatalog()
    semantics = _validate_cg(documents["check-generation"], catalog)
    dg = documents["defense-generation"]
    if dg.get("capability") != "defense-generation" or dg.get("contract_id") != "defense-generation-result@1.0" or dg.get("terminal_state") != "candidate-produced" or dg.get("status") != "completed":
        raise SharedContractV2Error("dg-identity-invalid", "DG identity or state differs")
    cg_bindings = [item for item in dg.get("upstream_result_refs", []) if isinstance(item, dict) and item.get("capability") == "check-generation"]
    if len(cg_bindings) != 1 or not _same_locator_document(cg_bindings[0], locators["check-generation"]):
        raise SharedContractV2Error("dg-cg-lineage-mismatch", "DG does not bind exact CG locator")
    bundle = dg.get("candidate_bundle")
    if not isinstance(bundle, dict):
        raise SharedContractV2Error("candidate-bundle-absent", "DG candidate_bundle is absent")
    attestation, contents = _validate_bundle(
        bundle,
        semantics,
        documents["check-generation"],
        records["check-generation"].payload_raw_result,
        dg,
        records["defense-generation"].artifact_raw_results,
        catalog,
    )
    lineage = {
        name: (documents[name].get("subject") or {}).get("vulnerability_id")
        for name in required
        if isinstance(documents[name].get("subject"), dict)
    }
    present = {value for value in lineage.values() if isinstance(value, str) and value}
    if len(present) > 1:
        raise SharedContractV2Error("vulnerability-lineage-mismatch", "upstream vulnerability lineage differs")
    mc_profile_id, mc_profile_digest, bv_profile_id, bv_profile_digest = _expected_profiles(expected_profile_id)
    _validate_mc(
        documents["mitigation-check"],
        semantics,
        bundle,
        locators,
        profile_id=mc_profile_id,
        profile_digest=mc_profile_digest,
    )
    bv_locators = dict(locators)
    bv_locators["candidate_bundle"] = bundle
    accounting = _validate_bv(
        documents["bypass-validation"],
        semantics,
        attestation,
        bv_locators,
        profile_id=bv_profile_id,
        profile_digest=bv_profile_digest,
    )
    count = len(semantics["obligations"])
    verification = PreTranslationVerification(
        all_required_obligations_have_dg_mapping=True,
        all_required_obligations_have_mc_disposition=True,
        all_required_obligations_have_required_bv_disposition=True,
        candidate_attestation_verified=True,
        source_member_partition_complete=True,
        lineage_verified=True,
        required_obligation_count=count,
        dg_mapping_count=count,
        mc_disposition_count=count,
        bv_campaign_count=count,
        unaccounted_required_obligation_count=0,
    )
    return VerifiedSharedContractV2(
        semantics,
        bundle,
        contents,
        verification,
        accounting,
        next(iter(present), "unknown"),
        expected_profile_id,
    )


def resolve_and_verify_four_result_join(
    request: SharedContractV2InvokeRequest,
    resolver: UpstreamResultResolver,
    *,
    cancellation_signal: CancellationSignal | None = None,
    catalog: OfflineSchemaCatalog | None = None,
) -> VerifiedSharedContractV2:
    """Fetch and verify the complete join before any model may be called."""

    records: dict[str, UpstreamRecord] = {}
    locators = {item.capability: item for item in request.upstream_inputs}
    for capability in (
        "check-generation",
        "defense-generation",
        "mitigation-check",
        "bypass-validation",
    ):
        check_cancelled(cancellation_signal)
        locator = locators[capability]
        try:
            record = resolver.fetch(
                locator.result_ref,
                immutable_locator=locator,
                cancellation_signal=cancellation_signal,
            )
        except (OperationCancelled, SharedContractV2Error):
            raise
        except UpstreamResolutionError as exc:
            raise SharedContractV2Error(
                "upstream-resolution-failed",
                str(exc),
            ) from exc
        except Exception as exc:
            raise UpstreamTransportError(
                f"{capability} result could not be fetched",
            ) from exc
        if record is None:
            raise SharedContractV2Error(
                "upstream-result-absent", f"{capability} result was not found"
            )
        records[capability] = record
    check_cancelled(cancellation_signal)
    return verify_four_result_join(
        records,
        locators,
        catalog=catalog,
        expected_profile_id=request.profile_id,
    )


class _FixedTranslationDoer:
    """Feeds a complete deterministic proposal into the established judge gates."""

    deterministic_proposal_source = "deterministic-shared-contract-v2"

    def __init__(self, proposal: TranslationProposal) -> None:
        self._proposal = proposal

    def propose(
        self,
        pattern: ProvenMitigationPattern,
        target_technology: str,
        artifact_type: str,
        snapshot: PolicySnapshot | None,
        translation_requirements: ProofLoopTranslationRequirements | None = None,
        cancellation_signal: CancellationSignal | None = None,
    ) -> TranslationProposal:
        del (
            pattern,
            target_technology,
            artifact_type,
            snapshot,
            translation_requirements,
            cancellation_signal,
        )
        return self._proposal


@dataclass(frozen=True)
class WafTranslationPlan:
    """Complete target construction, created atomically before translation gates."""

    doer: _FixedTranslationDoer
    target_artifacts: tuple[TargetTranslationArtifact, ...]
    translated_directives: tuple[TargetTranslationDirective, ...]
    translation_mappings: tuple[TranslationMapping, ...]
    discriminator_description: str
    pattern_summary: str
    primary_candidate_content: str


_CARRIER_CONDITION_TYPES = {
    "query": "uriQueryMatch",
    "header": "requestHeaderValueMatch",
    "cookie": "cookieMatch",
    "path": "pathMatch",
    "body": "argsPostMatch",
    "method": "requestMethodMatch",
}

_CARRIERS_REQUIRING_SELECTOR = frozenset({"header", "cookie"})


def _strict_object(raw: bytes, *, artifact_id: str) -> dict[str, Any]:
    return strict_json_bytes(raw, context=f"DG artifact {artifact_id}")


def _semantic_carrier(component: dict[str, Any]) -> tuple[str, str]:
    location = component.get("location")
    if not isinstance(location, dict):
        raise SharedContractV2Error("cannot-express", "component location is absent")
    kind = location.get("kind")
    if kind in {"http-query", "http-header", "http-cookie"}:
        name = location.get("name")
        if not isinstance(name, str) or not name:
            raise SharedContractV2Error("cannot-express", "named component selector is absent")
        return {
            "http-query": "query",
            "http-header": "header",
            "http-cookie": "cookie",
        }[kind], name
    if kind == "http-body-structured":
        selector_type = location.get("selector_type")
        if selector_type == "any-field":
            return "body", ""
        selector = location.get("selector")
        if not isinstance(selector, str) or not selector:
            raise SharedContractV2Error("cannot-express", "structured body selector is absent")
        return "body", selector
    if kind == "http-body-raw":
        return "body", ""
    if kind == "http-path":
        return "path", ""
    if kind == "http-method":
        return "method", ""
    raise SharedContractV2Error(
        "cannot-express", f"component location {kind!r} has no Akamai mapping"
    )


def _same_carrier_binding(
    actual: tuple[Any, Any], expected: tuple[str, str]
) -> bool:
    if actual[0] != expected[0] or not isinstance(actual[1], str):
        return False
    if actual[0] == "header":
        return actual[1].casefold() == expected[1].casefold()
    return actual[1] == expected[1]


def _component_condition(
    rule: dict[str, Any],
    *,
    component: dict[str, Any],
    source_artifact_id: str,
    seen_rule_ids: set[str],
) -> tuple[dict[str, Any], tuple[str, str, str]]:
    rule_id = rule.get("rule_id")
    carrier = rule.get("carrier")
    name = rule.get("name")
    component_id = rule.get("component_id")
    pattern = rule.get("pattern")
    flags = rule.get("flags")
    transformations = rule.get("transformations")
    expected_carrier, expected_name = _semantic_carrier(component)
    location = component["location"]
    carrier_binding_matches = _same_carrier_binding(
        (carrier, name), (expected_carrier, expected_name)
    ) or (
        location.get("kind") == "http-body-structured"
        and location.get("selector_type") == "any-field"
        and carrier == "body"
        and name == "*"
    )
    if (
        not isinstance(rule_id, str)
        or not rule_id
        or rule_id in seen_rule_ids
        or carrier not in _CARRIER_CONDITION_TYPES
        or not isinstance(name, str)
        or not carrier_binding_matches
        or not isinstance(component_id, str)
        or not component_id
        or not isinstance(pattern, str)
        or not pattern
        or not isinstance(flags, list)
        or any(flag not in {"i"} for flag in flags)
        or not isinstance(transformations, list)
        or any(not isinstance(item, str) or not item for item in transformations)
    ):
        raise SharedContractV2Error(
            "cannot-express",
            f"DG rule {rule_id!r} in {source_artifact_id} cannot map without semantic loss "
            f"(carrier={carrier!r}, name={name!r}, component={component_id!r}, "
            f"expected_carrier={expected_carrier!r}, expected_name={expected_name!r})",
        )
    seen_rule_ids.add(rule_id)
    location_kind = location["kind"]
    condition_type = _CARRIER_CONDITION_TYPES[carrier]
    if carrier == "header" and name == "*":
        condition_type = "requestHeaderMatch"
    if location_kind == "http-body-structured":
        condition_type = "argsPostJSONMatch"
    condition: dict[str, Any] = {
        "type": condition_type,
        "positiveMatch": True,
        "valueCase": "i" not in flags,
        "valueWildcard": False,
        "value": [pattern],
        "matchOperator": "regex",
        "sourceRuleId": rule_id,
        "sourceComponentId": component_id,
        "sourceCarrier": carrier,
        "sourceSelector": name,
        "sourceLocationKind": location_kind,
        "transformations": transformations,
    }
    if location.get("selector_type") is not None:
        condition["sourceSelectorType"] = location["selector_type"]
    if carrier == "header" and name != "*":
        condition["header"] = name
    elif carrier in {"query", "body"} and name and name != "*":
        condition["parameter"] = name
    elif carrier == "cookie" and name != "*":
        condition["cookieName"] = name
    return condition, (carrier, name, component_id)


def _source_input_route(item: dict[str, Any]) -> dict[str, str] | None:
    value = item.get("input")
    if not isinstance(value, dict):
        return None
    modality = value.get("modality")
    method = value.get("method")
    if modality == "http-request-template":
        path_key = value.get("path_key")
        if isinstance(method, str) and method and isinstance(path_key, str) and path_key:
            return {"kind": "opaque-path-key", "method": method, "path_key": path_key}
    elif modality == "http-request":
        path = value.get("path")
        if isinstance(method, str) and method and isinstance(path, str) and path:
            route = {"kind": "rendered-http-route", "method": method, "path": path}
            for key in ("scheme", "authority"):
                member = value.get(key)
                if isinstance(member, str) and member:
                    route[key] = member
            return route
    return None


def _profile_routes(profile_id: str) -> Mapping[str, Mapping[str, str]]:
    if profile_id == LEGACY_CT_PROFILE_ID:
        return {
            "inventory-item-detail": {
                "scheme": "https",
                "authority": "approved-mc-target.internal",
                "path": "/inventory/items/42",
            }
        }
    if profile_id != CT_PROFILE_ID:
        raise SharedContractV2Error("cannot-express", "unapproved route profile")
    raw = (BV_PROFILE_ROOT / "mc-http-route-profile-v2.json").read_bytes()
    if (
        len(raw) != MC_PROFILE_BYTE_LENGTH
        or "sha256:" + hashlib_sha256(raw).hexdigest() != MC_PROFILE_FILE_DIGEST
    ):
        raise SharedContractV2Error(
            "mc-profile-integrity-failed", "embedded route profile bytes differ"
        )
    profile = strict_json_bytes(raw, context="waf-standard@2 profile")
    if (
        profile.get("profile_id") != CT_PROFILE_ID
        or profile.get("resolver_id") != MC_RESOLVER_ID
        or digest(profile) != MC_RESOLVER_PROFILE_DIGEST
        or not isinstance(profile.get("routes"), dict)
    ):
        raise SharedContractV2Error(
            "mc-profile-integrity-failed", "embedded route profile identity differs"
        )
    return profile["routes"]


def _resolved_route_conditions(
    route: dict[str, Any],
    *,
    profile_id: str,
    alternative_id: str,
    path_payload: str | None = None,
) -> list[dict[str, Any]]:
    if route.get("kind") == "opaque-path-key":
        path_key = route.get("path_key")
        target = _profile_routes(profile_id).get(path_key)
        if not isinstance(target, Mapping):
            raise SharedContractV2Error(
                "cannot-express", f"route alternative {alternative_id} uses an unknown path_key"
            )
        path = target.get("path")
    elif route.get("kind") == "rendered-http-route":
        path = route.get("path")
    else:
        raise SharedContractV2Error(
            "cannot-express", f"route alternative {alternative_id} has an unknown route kind"
        )
    method = route.get("method")
    if not isinstance(path, str) or not path or not isinstance(method, str) or not method:
        raise SharedContractV2Error(
            "cannot-express", f"route alternative {alternative_id} is incomplete"
        )
    rendered_path = path
    if path_payload is not None:
        rendered_path = path.rstrip("/") + "/" + _path_segment_escape(path_payload)
    return [
        {
            "type": "pathMatch",
            "positiveMatch": True,
            "valueCase": True,
            "valueWildcard": False,
            "value": [rendered_path],
            "matchOperator": "exact",
            "sourceRoute": route,
        },
        {
            "type": "requestMethodMatch",
            "positiveMatch": True,
            "valueCase": True,
            "valueWildcard": False,
            "value": [method],
            "matchOperator": "exact",
            "sourceRoute": route,
        },
    ]


def _translate_rule_document(
    document: dict[str, Any],
    *,
    source_artifact_id: str,
    semantics: dict[str, Any],
    profile_id: str,
) -> tuple[list[tuple[str, dict[str, Any]]], list[tuple[str, str, str]]]:
    rules = document.get("rules")
    if not isinstance(rules, list) or not rules:
        raise SharedContractV2Error(
            "cannot-express",
            f"DG artifact {source_artifact_id} has no expressible WAF rules",
        )
    placement_mode = document.get("placement_mode")
    if placement_mode not in {None, "", "route-bound-v1"}:
        raise SharedContractV2Error(
            "cannot-express", f"DG artifact {source_artifact_id} uses an unknown placement mode"
        )
    route_alternatives = document.get("route_bound_alternatives")
    coverage_alternatives = document.get("coverage_alternatives")
    if not isinstance(coverage_alternatives, list) or not coverage_alternatives:
        raise SharedContractV2Error(
            "cannot-express", f"DG artifact {source_artifact_id} lacks Boolean alternatives"
        )
    if placement_mode == "route-bound-v1" and (
        not isinstance(route_alternatives, list) or not route_alternatives
    ):
        raise SharedContractV2Error(
            "cannot-express", f"DG artifact {source_artifact_id} lacks route-bound alternatives"
        )
    rules_by_component: dict[str, dict[str, Any]] = {}
    carrier_keys: list[tuple[str, str, str]] = []
    rule_ids: set[str] = set()
    semantic_components = _index(
        semantics["components"], "component_id", "components-invalid"
    )
    for rule in rules:
        if not isinstance(rule, dict):
            raise SharedContractV2Error(
                "cannot-express", f"DG artifact {source_artifact_id} has a malformed rule"
            )
        component_id = rule.get("component_id")
        if not isinstance(component_id, str) or not component_id or component_id in rules_by_component:
            raise SharedContractV2Error(
                "cannot-express",
                f"DG rule in {source_artifact_id} cannot map without semantic loss",
            )
        component = semantic_components.get(str(component_id))
        if component is None:
            raise SharedContractV2Error(
                "cannot-express", f"DG rule in {source_artifact_id} has no semantic component"
            )
        condition, carrier_key = _component_condition(
            rule,
            component=component,
            source_artifact_id=source_artifact_id,
            seen_rule_ids=rule_ids,
        )
        if carrier_key in carrier_keys:
            raise SharedContractV2Error(
                "cannot-express",
                f"DG artifact {source_artifact_id} repeats carrier binding "
                f"{carrier_key[0]}/{carrier_key[1]}",
            )
        carrier_keys.append(carrier_key)
        rules_by_component[component_id] = condition
    if placement_mode in {None, ""}:
        translated: list[tuple[str, dict[str, Any]]] = []
        seen_coverage: set[bytes] = set()
        for index, component_ids in enumerate(coverage_alternatives):
            key = canonical_bytes(component_ids)
            if (
                not isinstance(component_ids, list)
                or not component_ids
                or key in seen_coverage
                or any(component_id not in rules_by_component for component_id in component_ids)
            ):
                raise SharedContractV2Error(
                    "cannot-express", "DG endpoint-independent coverage alternative is invalid"
                )
            seen_coverage.add(key)
            translated.append(
                (
                    f"endpoint-independent:{index}",
                    {
                        "name": f"janus-{document.get('rule_set_id', source_artifact_id)}-{index}",
                        "description": "One endpoint-independent Boolean alternative from a verified DG WAF rule set.",
                        "operation": "AND",
                        "conditions": [deepcopy(rules_by_component[item]) for item in component_ids],
                        "sourceArtifactId": source_artifact_id,
                        "sourceRuleSetId": document.get("rule_set_id"),
                        "sourceAlternativeId": f"endpoint-independent:{index}",
                        "sourceAction": document.get("action"),
                        "fastLoopNegativeMaterials": document.get("fast_loop_negative_materials", []),
                    },
                )
            )
        return translated, carrier_keys
    semantic_inputs = _index(semantics["test_inputs"], "input_id", "semantics-inputs-invalid")
    coverage_keys = {canonical_bytes(item) for item in coverage_alternatives}
    represented_coverage: set[bytes] = set()
    translated: list[tuple[str, dict[str, Any]]] = []
    seen_alternatives: set[str] = set()
    for bound in route_alternatives:
        if not isinstance(bound, dict):
            raise SharedContractV2Error("cannot-express", "DG route alternative is malformed")
        alternative_id = bound.get("alternative_id")
        component_ids = bound.get("component_ids")
        route = bound.get("route")
        component_bindings = bound.get("component_bindings")
        if (
            not isinstance(alternative_id, str)
            or not alternative_id
            or alternative_id in seen_alternatives
            or not isinstance(component_ids, list)
            or not component_ids
            or canonical_bytes(component_ids) not in coverage_keys
            or not isinstance(route, dict)
            or not isinstance(component_bindings, list)
        ):
            raise SharedContractV2Error("cannot-express", "DG route alternative differs from coverage")
        seen_alternatives.add(alternative_id)
        represented_coverage.add(canonical_bytes(component_ids))
        bindings = _index(component_bindings, "component_id", "route-component-bindings-invalid")
        if set(bindings) != set(component_ids):
            raise SharedContractV2Error("cannot-express", "DG route component binding is incomplete")
        path_payloads: list[str] = []
        for component_id in component_ids:
            component = semantic_components.get(component_id)
            if component is None or component_id not in rules_by_component:
                raise SharedContractV2Error("cannot-express", "DG route alternative references an unknown component")
            expected_refs = [
                ref
                for ref in component["input_refs"]
                if ref.get("id") in semantic_inputs
                and _source_input_route(semantic_inputs[ref["id"]]) == route
            ]
            if bindings[component_id].get("input_refs") != expected_refs or not expected_refs:
                raise SharedContractV2Error("cannot-express", "DG route binding differs from authenticated CG inputs")
            if component["location"].get("kind") == "http-path":
                for ref in expected_refs:
                    payload = semantic_inputs[ref["id"]]["input"].get("path_payload")
                    if route.get("kind") == "opaque-path-key" and (
                        not isinstance(payload, str) or not payload
                    ):
                        raise SharedContractV2Error(
                            "cannot-express",
                            "template path component has no exact authenticated path_payload",
                        )
                    if isinstance(payload, str) and payload not in path_payloads:
                        path_payloads.append(payload)
        variants: list[str | None] = path_payloads or [None]
        for variant_index, path_payload in enumerate(variants):
            route_conditions = _resolved_route_conditions(
                route,
                profile_id=profile_id,
                alternative_id=alternative_id,
                path_payload=path_payload,
            )
            component_conditions = [
                deepcopy(rules_by_component[component_id])
                for component_id in component_ids
                if semantic_components[component_id]["location"].get("kind") != "http-path"
            ]
            path_components = [
                component_id
                for component_id in component_ids
                if semantic_components[component_id]["location"].get("kind") == "http-path"
            ]
            if path_components:
                route_conditions[0]["sourcePathComponents"] = [
                    deepcopy(rules_by_component[component_id])
                    for component_id in path_components
                ]
            translated_id = (
                alternative_id
                if len(variants) == 1
                else f"{alternative_id}:path-payload:{variant_index}"
            )
            translated.append(
                (
                    translated_id,
                    {
                        "name": f"janus-{document.get('rule_set_id', source_artifact_id)}-{len(translated)}",
                        "description": "One route-bound Boolean alternative from a verified DG WAF rule set.",
                        "operation": "AND",
                        "conditions": route_conditions + component_conditions,
                        "sourceArtifactId": source_artifact_id,
                        "sourceRuleSetId": document.get("rule_set_id"),
                        "sourceAlternativeId": alternative_id,
                        "sourceAction": document.get("action"),
                        "fastLoopNegativeMaterials": document.get("fast_loop_negative_materials", []),
                    },
                )
            )
    if represented_coverage != coverage_keys:
        raise SharedContractV2Error("cannot-express", "DG route alternatives do not cover every Boolean alternative")
    return translated, carrier_keys


def _translate_carrier_document(
    document: dict[str, Any],
    *,
    source_artifact_id: str,
    semantics: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], list[tuple[str, str, str]]]:
    bindings = document.get("carrier_bindings")
    if not isinstance(bindings, list) or not bindings:
        raise SharedContractV2Error(
            "cannot-express",
            f"DG artifact {source_artifact_id} has no expressible carrier bindings",
        )
    translated: list[dict[str, Any]] = []
    carrier_keys: list[tuple[str, str, str]] = []
    semantic_components = (
        _index(semantics["components"], "component_id", "components-invalid")
        if semantics is not None
        else None
    )
    for binding in bindings:
        if not isinstance(binding, dict):
            raise SharedContractV2Error(
                "cannot-express", f"DG artifact {source_artifact_id} has a malformed carrier binding"
            )
        carrier = binding.get("carrier")
        name = binding.get("name")
        component_id = binding.get("component_id")
        expected = (
            _semantic_carrier(semantic_components[component_id])
            if semantic_components is not None and component_id in semantic_components
            else None
        )
        component = (
            semantic_components.get(component_id)
            if semantic_components is not None and isinstance(component_id, str)
            else None
        )
        any_field_binding = (
            isinstance(component, dict)
            and component.get("location", {}).get("kind") == "http-body-structured"
            and component.get("location", {}).get("selector_type") == "any-field"
            and carrier == "body"
            and name == "*"
        )
        if (
            carrier not in _CARRIER_CONDITION_TYPES
            or not isinstance(name, str)
            or not isinstance(component_id, str)
            or not component_id
            or (
                expected is not None
                and not _same_carrier_binding((carrier, name), expected)
                and not any_field_binding
            )
            or (expected is None and carrier in _CARRIERS_REQUIRING_SELECTOR and not name)
        ):
            raise SharedContractV2Error(
                "cannot-express",
                f"DG carrier binding in {source_artifact_id} cannot map without semantic loss",
            )
        key = (carrier, name, component_id)
        if key in carrier_keys:
            raise SharedContractV2Error(
                "cannot-express",
                f"DG artifact {source_artifact_id} repeats carrier binding {carrier}/{name}",
            )
        carrier_keys.append(key)
        translated.append(
            {
                "carrier": carrier,
                "selector": name,
                "sourceComponentId": component_id,
                "targetConditionType": _CARRIER_CONDITION_TYPES[carrier],
            }
        )
    return (
        {
            "configurationType": "akamai-carrier-bindings",
            "sourceArtifactId": source_artifact_id,
            "sourceRuleSetId": document.get("rule_set_id"),
            "carrierBindings": translated,
            "claimRule": document.get("claim_rule"),
        },
        carrier_keys,
    )


def build_waf_translation_plan(
    verified: VerifiedSharedContractV2,
    *,
    target_technology: str,
) -> WafTranslationPlan:
    """Translate every cooperating DG artifact or fail without partial output."""

    if target_technology != "akamai-waf":
        raise SharedContractV2Error(
            "cannot-express",
            f"shared WAF profile cannot map to target technology {target_technology}",
        )
    candidate = verified.bundle["primary_candidate"]
    source_artifacts = _index(
        candidate["artifacts"], "artifact_id", "candidate-artifacts-invalid"
    )
    source_to_target: dict[str, list[str]] = {}
    rule_documents: list[dict[str, Any]] = []
    rule_carriers: set[tuple[str, str, str]] = set()
    binding_carriers: set[tuple[str, str, str]] = set()
    for source in sorted(source_artifacts.values(), key=lambda item: item["order"]):
        source_id = source["artifact_id"]
        document = _strict_object(
            verified.artifact_contents[source_id], artifact_id=source_id
        )
        if "rules" in document:
            translated_rules, carriers = _translate_rule_document(
                document,
                source_artifact_id=source_id,
                semantics=verified.semantics,
                profile_id=verified.profile_id,
            )
            rule_carriers.update(carriers)
            for _, translated in translated_rules:
                rule_documents.append(translated)
        elif "carrier_bindings" in document:
            _, carriers = _translate_carrier_document(
                document,
                source_artifact_id=source_id,
                semantics=verified.semantics,
            )
            binding_carriers.update(carriers)
        else:
            raise SharedContractV2Error(
                "cannot-express",
                f"DG artifact {source_id} has no lossless Akamai mapping",
            )
    if not rule_documents or binding_carriers != rule_carriers:
        raise SharedContractV2Error(
            "cannot-express",
            "complete DG carrier bindings do not exactly match executable WAF rule carriers",
        )
    from control_translation.adapters.akamai_waf import AkamaiWafAdapter

    syntax_adapter = AkamaiWafAdapter()
    for index, rule_document in enumerate(rule_documents):
        syntax = syntax_adapter.validate_syntax(
            canonical_bytes(rule_document).decode("utf-8")
        )
        if not syntax.valid:
            raise SharedContractV2Error(
                "cannot-express",
                f"translated Akamai rule {index} is invalid: {'; '.join(syntax.errors)}",
            )
    primary_candidate_content = canonical_bytes({"rules": rule_documents}).decode(
        "utf-8"
    )
    primary_content_hash = "sha256:" + hashlib_sha256(
        primary_candidate_content.encode()
    ).hexdigest()
    primary_artifact_id = shared_waf_primary_artifact_id(primary_content_hash)
    source_to_target = {
        source_id: [primary_artifact_id] for source_id in source_artifacts
    }
    proposal = TranslationProposal(
        candidate_content=primary_candidate_content,
        translation_label="equivalent",
        justification="Every verified DG Boolean alternative, carrier, selector, pattern, and ordered transformation is preserved without fixture route narrowing.",
        translation_assumptions=[],
        limitations=list(candidate.get("limitations", [])),
    )
    directives = _index(
        candidate["directives"], "directive_id", "candidate-directives-invalid"
    )
    translated_directives: list[TargetTranslationDirective] = []
    for directive in candidate["directives"]:
        source_ref = directive.get("artifact_ref")
        source_id = source_ref.get("id") if isinstance(source_ref, dict) else None
        if source_id not in source_to_target:
            raise SharedContractV2Error(
                "cannot-express",
                f"DG directive {directive['directive_id']} does not map to an emitted artifact",
            )
        for index, target_id in enumerate(source_to_target[source_id]):
            translated_directives.append(
                TargetTranslationDirective(
                    directive_id=f"akamai-{directive['directive_id']}-{index}",
                    source_directive_id=directive["directive_id"],
                    target_artifact_id=target_id,
                    kind=directive["kind"],
                    value=directive["value"],
                    required=directive["required"],
                )
            )
    mappings: list[TranslationMapping] = []
    for mapping in candidate["obligation_mappings"]:
        source_ids = _ref_ids(
            mapping["artifact_refs"],
            kind="artifact",
            scope=verified.bundle["bundle_id"],
            known=source_artifacts,
            code="obligation-artifacts-invalid",
        )
        _ref_ids(
            mapping["directive_refs"],
            kind="directive",
            scope=verified.bundle["bundle_id"],
            known=directives,
            code="obligation-directives-invalid",
            allow_empty=True,
        )
        mapped_target_ids = list(
            dict.fromkeys(
                target_id
                for item in source_ids
                for target_id in source_to_target[item]
            )
        )
        if not mapped_target_ids:
            raise SharedContractV2Error(
                "cannot-express",
                f"obligation {mapping['obligation_id']} has no applicable target alternative",
            )
        mappings.append(
            TranslationMapping(
                obligation_id=mapping["obligation_id"],
                target_artifact_ids=mapped_target_ids,
            )
        )
    required_ids = {
        item["obligation_id"] for item in verified.semantics["obligations"]
    }
    if {item.obligation_id for item in mappings} != required_ids:
        raise SharedContractV2Error(
            "cannot-express", "not every required obligation has one target mapping"
        )
    descriptions = [
        item.get("description", "") for item in verified.semantics["components"]
    ]
    return WafTranslationPlan(
        doer=_FixedTranslationDoer(proposal),
        target_artifacts=(),
        translated_directives=tuple(translated_directives),
        translation_mappings=tuple(mappings),
        discriminator_description="WAF regex matching across query, header, cookie, path, body, and method carriers: "
        + "; ".join(item for item in descriptions if item),
        pattern_summary=canonical_bytes(
            {
                "candidate_bundle_id": verified.bundle["bundle_id"],
                "candidate_id": candidate["candidate_id"],
                "source_artifact_ids": list(source_to_target),
            }
        ).decode("utf-8"),
        primary_candidate_content=primary_candidate_content,
    )
