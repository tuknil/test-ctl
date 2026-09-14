"""Offline verification and WAF-first translation for shared contracts v2.

The v2 path is deliberately isolated from the retained three-result path. It
accepts only authenticated immutable CG, DG, MC, and BV records, verifies the
complete join before translation, and never performs network schema lookup.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from hashlib import sha256 as hashlib_sha256
from pathlib import Path
from typing import Any
from urllib.parse import unquote

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
)
from control_translation.policy_reader.base import PolicySnapshot
from control_translation.upstream import (
    UpstreamRecord,
    UpstreamResolutionError,
    UpstreamResultResolver,
    UpstreamTransportError,
)

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
    "sha256:fbc8e62217c6ff269458f16c55b690ff0341cd3a6e4eaca92336532ca001f828"
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
BV_PROFILE_FILE_DIGEST = "sha256:ca9e037080199f3a58958aa324484953d39e9c73e904c77ea6305692024900cb"
BV_PROFILE_BYTE_LENGTH = 3861
BV_RESOLVER_PROFILE_DIGEST = "sha256:eb15d48ba11ecf93d26c8ae1b0f08bb1754edf0afef1c0401f1bf897ac8771af"


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
        if document.get("contract_type") != "check-generation-persisted-result" or document.get("contract_version") != "1.0":
            raise SharedContractV2Error("cg-wrapper-identity-invalid", "expected check-generation-persisted-result@1.0")
        raw_context = document.get("temporal_context")
        raw_run_result = document.get("run_result")
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
        if document.get("temporal_result_content_sha256") != locator.content_sha256:
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
    if set(members) != set(outer_members) or set(members) != set(membership) or set(artifacts) != set(outer_artifacts) or set(inputs) != set(outer_inputs):
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
    for item in semantics["unsupported_dimensions"]:
        unsupported.update(_ref_ids(item["source_member_refs"], kind="source-member", scope=semantics["semantics_id"], known=members, code="unsupported-members-invalid", allow_empty=True))
    if represented & unsupported or represented | unsupported != set(members):
        raise SharedContractV2Error("source-member-partition-incomplete", "represented and unsupported source members are not a complete disjoint partition")
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
    if strict_json_bytes(exact_cg, context="bound CG result") != cg:
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


def _accounting(semantics: dict[str, Any], *, work: int) -> CoverageAccounting:
    members = {item["member_id"] for item in semantics["source_binding"]["members"]}
    represented = {ref["id"] for item in semantics["test_inputs"] for ref in item["source_member_refs"]}
    unsupported = {ref["id"] for item in semantics["unsupported_dimensions"] for ref in item["source_member_refs"]}
    if represented & unsupported or represented | unsupported != members:
        raise SharedContractV2Error("source-member-partition-incomplete", "source member partition differs")
    count = len(semantics["obligations"])
    return CoverageAccounting(
        required_obligation_count=count,
        accounted_obligation_count=count,
        unaccounted_required_obligation_count=0,
        source_member_count=len(members),
        represented_source_member_count=len(represented),
        unsupported_source_member_count=len(unsupported),
        unaccounted_source_member_count=0,
        required_work_item_count=work,
        disposed_work_item_count=work,
        unaccounted_required_work_item_count=0,
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
    rendered.update(
        modality="http-request",
        scheme=route["scheme"],
        authority=route["authority"],
        path=route["path"],
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
    if not isinstance(provenance, dict) or provenance.get("route_policy") != "shared-attack-contracts-v2" or provenance.get("verification") != "physical-and-logical-sha256-verified":
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
    if mc.get("accounting") != _accounting(semantics, work=work).model_dump(mode="json"):
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
            labels: list[str] = []
            transformations = component["transformations"]
            if transformations:
                labels.append("cg:" + ":".join(step["operation"] for step in transformations))
            for index, chain in enumerate(profile["bypass_dimensions"].get(carrier, [])):
                labels.append(f"bv:{carrier}:{index}:" + ":".join(step["operation"] for step in chain))
            if not labels:
                expected.append({
                    "carrier": carrier,
                    "transformation": "baseline:identity",
                    "input_id": input_id,
                    "component_id": component_id,
                })
            else:
                expected.extend({
                    "carrier": carrier,
                    "transformation": label,
                    "input_id": input_id,
                    "component_id": component_id,
                } for label in labels)
    return expected


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
    if not isinstance(rendered, dict) or set(rendered) != set(expected_rendered):
        raise SharedContractV2Error("bv-template-resolution-invalid", f"BV rendered request shape differs: {obligation_id}")
    mutable_field = {
        "http-query": "query", "http-header": "headers", "http-cookie": "cookies",
        "http-method": "method", "http-path": "path", "http-body-raw": "body",
        "http-body-structured": "body",
    }.get(component["location"].get("kind"))
    if mutable_field is None or any(
        rendered[key] != value for key, value in expected_rendered.items() if key != mutable_field
    ):
        raise SharedContractV2Error("bv-template-resolution-invalid", f"BV changed a nonselected template field: {obligation_id}")


def _validate_bv(bv: dict[str, Any], semantics: dict[str, Any], attestation: dict[str, Any], locators: Mapping[str, Any], *, profile_id: str, profile_digest: str) -> None:
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
    for obligation_id, campaign in campaigns.items():
        dimensions = campaign.get("attempted_dimensions")
        expected_dimensions = _expected_bv_dimensions(obligations[obligation_id], semantics, profile_id=profile_id)
        if not isinstance(dimensions, list) or len(dimensions) != len(expected_dimensions):
            raise SharedContractV2Error("bv-empty-campaign", f"BV campaign has no attempted dimensions: {obligation_id}")
        supported_attempt_ids: list[str] = []
        expected_resolutions: list[tuple[dict[str, Any], dict[str, Any]]] = []
        for actual, expected in zip(dimensions, expected_dimensions, strict=True):
            allowed = {"carrier", "transformation", "input_id", "component_id", "supported", "detail", "attempt_id", "disposition"}
            if not isinstance(actual, dict) or not set(actual) <= allowed or any(actual.get(key) != value for key, value in expected.items()):
                raise SharedContractV2Error("bv-dimension-invalid", f"BV dimension is bogus or out of order: {obligation_id}")
            supported = actual.get("supported")
            if supported is True:
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
                if actual.get("attempt_id") is not None or actual.get("disposition") is not None or not isinstance(actual.get("detail"), str) or not actual["detail"]:
                    raise SharedContractV2Error("bv-dimension-invalid", f"BV unsupported dimension evidence differs: {obligation_id}")
            else:
                raise SharedContractV2Error("bv-dimension-invalid", f"BV dimension support state is absent: {obligation_id}")
        if campaign.get("attempt_refs") != supported_attempt_ids:
            raise SharedContractV2Error("bv-attempt-accounting-invalid", f"BV attempts do not bind dimensions: {obligation_id}")
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
    if bv.get("accounting") != _accounting(semantics, work=len(obligations)).model_dump(mode="json"):
        raise SharedContractV2Error("bv-accounting-invalid", "BV CoverageAccounting differs")


@dataclass(frozen=True)
class VerifiedSharedContractV2:
    semantics: dict[str, Any]
    bundle: dict[str, Any]
    artifact_contents: dict[str, bytes]
    verification: PreTranslationVerification
    accounting: CoverageAccounting
    vulnerability_id: str


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
    _validate_bv(
        documents["bypass-validation"],
        semantics,
        attestation,
        bv_locators,
        profile_id=bv_profile_id,
        profile_digest=bv_profile_digest,
    )
    count = len(semantics["obligations"])
    accounting = _accounting(semantics, work=count)
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


_CARRIER_CONDITION_TYPES = {
    "query": "uriQueryMatch",
    "header": "requestHeaderValueMatch",
    "cookie": "cookieMatch",
    "path": "pathMatch",
    "body": "argsPostMatch",
    "method": "requestMethodMatch",
}

_CARRIERS_REQUIRING_SELECTOR = frozenset({"header", "cookie"})


def _target_artifact_id(source_artifact_id: str) -> str:
    safe = "".join(
        character if character.isalnum() or character in "-_." else "-"
        for character in source_artifact_id
    ).strip("-")
    if not safe:
        raise SharedContractV2Error(
            "cannot-express", "source artifact identity cannot map to a target identity"
        )
    return f"akamai-{safe}"


def _strict_object(raw: bytes, *, artifact_id: str) -> dict[str, Any]:
    return strict_json_bytes(raw, context=f"DG artifact {artifact_id}")


def _translate_rule_document(
    document: dict[str, Any], *, source_artifact_id: str
) -> tuple[dict[str, Any], list[tuple[str, str, str]]]:
    rules = document.get("rules")
    if not isinstance(rules, list) or not rules:
        raise SharedContractV2Error(
            "cannot-express",
            f"DG artifact {source_artifact_id} has no expressible WAF rules",
        )
    conditions: list[dict[str, Any]] = []
    carrier_keys: list[tuple[str, str, str]] = []
    rule_ids: set[str] = set()
    for rule in rules:
        if not isinstance(rule, dict):
            raise SharedContractV2Error(
                "cannot-express", f"DG artifact {source_artifact_id} has a malformed rule"
            )
        rule_id = rule.get("rule_id")
        carrier = rule.get("carrier")
        name = rule.get("name")
        component_id = rule.get("component_id")
        pattern = rule.get("pattern")
        flags = rule.get("flags")
        transformations = rule.get("transformations")
        if (
            not isinstance(rule_id, str)
            or not rule_id
            or rule_id in rule_ids
            or carrier not in _CARRIER_CONDITION_TYPES
            or not isinstance(name, str)
            or (carrier in _CARRIERS_REQUIRING_SELECTOR and not name)
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
                f"DG rule in {source_artifact_id} cannot map without semantic loss",
            )
        rule_ids.add(rule_id)
        carrier_key = (carrier, name, component_id)
        if carrier_key in carrier_keys:
            raise SharedContractV2Error(
                "cannot-express",
                f"DG artifact {source_artifact_id} repeats carrier binding {carrier}/{name}",
            )
        carrier_keys.append(carrier_key)
        condition: dict[str, Any] = {
            "type": _CARRIER_CONDITION_TYPES[carrier],
            "positiveMatch": True,
            "valueCase": "i" not in flags,
            "valueWildcard": False,
            "value": [pattern],
            "matchOperator": "regex",
            "sourceRuleId": rule_id,
            "sourceComponentId": component_id,
            "sourceCarrier": carrier,
            "sourceSelector": name,
            "transformations": transformations,
        }
        if carrier == "header":
            condition["header"] = name
        elif carrier in {"query", "body"} and name:
            condition["parameter"] = name
        elif carrier == "cookie":
            condition["cookieName"] = name
        conditions.append(condition)
    return (
        {
            "name": f"janus-{document.get('rule_set_id', source_artifact_id)}",
            "description": "Complete deterministic translation of a verified DG WAF rule artifact.",
            "operation": "OR",
            "conditions": conditions,
            "sourceArtifactId": source_artifact_id,
            "sourceRuleSetId": document.get("rule_set_id"),
            "sourceAction": document.get("action"),
            "fastLoopNegativeMaterials": document.get(
                "fast_loop_negative_materials", []
            ),
        },
        carrier_keys,
    )


def _translate_carrier_document(
    document: dict[str, Any], *, source_artifact_id: str
) -> tuple[dict[str, Any], list[tuple[str, str, str]]]:
    bindings = document.get("carrier_bindings")
    if not isinstance(bindings, list) or not bindings:
        raise SharedContractV2Error(
            "cannot-express",
            f"DG artifact {source_artifact_id} has no expressible carrier bindings",
        )
    translated: list[dict[str, Any]] = []
    carrier_keys: list[tuple[str, str, str]] = []
    for binding in bindings:
        if not isinstance(binding, dict):
            raise SharedContractV2Error(
                "cannot-express", f"DG artifact {source_artifact_id} has a malformed carrier binding"
            )
        carrier = binding.get("carrier")
        name = binding.get("name")
        component_id = binding.get("component_id")
        if (
            carrier not in _CARRIER_CONDITION_TYPES
            or not isinstance(name, str)
            or (carrier in _CARRIERS_REQUIRING_SELECTOR and not name)
            or not isinstance(component_id, str)
            or not component_id
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
    source_to_target: dict[str, str] = {}
    target_artifacts: list[TargetTranslationArtifact] = []
    rule_documents: list[dict[str, Any]] = []
    rule_carriers: set[tuple[str, str, str]] = set()
    binding_carriers: set[tuple[str, str, str]] = set()
    for source in sorted(source_artifacts.values(), key=lambda item: item["order"]):
        source_id = source["artifact_id"]
        document = _strict_object(
            verified.artifact_contents[source_id], artifact_id=source_id
        )
        if "rules" in document:
            translated, carriers = _translate_rule_document(
                document, source_artifact_id=source_id
            )
            artifact_type = "akamai-waf-rule"
            rule_documents.append(translated)
            rule_carriers.update(carriers)
        elif "carrier_bindings" in document:
            translated, carriers = _translate_carrier_document(
                document, source_artifact_id=source_id
            )
            artifact_type = "akamai-waf-carrier-configuration"
            binding_carriers.update(carriers)
        else:
            raise SharedContractV2Error(
                "cannot-express",
                f"DG artifact {source_id} has no lossless Akamai mapping",
            )
        content = canonical_bytes(translated).decode("utf-8")
        target_id = _target_artifact_id(source_id)
        source_to_target[source_id] = target_id
        target_artifacts.append(
            TargetTranslationArtifact(
                artifact_id=target_id,
                source_artifact_id=source_id,
                role=source["role"],
                kind=source["kind"],
                order=source["order"],
                artifact_type=artifact_type,
                content=content,
                content_hash="sha256:" + hashlib_sha256(content.encode()).hexdigest(),
            )
        )
    if not rule_documents or binding_carriers != rule_carriers:
        raise SharedContractV2Error(
            "cannot-express",
            "complete DG carrier bindings do not exactly match executable WAF rule carriers",
        )
    combined_conditions = [
        condition
        for document in rule_documents
        for condition in document["conditions"]
    ]
    proposal_content = (
        rule_documents[0]
        if len(rule_documents) == 1
        else {
            "name": f"janus-{candidate['candidate_id']}",
            "description": candidate["intent"],
            "operation": "OR",
            "conditions": combined_conditions,
            "sourceCandidateId": candidate["candidate_id"],
            "sourceArtifactIds": list(source_to_target),
        }
    )
    proposal = TranslationProposal(
        candidate_content=canonical_bytes(proposal_content).decode("utf-8"),
        translation_label="exact",
        justification="Every verified DG WAF rule, carrier, selector, and pattern is preserved.",
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
        translated_directives.append(
            TargetTranslationDirective(
                directive_id=f"akamai-{directive['directive_id']}",
                source_directive_id=directive["directive_id"],
                target_artifact_id=source_to_target[source_id],
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
        mappings.append(
            TranslationMapping(
                obligation_id=mapping["obligation_id"],
                target_artifact_ids=[source_to_target[item] for item in source_ids],
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
        target_artifacts=tuple(target_artifacts),
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
    )
