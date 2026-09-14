from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from threading import Event
from typing import Any

import pytest
import rfc8785
from fastapi import HTTPException
from pydantic import TypeAdapter, ValidationError

from control_translation import api as api_module
from control_translation import capability
from control_translation.config import Settings, get_settings
from control_translation.contracts import (
    ControlTranslationResult,
    InvokeAPIRequest,
    ResultEnvelope,
    SharedContractV2InvokeRequest,
)
from control_translation.lifecycle import LifecycleWorker, build_lifecycle_result
from control_translation.persistence import (
    SplitRunRepository,
    SQLiteRunRepository,
    canonical_request_hash,
    canonical_result_bytes,
    normalized_request_digest,
)
from control_translation.policy_reader.base import PolicySnapshot
from control_translation.shared_contracts_v2 import (
    OfflineSchemaCatalog,
    SharedContractV2Error,
    _expected_bv_dimensions,
    _validate_cg,
    _validate_mc,
    build_waf_translation_plan,
    canonical_bytes,
    digest,
    digest_without,
    resolve_and_verify_four_result_join,
    strict_json_bytes,
    verify_four_result_join,
)
from control_translation.upstream import (
    UpstreamRecord,
    UpstreamResolutionError,
    UpstreamTransportError,
)
from control_translation.upstream_databricks import DatabricksUpstreamResultResolver

FIXTURES = Path(__file__).parent / "fixtures" / "shared-attack-contracts-v2"
CREATED_AT = "2026-09-11T12:30:00Z"
CORRELATION_ID = "correlation-shared-contracts-v2-42"


def _load(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / name).read_bytes())


def _reference(capability: str, result_id: str) -> dict[str, str]:
    coordinates = {
        "check-generation": ("check_generation", "check_generation_results"),
        "defense-generation": ("defense_generation", "defense_generation_results"),
        "mitigation-check": ("mitigation-check", "mitigation_check"),
        "bypass-validation": ("bypass_validation", "bypass_validation_results"),
    }
    schema, table = coordinates[capability]
    return {
        "system": "databricks",
        "catalog": "36889_janus_dev",
        "schema": schema,
        "table": table,
        "key": result_id,
    }


def _signed(document: dict[str, Any]) -> tuple[dict[str, Any], bytes]:
    unsigned = {
        key: value
        for key, value in document.items()
        if key not in {"content_sha256", "size_bytes"}
    }
    raw = canonical_bytes(unsigned)
    return {
        **unsigned,
        "content_sha256": f"sha256:{sha256(raw).hexdigest()}",
        "size_bytes": len(raw),
    }, raw


def _locator(
    capability: str,
    *,
    contract_id: str,
    state: str,
    run_id: str,
    result_id: str,
    request_id: str,
    content_sha256: str,
    size_bytes: int,
) -> dict[str, Any]:
    return {
        "capability": capability,
        "contract_id": contract_id,
        "run_id": run_id,
        "result_id": result_id,
        "terminal_state": state,
        "status": "completed",
        "request_id": request_id,
        "correlation_id": CORRELATION_ID,
        "result_ref": _reference(capability, result_id),
        "evidence_refs": [],
        "content_sha256": content_sha256,
        "size_bytes": size_bytes,
        "created_at": CREATED_AT,
    }


def _chain(*, current_profiles: bool = False) -> tuple[SharedContractV2InvokeRequest, dict[str, UpstreamRecord]]:
    cg_raw = (FIXTURES / "check-generation-complete-result.json").read_bytes()
    cg = strict_json_bytes(cg_raw, context="CG fixture")
    cg_run_id = "check-generation-run:CVE-2026-0042:7"
    cg_result_id = f"check-generation-result:{cg_run_id}"
    cg_request_id = "check-generation-request:CVE-2026-0042:7"
    upstream_ref = {
        "capability": "vulnerability-research",
        "contract_id": "vulnerability-research-result@1.0",
        "run_id": "vr-run-42",
        "result_id": "vulnerability-research-result:42",
        "terminal_state": "signal-found",
        "status": "completed",
        "result_ref": {
            "system": "databricks",
            "catalog": "36889_janus_dev",
            "schema": "vuln_research",
            "table": "vulnerability_research_results",
            "key": "vulnerability-research-result:42",
        },
        "evidence_refs": [],
        "subject_record_revision_id": "subject-revision-42",
        "characterization_revision_id": "characterization-revision-42",
        "content_sha256": "sha256:" + "1" * 64,
        "size_bytes": 1,
        "created_at": CREATED_AT,
    }
    temporal_context = {
        "request_id": cg_request_id,
        "correlation_id": CORRELATION_ID,
        "upstream_result_refs": [upstream_ref],
        "inherited_evidence_refs": [],
        "new_evidence_refs": [],
        "result_created_at": CREATED_AT,
    }
    temporal_core = {
        "capability": "check-generation",
        "contract_id": "check-generation-result@1.0",
        "result_id": cg_result_id,
        "run_id": cg_run_id,
        "request_id": cg_request_id,
        "correlation_id": CORRELATION_ID,
        "terminal_state": "completed",
        "status": "completed",
        "upstream_result_refs": [upstream_ref],
        "evidence_refs": [],
        "subject_record_revision_id": "subject-revision-42",
        "characterization_revision_id": "characterization-revision-42",
        "run_result": cg,
        "created_at": CREATED_AT,
    }
    cg_preimage = canonical_bytes(temporal_core)
    cg_hash = f"sha256:{sha256(cg_preimage).hexdigest()}"
    cg_wrapper = {
        "contract_type": "check-generation-persisted-result",
        "contract_version": "1.0",
        "result_id": cg_result_id,
        "diagnostic_run": False,
        "run_result": cg,
        "operational_snapshot": {},
        "temporal_context": temporal_context,
        "temporal_result_content_sha256": cg_hash,
        "history_summary": {},
    }
    cg_locator = _locator(
        "check-generation",
        contract_id="check-generation@2.1",
        state="completed",
        run_id=cg_run_id,
        result_id=cg_result_id,
        request_id=cg_request_id,
        content_sha256=cg_hash,
        size_bytes=len(cg_preimage),
    )

    bundle = _load("candidate-bundle.json")
    dg_result_id = "defense-generation-result:shared-42"
    dg_document = {
        "capability": "defense-generation",
        "contract_id": "defense-generation-result@1.0",
        "request_id": "defense-generation-request:shared-42",
        "correlation_id": CORRELATION_ID,
        "run_id": "defense-generation-run:shared-42",
        "result_id": dg_result_id,
        "status": "completed",
        "terminal_state": "candidate-produced",
        "result_ref": _reference("defense-generation", dg_result_id),
        "evidence_refs": [],
        "outcome_reason": {
            "code": "candidate-produced",
            "detail": "Complete shared-contract WAF candidate produced.",
        },
        "subject": {"vulnerability_id": "CVE-2026-0042"},
        "upstream_result_refs": [cg_locator],
        "candidate_bundle": bundle,
        "candidate_artifact_contents": {
            "artifact-main": _load("waf-rule-main.json"),
            "artifact-carriers": _load("waf-rule-carriers.json"),
        },
        "attempt_history": [],
        "prose_summary": "Complete shared-contract WAF candidate produced.",
        "request_digest": "a" * 64,
        "created_at": CREATED_AT,
    }
    dg_document, dg_preimage = _signed(dg_document)
    dg_locator = _locator(
        "defense-generation",
        contract_id="defense-generation-result@1.0",
        state="candidate-produced",
        run_id=dg_document["run_id"],
        result_id=dg_result_id,
        request_id=dg_document["request_id"],
        content_sha256=dg_document["content_sha256"],
        size_bytes=dg_document["size_bytes"],
    )

    mc_seed = _load("mitigation-check-accounting.json")
    if current_profiles:
        mc_seed["profile_id"] = "waf-standard@2"
        for obligation in mc_seed["obligation_results"]:
            for case in obligation["case_results"]:
                resolution = case.get("resolution")
                if resolution is not None:
                    resolution["profile_id"] = "waf-standard@2"
                    resolution["resolver_profile_digest"] = "sha256:01f6033b5b09db48056adc8a0d47083f4020cf18d71913c69e283f644ec41a94"
    mc_result_id = "mitigation-check-result:shared-42"
    mc_document = {
        **mc_seed,
        "contract_id": "mitigation-check@1.0",
        "request_id": "mitigation-check-request:shared-42",
        "correlation_id": CORRELATION_ID,
        "run_id": "mitigation-check-run:shared-42",
        "result_id": mc_result_id,
        "status": "completed",
        "terminal_state": "blocked",
        "result_ref": _reference("mitigation-check", mc_result_id),
        "subject": {"vulnerability_id": "CVE-2026-0042"},
        "evidence_refs": [],
        "request_sha256": "sha256:" + "b" * 64,
        "input_provenance": {
            "route_policy": "shared-attack-contracts-v2",
            "check_result": cg_locator,
            "defense_result": dg_locator,
            "selected_test_basis_id": "shared-contracts-v2",
            "verification": "physical-and-logical-sha256-verified",
        },
        "application_unit": {
            "application_unit_id": bundle["application_unit"]["application_unit_id"],
            "artifact_ids": [
                item["id"] for item in bundle["application_unit"]["artifact_refs"]
            ],
            "readback_verified": True,
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
            "matched_rule_id": "janus-shared-contract-v2",
            "detail": "complete WAF application unit matched",
        },
        "substrate": {"image": "fixture", "ready": True},
        "steps": [],
        "prose_summary": "Every required shared-contract case was blocked.",
        "created_at": CREATED_AT,
    }
    mc_document.pop("source_results", None)
    for obligation in mc_document["obligation_results"]:
        for case in obligation["case_results"]:
            case["evidence"] = {
                "blocked": True,
                "status_code": 403,
                "matched_rule_id": "janus-shared-contract-v2",
                "detail": "complete WAF application unit matched",
            }
    mc_document, mc_preimage = _signed(mc_document)
    mc_locator = _locator(
        "mitigation-check",
        contract_id="mitigation-check@1.0",
        state="blocked",
        run_id=mc_document["run_id"],
        result_id=mc_result_id,
        request_id=mc_document["request_id"],
        content_sha256=mc_document["content_sha256"],
        size_bytes=mc_document["size_bytes"],
    )

    bv_seed = _load("bypass-validation-accounting.json")
    mappings = {
        item["obligation_id"]: item
        for item in bundle["primary_candidate"]["obligation_mappings"]
    }
    semantics = cg["attack_match_semantics"]
    obligations = {
        item["obligation_id"]: item for item in semantics["obligations"]
    }
    campaigns = []
    for campaign in bv_seed["campaign_results"]:
        dimensions = []
        attempt_refs = []
        for index, expected in enumerate(
            _expected_bv_dimensions(
                obligations[campaign["obligation_id"]],
                semantics,
                profile_id="waf-bypass@3" if current_profiles else "waf-bypass@2",
            )
        ):
            if expected.get("supported") is False:
                dimensions.append(
                    {
                        **expected,
                        "detail": "No non-identity CG or BV transformation is approved for this carrier.",
                    }
                )
                continue
            attempt_id = f"bv-attempt:{campaign['obligation_id']}:{index}"
            dimensions.append(
                {
                    **expected,
                    "supported": True,
                    "attempt_id": attempt_id,
                    "disposition": "blocked",
                }
            )
            attempt_refs.append(attempt_id)
        campaigns.append(
            {
                **campaign,
                "attempted_dimensions": dimensions,
                "candidate_mapping": mappings[campaign["obligation_id"]],
                "attempt_refs": attempt_refs,
                "resolution_refs": [],
            }
        )
    candidate = bundle["primary_candidate"]
    bv_result_id = "bypass-validation-result:shared-42"
    bv_document = {
        "contract_id": "bypass-validation@2.0",
        "profile_id": "waf-bypass@3" if current_profiles else "waf-bypass@2",
        "run_id": "bypass-validation-run:shared-42",
        "result_id": bv_result_id,
        "terminal_state": "no-bypass-found",
        "result_ref": _reference("bypass-validation", bv_result_id),
        "subject": {"vulnerability_id": "CVE-2026-0042"},
        "outcome_reason": {
            "code": "no-bypass-within-required-campaigns",
            "detail": "Every required obligation campaign completed without an attributable bypass.",
        },
        "search_bounds": {
            "variant_families_requested": [],
            "variant_families_attempted": sorted(
                {
                    dimension["transformation"]
                    for campaign in campaigns
                    for dimension in campaign["attempted_dimensions"]
                }
            ),
            "variant_families_out_of_scope": [],
            "attempt_budget": sum(
                len(campaign["attempted_dimensions"]) for campaign in campaigns
            ),
            "attempts_executed": sum(
                len(campaign["attempt_refs"]) for campaign in campaigns
            ),
            "timeout_seconds": 0,
            "stop_reason": "required-campaigns-completed",
        },
        "candidate_attestation": {
            "bundle_id": bundle["bundle_id"],
            "bundle_revision": bundle["bundle_revision"],
            "bundle_digest": bundle["bundle_digest"],
            "candidate_id": candidate["candidate_id"],
            "candidate_revision": candidate["candidate_revision"],
            "candidate_digest": candidate["candidate_digest"],
        },
        "input_bindings": {
            "shared_contract_locators": [cg_locator, dg_locator, mc_locator],
            "bypass_profile_id": "waf-bypass@3" if current_profiles else "waf-bypass@2",
            "validation_substrate_id": "waf-nonprod-default",
        },
        "resolutions": [],
        "campaign_results": campaigns,
        "counterexamples": [],
        "feedback": [],
        "accounting": bv_seed["accounting"],
        "limitations": [],
        "prose_summary": "Every required obligation campaign completed without an attributable bypass.",
        "produced_at": CREATED_AT,
    }
    bv_preimage = canonical_bytes(bv_document)
    bv_content_sha256 = f"sha256:{sha256(bv_preimage).hexdigest()}"
    bv_locator = _locator(
        "bypass-validation",
        contract_id="bypass-validation@2.0",
        state="no-bypass-found",
        run_id=bv_document["run_id"],
        result_id=bv_result_id,
        request_id="bypass-validation-request:shared-42",
        content_sha256=bv_content_sha256,
        size_bytes=len(bv_preimage),
    )

    request = SharedContractV2InvokeRequest.model_validate(
        {
            "contract_id": "control-translation@2.0",
            "shared_contract_version": "2.0",
            "profile_id": "waf-standard@2" if current_profiles else "waf-standard@1",
            "request_id": "control-translation-request:shared-42",
            "correlation_id": CORRELATION_ID,
            "upstream_inputs": [cg_locator, dg_locator, mc_locator, bv_locator],
            "provenance": {"caller": "janus-orchestration", "source": "temporal"},
        }
    )
    records = {
        "check-generation": UpstreamRecord(
            result_id=cg_result_id,
            terminal_state="completed",
            correlation_id=CORRELATION_ID,
            subject_record_revision_id="subject-revision-42",
            request={},
            result=cg_wrapper,
            raw_result=canonical_bytes(cg_wrapper),
            payload_raw_result=cg_raw,
            authenticated_content=cg_preimage,
            authenticated_content_sha256=cg_hash,
            authenticated_content_size=len(cg_preimage),
        ),
        "defense-generation": UpstreamRecord(
            result_id=dg_result_id,
            terminal_state="candidate-produced",
            correlation_id=CORRELATION_ID,
            subject_record_revision_id="subject-revision-42",
            request={},
            result=dg_document,
            raw_result=canonical_bytes(dg_document),
            artifact_raw_results={
                "artifact-main": (FIXTURES / "waf-rule-main.json").read_bytes(),
                "artifact-carriers": (FIXTURES / "waf-rule-carriers.json").read_bytes(),
            },
            authenticated_content=dg_preimage,
            authenticated_content_sha256=dg_document["content_sha256"],
            authenticated_content_size=len(dg_preimage),
        ),
        "mitigation-check": UpstreamRecord(
            result_id=mc_result_id,
            terminal_state="blocked",
            correlation_id=CORRELATION_ID,
            subject_record_revision_id="subject-revision-42",
            request={},
            result=mc_document,
            raw_result=canonical_bytes(mc_document),
            authenticated_content=mc_preimage,
            authenticated_content_sha256=mc_document["content_sha256"],
            authenticated_content_size=len(mc_preimage),
        ),
        "bypass-validation": UpstreamRecord(
            result_id=bv_result_id,
            terminal_state="no-bypass-found",
            correlation_id=CORRELATION_ID,
            subject_record_revision_id="subject-revision-42",
            request={},
            result=bv_document,
            raw_result=canonical_bytes(bv_document),
            authenticated_content=bv_preimage,
            authenticated_content_sha256=bv_content_sha256,
            authenticated_content_size=len(bv_preimage),
        ),
    }
    assert all(preimage for preimage in (dg_preimage, mc_preimage, bv_preimage))
    return request, records


def _locators(request: SharedContractV2InvokeRequest) -> dict[str, Any]:
    return {item.capability: item for item in request.upstream_inputs}


def _resign_record(
    request: SharedContractV2InvokeRequest,
    records: dict[str, UpstreamRecord],
    capability: str,
) -> SharedContractV2InvokeRequest:
    record = records[capability]
    if capability == "bypass-validation":
        signed = deepcopy(record.result)
        authenticated = canonical_bytes(signed)
        signed_digest = f"sha256:{sha256(authenticated).hexdigest()}"
        signed_size = len(authenticated)
    else:
        signed, authenticated = _signed(record.result)
        signed_digest = signed["content_sha256"]
        signed_size = signed["size_bytes"]
    records[capability] = UpstreamRecord(
        result_id=record.result_id,
        terminal_state=record.terminal_state,
        correlation_id=record.correlation_id,
        subject_record_revision_id=record.subject_record_revision_id,
        request=record.request,
        result=signed,
        raw_result=canonical_bytes(signed),
        payload_raw_result=record.payload_raw_result,
        artifact_raw_results=record.artifact_raw_results,
        authenticated_content=authenticated,
        authenticated_content_sha256=signed_digest,
        authenticated_content_size=signed_size,
    )
    body = request.model_dump(mode="json", by_alias=True)
    for item in body["upstream_inputs"]:
        if item["capability"] == capability:
            item["content_sha256"] = signed_digest
            item["size_bytes"] = signed_size
    return SharedContractV2InvokeRequest.model_validate(body)


class FakeResolver:
    def __init__(self, records: dict[str, UpstreamRecord]) -> None:
        self.records = records

    def fetch(self, reference, **_kwargs):
        return next(
            (record for record in self.records.values() if record.result_id == reference.key),
            None,
        )


class EmptyPolicyReader:
    def read_snapshot(
        self, target_technology: str, target_policy_context_id: str, **_kwargs
    ) -> PolicySnapshot:
        return PolicySnapshot(
            snapshot_id="policy-snapshot:empty",
            target_technology=target_technology,
            target_policy_context_id=target_policy_context_id,
            existing_rule_ids=[],
            existing_rule_summaries=[],
        )


def _translated_v2() -> tuple[
    SharedContractV2InvokeRequest, dict[str, UpstreamRecord], ResultEnvelope
]:
    request, records = _chain()
    result = capability.invoke_shared_contract_v2(
        request,
        resolver=FakeResolver(records),
        policy_reader=EmptyPolicyReader(),
    )
    return request, records, result


def test_databricks_resolver_reads_normalized_inline_cg_persisted_wrapper() -> None:
    request, records = _chain()
    locator = _locators(request)["check-generation"]
    wrapper = records["check-generation"].result
    transport = json.dumps(
        wrapper,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    row = (
        locator.run_id,
        locator.result_id,
        locator.request_id,
        locator.correlation_id,
        locator.terminal_state,
        locator.status,
        transport.decode(),
        "sha256:" + "f" * 64,
        len(transport) + 1,
        datetime.fromisoformat(CREATED_AT),
    )

    class Cursor:
        operation = ""
        parameters: tuple[Any, ...] | None = None

        def execute(self, operation, parameters=None):
            self.operation = operation
            self.parameters = parameters

        def fetchall(self):
            return [row]

        def close(self):
            pass

    class Connection:
        def __init__(self) -> None:
            self.cursor_instance = Cursor()

        def cursor(self):
            return self.cursor_instance

        def close(self):
            pass

    connection = Connection()
    resolver = DatabricksUpstreamResultResolver(
        server_hostname="adb.example.azuredatabricks.net",
        http_path="/sql/1.0/warehouses/example",
        connection_factory=lambda: connection,
    )

    record = resolver.fetch(locator.result_ref, immutable_locator=locator)

    assert record is not None
    assert record.result == wrapper
    assert record.payload_raw_result == canonical_bytes(wrapper["run_result"])
    assert connection.cursor_instance.parameters == (locator.result_id,)
    assert "check_generation_results" in connection.cursor_instance.operation


def test_valid_four_result_join_is_complete_and_deterministic() -> None:
    request, records = _chain()

    first = verify_four_result_join(records, _locators(request))
    second = resolve_and_verify_four_result_join(request, FakeResolver(records))

    assert first.verification == second.verification
    assert first.verification.required_obligation_count == 6
    assert first.accounting.unaccounted_required_obligation_count == 0
    assert set(first.artifact_contents) == {"artifact-main", "artifact-carriers"}


def test_current_four_result_join_requires_exact_profile_revisions() -> None:
    request, records = _chain(current_profiles=True)
    verified = resolve_and_verify_four_result_join(request, FakeResolver(records))
    assert verified.verification.all_required_obligations_have_required_bv_disposition

    records["bypass-validation"].result["profile_id"] = "waf-bypass@2"
    records["bypass-validation"].result["input_bindings"]["bypass_profile_id"] = "waf-bypass@2"
    request = _resign_record(request, records, "bypass-validation")
    with pytest.raises(SharedContractV2Error) as raised:
        resolve_and_verify_four_result_join(request, FakeResolver(records))
    assert raised.value.code == "bv-identity-invalid"


def test_outer_join_requires_producer_authenticated_bytes() -> None:
    request, records = _chain()
    records["mitigation-check"] = replace(
        records["mitigation-check"],
        authenticated_content=None,
        authenticated_content_sha256=None,
        authenticated_content_size=None,
    )

    with pytest.raises(SharedContractV2Error) as raised:
        verify_four_result_join(records, _locators(request))
    assert raised.value.code == "outer-locator-integrity-failed"


def test_mc_d78824c_template_resolution_and_case_evidence_are_verified() -> None:
    request, records = _chain()
    semantics = deepcopy(
        records["check-generation"].result["run_result"]["attack_match_semantics"]
    )
    template_input = next(
        item for item in semantics["test_inputs"] if item["input_id"] == "input-header"
    )
    template_input["input"].pop("scheme")
    template_input["input"].pop("authority")
    template_input["input"].pop("path")
    template_input["input"].update(
        modality="http-request-template",
        path_key="inventory-item-detail",
    )
    captured = _load("mitigation-check-template-case-d78824c.json")
    mc = deepcopy(records["mitigation-check"].result)
    for obligation in mc["obligation_results"]:
        obligation["case_results"] = [
            deepcopy(captured) if case["input_id"] == "input-header" else case
            for case in obligation["case_results"]
        ]

    _validate_mc(
        mc,
        semantics,
        records["defense-generation"].result["candidate_bundle"],
        _locators(request),
    )

    captured["resolution"]["rendered_request"]["authority"] = "invented.invalid"
    for obligation in mc["obligation_results"]:
        for index, case in enumerate(obligation["case_results"]):
            if case["input_id"] == "input-header":
                obligation["case_results"][index] = deepcopy(captured)
    with pytest.raises(SharedContractV2Error) as raised:
        _validate_mc(
            mc,
            semantics,
            records["defense-generation"].result["candidate_bundle"],
            _locators(request),
        )
    assert raised.value.code == "mc-template-resolution-invalid"


def test_bv_ddb49be_root_dimensions_match_cg_semantics_and_profile() -> None:
    request, records = _chain()
    semantics = records["check-generation"].result["run_result"]["attack_match_semantics"]
    root = next(
        item for item in semantics["obligations"] if item["obligation_id"] == "obligation-root"
    )
    campaign = records["bypass-validation"].result["campaign_results"][0]
    captured = _load("bypass-validation-root-dimensions-ddb49be.json")

    assert _expected_bv_dimensions(root, semantics) == captured
    assert [
        {key: dimension[key] for key in ("carrier", "transformation", "input_id", "component_id")}
        for dimension in campaign["attempted_dimensions"]
    ] == captured
    assert campaign["attempt_refs"] == [
        dimension["attempt_id"] for dimension in campaign["attempted_dimensions"]
    ]
    verify_four_result_join(records, _locators(request))


def test_valid_full_v2_invocation_preserves_all_artifacts_and_carriers() -> None:
    request, _, result = _translated_v2()
    structured = result.structured_result

    assert result.contract_id == "control-translation@2.0"
    assert result.terminal_state.value == "translated"
    assert structured.shared_contract_version == "2.0"
    assert structured.profile_id == "waf-standard@1"
    assert structured.pre_translation_verification is not None
    assert structured.pre_translation_verification.required_obligation_count == 6
    assert structured.accounting is not None
    assert structured.accounting.unaccounted_required_obligation_count == 0
    assert [item.source_artifact_id for item in structured.target_artifacts] == [
        "artifact-main",
        "artifact-carriers",
    ]
    assert structured.primary_candidate is not None
    assert (
        structured.target_artifacts[0].content_hash
        == structured.primary_candidate.candidate_artifact.content_hash
    )
    assert [item.source_directive_id for item in structured.translated_directives] == [
        "directive-main-placement",
        "directive-carrier-attach",
    ]
    main = json.loads(structured.target_artifacts[0].content)
    carriers = {
        (
            condition["sourceCarrier"],
            condition["sourceSelector"],
            condition["sourceComponentId"],
        )
        for condition in main["conditions"]
    }
    assert carriers == {
        ("query", "target", "component-url"),
        ("query", "filter", "component-query"),
        ("header", "x-probe", "component-header"),
        ("cookie", "probe", "component-cookie"),
    }
    assert set(result.reference_bundle["upstream_inputs"]) == {
        item.capability for item in request.upstream_inputs
    }


def test_translation_mappings_are_exact_and_bind_emitted_target_ids() -> None:
    _, records, result = _translated_v2()
    source_mappings = {
        item["obligation_id"]: [ref["id"] for ref in item["artifact_refs"]]
        for item in records["defense-generation"].result["candidate_bundle"][
            "primary_candidate"
        ]["obligation_mappings"]
    }
    target_by_source = {
        item.source_artifact_id: item.artifact_id
        for item in result.structured_result.target_artifacts
    }
    actual = {
        item.obligation_id: item.target_artifact_ids
        for item in result.structured_result.translation_mappings
    }

    assert actual == {
        obligation_id: [target_by_source[source_id] for source_id in source_ids]
        for obligation_id, source_ids in source_mappings.items()
    }
    assert len(actual) == 6


def test_unmappable_required_artifact_returns_typed_cannot_express_without_partial_output(
    monkeypatch,
) -> None:
    request, records = _chain()

    def cannot_map(*_args, **_kwargs):
        raise SharedContractV2Error(
            "cannot-express", "required carrier cannot map to the target"
        )

    monkeypatch.setattr(capability, "build_waf_translation_plan", cannot_map)
    result = capability.invoke_shared_contract_v2(
        request,
        resolver=FakeResolver(records),
        policy_reader=EmptyPolicyReader(),
    )

    assert result.terminal_state.value == "cannot-express"
    assert result.structured_result.outcome_reason.detail == (
        "required carrier cannot map to the target"
    )
    assert result.structured_result.target_artifacts == []
    assert result.structured_result.translated_directives == []
    assert result.structured_result.translation_mappings == []
    assert result.inference["llm_invoked"] is False


def test_capability_verification_failure_stops_before_translation_plan(
    monkeypatch,
) -> None:
    request, records = _chain()
    records["mitigation-check"].result["obligation_results"].pop()
    request = _resign_record(request, records, "mitigation-check")
    called = False

    def translation_plan(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("translation plan must not run")

    monkeypatch.setattr(capability, "build_waf_translation_plan", translation_plan)
    with pytest.raises(SharedContractV2Error):
        capability.invoke_shared_contract_v2(
            request,
            resolver=FakeResolver(records),
            policy_reader=EmptyPolicyReader(),
        )
    assert called is False


def test_v2_result_persistence_readback_and_canonical_integrity(tmp_path) -> None:
    request, _, result = _translated_v2()
    repository = SQLiteRunRepository(tmp_path / "shared-contract-v2.db")
    started_at = datetime.now(UTC)
    repository.save_completed_run(
        request,
        result,
        request_hash=canonical_request_hash(request),
        started_at=started_at,
    )
    repository.save_completed_run(
        request,
        result,
        request_hash=canonical_request_hash(request),
        started_at=started_at,
    )

    assert repository.get_run(result.run_id) == result
    assert repository.get_result(result.result_id) == result
    replay = repository.get_by_idempotency_key(request.request_id)
    assert replay is not None
    assert replay.result.model_dump_json() == result.model_dump_json()

    canonical = build_lifecycle_result(result, request, get_settings())
    canonical_again = build_lifecycle_result(result, request, get_settings())
    assert canonical_again == canonical
    assert canonical["profile_id"] == request.profile_id
    assert canonical["shared_contract_version"] == request.shared_contract_version
    assert len(canonical["provenance"]["upstream_inputs"]) == 4
    content = canonical_result_bytes(canonical)
    assert canonical["content_sha256"] == f"sha256:{sha256(content).hexdigest()}"
    assert canonical["size_bytes"] == len(content)


def test_v2_lifecycle_state_is_compact_and_request_rehydrates(tmp_path) -> None:
    request, _ = _chain()
    repository = SQLiteRunRepository(tmp_path / "compact-v2.db")
    created = repository.create_lifecycle_run(
        request,
        idempotency_key=request.request_id,
        request_digest=normalized_request_digest(request),
    )
    rehydrated = repository.get_lifecycle_run(created.run.status.run_id)

    assert rehydrated is not None
    assert rehydrated.request == request
    serialized = request.model_dump_json()
    assert "candidate_bundle" not in serialized
    assert "candidate_artifact_contents" not in serialized
    assert len(serialized.encode()) < 16 * 1024


def test_v2_result_contract_rejects_partial_or_unknown_mapping() -> None:
    _, _, result = _translated_v2()
    document = result.structured_result.model_dump(mode="json")
    document["translation_mappings"].pop()
    with pytest.raises(ValidationError):
        ControlTranslationResult.model_validate(document)

    document = result.structured_result.model_dump(mode="json")
    document["translation_mappings"][0]["target_artifact_ids"] = ["absent"]
    with pytest.raises(ValidationError):
        ControlTranslationResult.model_validate(document)


def test_build_plan_rejects_unknown_carrier_without_partial_plan() -> None:
    request, records = _chain()
    verified = verify_four_result_join(records, _locators(request))
    carrier_document = json.loads(verified.artifact_contents["artifact-carriers"])
    carrier_document["carrier_bindings"][0]["carrier"] = "unknown-carrier"
    verified.artifact_contents["artifact-carriers"] = canonical_bytes(carrier_document)

    with pytest.raises(SharedContractV2Error) as raised:
        build_waf_translation_plan(verified, target_technology="akamai-waf")
    assert raised.value.code == "cannot-express"


def test_v2_request_gate_is_additive_and_legacy_shape_remains_three_result() -> None:
    request, _ = _chain()
    body = request.model_dump(mode="json", by_alias=True)
    body["profile_id"] = "unknown@9"
    with pytest.raises(ValidationError):
        SharedContractV2InvokeRequest.model_validate(body)

    body = request.model_dump(mode="json", by_alias=True)
    body["upstream_inputs"] = body["upstream_inputs"][:3]
    with pytest.raises(ValidationError):
        SharedContractV2InvokeRequest.model_validate(body)


def test_strict_json_rejects_duplicate_keys_and_rfc8785_rejects_nonfinite() -> None:
    with pytest.raises(SharedContractV2Error, match="duplicate JSON key"):
        strict_json_bytes(b'{"a":1,"a":2}', context="duplicate")
    with pytest.raises(SharedContractV2Error, match="RFC 8785"):
        canonical_bytes({"not_finite": float("nan")})


def test_offline_catalog_rejects_unknown_schema_without_network_lookup() -> None:
    with pytest.raises(SharedContractV2Error) as raised:
        OfflineSchemaCatalog().validate("https://network.invalid/schema.json", {})
    assert raised.value.code == "unknown-schema"


Mutation = Callable[[dict[str, UpstreamRecord]], str]


def _dg_mutation(action: Callable[[dict[str, Any]], None]) -> Mutation:
    def mutate(records: dict[str, UpstreamRecord]) -> str:
        action(records["defense-generation"].result["candidate_bundle"])
        return "defense-generation"

    return mutate


@pytest.mark.parametrize(
    ("name", "mutation"),
    [
        (
            "missing-obligation",
            _dg_mutation(
                lambda bundle: bundle["primary_candidate"]["obligation_mappings"].pop()
            ),
        ),
        (
            "duplicate-obligation",
            _dg_mutation(
                lambda bundle: bundle["primary_candidate"]["obligation_mappings"].append(
                    deepcopy(bundle["primary_candidate"]["obligation_mappings"][0])
                )
            ),
        ),
        (
            "renamed-obligation",
            _dg_mutation(
                lambda bundle: bundle["primary_candidate"]["obligation_mappings"][0].update(
                    obligation_id="obligation-renamed"
                )
            ),
        ),
        (
            "missing-input-case",
            lambda records: (
                records["mitigation-check"].result["obligation_results"][0][
                    "case_results"
                ].pop(),
                "mitigation-check",
            )[1],
        ),
        (
            "wrong-count",
            lambda records: (
                records["mitigation-check"].result["accounting"].update(
                    disposed_work_item_count=9
                ),
                "mitigation-check",
            )[1],
        ),
        (
            "missing-campaign",
            lambda records: (
                records["bypass-validation"].result["campaign_results"].pop(),
                "bypass-validation",
            )[1],
        ),
        (
            "duplicate-campaign",
            lambda records: (
                records["bypass-validation"].result["campaign_results"].append(
                    deepcopy(
                        records["bypass-validation"].result["campaign_results"][0]
                    )
                ),
                "bypass-validation",
            )[1],
        ),
        (
            "duplicate-dimension",
            lambda records: (
                records["bypass-validation"].result["campaign_results"][0][
                    "attempted_dimensions"
                ].append(
                    deepcopy(
                        records["bypass-validation"].result["campaign_results"][0][
                            "attempted_dimensions"
                        ][0]
                    )
                ),
                "bypass-validation",
            )[1],
        ),
        (
            "unbound-attempt-ref",
            lambda records: (
                records["bypass-validation"].result["campaign_results"][0][
                    "attempt_refs"
                ].append("bv-attempt:invented"),
                "bypass-validation",
            )[1],
        ),
        (
            "bad-attestation",
            lambda records: (
                records["bypass-validation"].result["candidate_attestation"].update(
                    candidate_revision=2
                ),
                "bypass-validation",
            )[1],
        ),
    ],
)
def test_join_rejects_required_defect(
    name: str, mutation: Mutation
) -> None:
    request, records = _chain()
    capability = mutation(records)
    request = _resign_record(request, records, capability)

    with pytest.raises(SharedContractV2Error):
        verify_four_result_join(records, _locators(request))


@pytest.mark.parametrize(
    ("disposition", "evidence"),
    [
        ("safety-stop", {"detail": "execution stopped safely"}),
        ("unsupported", {"detail": "execution is unsupported"}),
        (
            "not-blocked",
            {
                "status_code": 200,
                "reached_app": True,
                "detail": "execution reached the application",
            },
        ),
    ],
)
def test_join_rejects_resigned_mc_case_contradiction(
    disposition: str, evidence: dict[str, Any]
) -> None:
    request, records = _chain()
    case = records["mitigation-check"].result["obligation_results"][0][
        "case_results"
    ][0]
    case["disposition"] = disposition
    case["evidence"] = evidence
    request = _resign_record(request, records, "mitigation-check")

    with pytest.raises(SharedContractV2Error) as raised:
        verify_four_result_join(records, _locators(request))
    assert raised.value.code == "mc-translation-outcome-invalid"


def test_join_rejects_resigned_mc_aggregate_match_contradiction() -> None:
    request, records = _chain()
    records["mitigation-check"].result["match"] = False
    request = _resign_record(request, records, "mitigation-check")

    with pytest.raises(SharedContractV2Error) as raised:
        verify_four_result_join(records, _locators(request))
    assert raised.value.code == "mc-aggregate-outcome-invalid"


def test_join_rejects_resigned_bv_bypassed_dimension_contradiction() -> None:
    request, records = _chain()
    dimension = next(
        item
        for campaign in records["bypass-validation"].result["campaign_results"]
        for item in campaign["attempted_dimensions"]
        if item.get("supported") is True
    )
    dimension["disposition"] = "bypassed"
    request = _resign_record(request, records, "bypass-validation")

    with pytest.raises(SharedContractV2Error) as raised:
        verify_four_result_join(records, _locators(request))
    assert raised.value.code == "bv-translation-outcome-invalid"


def test_join_rejects_resigned_bv_campaign_contradiction() -> None:
    request, records = _chain()
    records["bypass-validation"].result["campaign_results"][0][
        "disposition"
    ] = "safety-stop"
    request = _resign_record(request, records, "bypass-validation")

    with pytest.raises(SharedContractV2Error) as raised:
        verify_four_result_join(records, _locators(request))
    assert raised.value.code == "bv-translation-outcome-invalid"


def test_join_rejects_resigned_bv_counterexample_feedback_contradiction() -> None:
    request, records = _chain()
    attempt_id = records["bypass-validation"].result["campaign_results"][0][
        "attempt_refs"
    ][0]
    records["bypass-validation"].result["counterexamples"] = [
        {"attempt_id": attempt_id}
    ]
    records["bypass-validation"].result["feedback"] = [
        {"counterexample_ref": attempt_id}
    ]
    request = _resign_record(request, records, "bypass-validation")

    with pytest.raises(SharedContractV2Error) as raised:
        verify_four_result_join(records, _locators(request))
    assert raised.value.code == "bv-translation-outcome-invalid"


def test_join_rejects_digest_defect() -> None:
    request, records = _chain()
    records["defense-generation"].result["content_sha256"] = "sha256:" + "f" * 64
    records["defense-generation"] = replace(
        records["defense-generation"],
        raw_result=canonical_bytes(records["defense-generation"].result),
    )

    with pytest.raises(SharedContractV2Error) as raised:
        verify_four_result_join(records, _locators(request))
    assert raised.value.code == "outer-locator-integrity-failed"


@pytest.mark.parametrize("partition_defect", ["overlap", "missing"])
def test_join_rejects_source_member_partition_defect(partition_defect: str) -> None:
    request, records = _chain()
    cg = records["check-generation"].result["run_result"]
    unsupported = cg["attack_match_semantics"]["unsupported_dimensions"]
    if partition_defect == "overlap":
        unsupported[0]["source_member_refs"][0]["id"] = "member-query"
    else:
        unsupported.pop()
    records["check-generation"] = replace(
        records["check-generation"],
        raw_result=canonical_bytes(records["check-generation"].result),
    )

    with pytest.raises(SharedContractV2Error):
        verify_four_result_join(records, _locators(request))


def test_verification_failure_occurs_before_model_boundary() -> None:
    request, records = _chain()
    records["mitigation-check"].result["obligation_results"].pop()
    request = _resign_record(request, records, "mitigation-check")
    called = False

    def model_call() -> None:
        nonlocal called
        called = True

    with pytest.raises(SharedContractV2Error):
        resolve_and_verify_four_result_join(request, FakeResolver(records))
        model_call()
    assert called is False


class TransportFailingResolver:
    def fetch(self, *_args, **_kwargs):
        raise ConnectionError("temporary Databricks outage")


class IntegrityFailingResolver:
    def fetch(self, *_args, **_kwargs):
        raise UpstreamResolutionError("authenticated row digest differs")


def test_sync_resolver_distinguishes_transport_from_contract_failure() -> None:
    request, _ = _chain()

    with pytest.raises(UpstreamTransportError) as transport:
        resolve_and_verify_four_result_join(request, TransportFailingResolver())
    assert not isinstance(transport.value, SharedContractV2Error)

    with pytest.raises(SharedContractV2Error) as integrity:
        resolve_and_verify_four_result_join(request, IntegrityFailingResolver())
    assert integrity.value.code == "upstream-resolution-failed"
    assert integrity.value.detail == "authenticated row digest differs"


def _permanently_invalid_chain() -> tuple[
    SharedContractV2InvokeRequest, dict[str, UpstreamRecord]
]:
    request, records = _chain()
    records["mitigation-check"].result["obligation_results"].pop()
    return _resign_record(request, records, "mitigation-check"), records


def test_sync_api_preserves_exact_permanent_v2_failure(
    tmp_path, monkeypatch
) -> None:
    request, records = _permanently_invalid_chain()
    repository = SQLiteRunRepository(tmp_path / "sync-v2-failure.db")
    monkeypatch.setattr(api_module, "_REPOSITORY", repository)
    monkeypatch.setattr(api_module, "_UPSTREAM_RESOLVER", FakeResolver(records))
    model_built = False

    def build_model(*_args, **_kwargs):
        nonlocal model_built
        model_built = True
        raise AssertionError("model boundary must not be reached")

    monkeypatch.setattr(capability, "build_translation_doer", build_model)

    with pytest.raises(HTTPException) as raised:
        api_module.invoke_endpoint(request)

    assert raised.value.status_code == 422
    assert raised.value.detail == {
        "code": "mc-obligation-accounting-invalid",
        "detail": "MC obligation IDs differ",
        "retryable": False,
    }
    assert model_built is False


def test_async_lifecycle_preserves_exact_permanent_v2_failure(
    tmp_path, monkeypatch
) -> None:
    request, records = _permanently_invalid_chain()
    repository = SQLiteRunRepository(tmp_path / "async-v2-failure.db")
    created = repository.create_lifecycle_run(
        request,
        idempotency_key=request.request_id,
        request_digest=normalized_request_digest(request),
    )
    settings = Settings(
        run_mode="fixture",
        model_provider="none",
        database_path=str(repository.database_path),
    )
    worker = LifecycleWorker(
        lambda: repository, lambda: FakeResolver(records), settings
    )
    claimed = repository.claim_lifecycle_run(
        worker_id=worker._worker_id, lease_seconds=30, max_attempts=3
    )
    assert claimed is not None
    model_built = False

    def build_model(*_args, **_kwargs):
        nonlocal model_built
        model_built = True
        raise AssertionError("model boundary must not be reached")

    monkeypatch.setattr(capability, "build_translation_doer", build_model)
    worker._execute(claimed)

    failed = repository.get_lifecycle_run(created.run.status.run_id)
    assert failed is not None
    assert failed.status.status == "failed"
    assert failed.status.failure is not None
    assert failed.status.failure.model_dump() == {
        "code": "mc-obligation-accounting-invalid",
        "detail": "MC obligation IDs differ",
        "retryable": False,
    }
    assert model_built is False


def test_async_lifecycle_classifies_v2_transport_failure_as_retryable(
    tmp_path,
) -> None:
    request, _ = _chain()
    repository = SQLiteRunRepository(tmp_path / "async-v2-transport-failure.db")
    created = repository.create_lifecycle_run(
        request,
        idempotency_key=request.request_id,
        request_digest=normalized_request_digest(request),
    )
    settings = Settings(
        run_mode="fixture",
        model_provider="none",
        database_path=str(repository.database_path),
    )
    worker = LifecycleWorker(
        lambda: repository, lambda: TransportFailingResolver(), settings
    )
    claimed = repository.claim_lifecycle_run(
        worker_id=worker._worker_id, lease_seconds=30, max_attempts=3
    )
    assert claimed is not None

    worker._execute(claimed)

    failed = repository.get_lifecycle_run(created.run.status.run_id)
    assert failed is not None
    assert failed.status.status == "failed"
    assert failed.status.failure is not None
    assert failed.status.failure.model_dump() == {
        "code": "translation_execution_failed",
        "detail": "Translation execution failed (UpstreamTransportError).",
        "retryable": True,
    }


@pytest.mark.parametrize(
    "settings",
    [
        Settings(run_mode="fixture", model_provider="none"),
        Settings(
            run_mode="live",
            model_provider="att-inference",
            model_name="configured-but-unused",
            att_inference_base_url="https://inference.invalid/v1",
            att_inference_api_key="unused-test-key",
        ),
    ],
    ids=["fixture", "live"],
)
def test_successful_v2_translation_reports_deterministic_actor_and_provenance(
    settings: Settings, monkeypatch
) -> None:
    request, records = _chain()
    monkeypatch.setattr(
        capability,
        "build_translation_doer",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("configured model must not be constructed")
        ),
    )

    result = capability.invoke_shared_contract_v2(
        request,
        resolver=FakeResolver(records),
        settings=settings,
        policy_reader=EmptyPolicyReader(),
    )

    proof_ids = [item.result_id for item in request.upstream_inputs]
    assert result.inference == {
        "execution_mode": "live" if settings.is_live else "fixture",
        "provider": "deterministic-code",
        "model": None,
        "llm_invoked": False,
        "proposal_source": "deterministic-shared-contract-v2",
        "credentials_configured": settings.credentials_configured,
        "proposal_from_doer": False,
        "actor": {
            "type": "deterministic-code",
            "identity": "control-translation.shared-contract-v2",
            "version": "2.0",
        },
        "provenance": {
            "source": "verified-four-result-join",
            "upstream_result_ids": proof_ids,
        },
    }
    assert result.provenance == proof_ids
    assert result.structured_result.primary_candidate is not None
    assert result.structured_result.primary_candidate.provenance == proof_ids


@pytest.mark.parametrize(
    "run_mode",
    ["fixture", "live"],
)
def test_async_v2_result_persists_deterministic_actor_and_provenance(
    run_mode: str, tmp_path, monkeypatch
) -> None:
    request, records = _chain()
    repository = SQLiteRunRepository(tmp_path / f"async-v2-{run_mode}.db")
    created = repository.create_lifecycle_run(
        request,
        idempotency_key=request.request_id,
        request_digest=normalized_request_digest(request),
    )
    settings = (
        Settings(
            run_mode="live",
            model_provider="att-inference",
            model_name="configured-but-unused",
            att_inference_base_url="https://inference.invalid/v1",
            att_inference_api_key="unused-test-key",
            database_path=str(repository.database_path),
        )
        if run_mode == "live"
        else Settings(
            run_mode="fixture",
            model_provider="none",
            database_path=str(repository.database_path),
        )
    )
    worker = LifecycleWorker(
        lambda: repository, lambda: FakeResolver(records), settings
    )
    claimed = repository.claim_lifecycle_run(
        worker_id=worker._worker_id, lease_seconds=30, max_attempts=3
    )
    assert claimed is not None
    monkeypatch.setattr(
        capability,
        "build_translation_doer",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("configured model must not be constructed")
        ),
    )

    worker._execute(claimed)

    proof_ids = [item.result_id for item in request.upstream_inputs]
    expected_inference = {
        "execution_mode": run_mode,
        "provider": "deterministic-code",
        "model": None,
        "llm_invoked": False,
        "proposal_source": "deterministic-shared-contract-v2",
        "credentials_configured": settings.credentials_configured,
        "proposal_from_doer": False,
        "actor": {
            "type": "deterministic-code",
            "identity": "control-translation.shared-contract-v2",
            "version": "2.0",
        },
        "provenance": {
            "source": "verified-four-result-join",
            "upstream_result_ids": proof_ids,
        },
    }
    run_id = created.run.status.run_id
    persisted = repository.get_run(run_id)
    canonical = repository.get_lifecycle_result(run_id)
    assert persisted is not None
    assert persisted.inference == expected_inference
    assert persisted.provenance == proof_ids
    assert canonical is not None
    assert canonical["inference"] == expected_inference
    assert [
        item["result_id"] for item in canonical["provenance"]["upstream_inputs"]
    ] == proof_ids


class _CountingResultSink(SQLiteRunRepository):
    def __init__(self, database_path: Path) -> None:
        super().__init__(database_path)
        self.publish_calls = 0

    def save_completed_run(self, *args, **kwargs) -> None:
        self.publish_calls += 1
        super().save_completed_run(*args, **kwargs)


def test_v2_prepared_result_is_stable_across_publication_recovery(
    tmp_path, monkeypatch
) -> None:
    request, records = _chain()
    lifecycle = SQLiteRunRepository(tmp_path / "v2-recovery-lifecycle.db")
    sink = _CountingResultSink(tmp_path / "v2-recovery-sink.db")
    repository = SplitRunRepository(lifecycle, sink)
    created = repository.create_lifecycle_run(
        request,
        idempotency_key=request.request_id,
        request_digest=normalized_request_digest(request),
    )
    settings = Settings(
        run_mode="fixture",
        model_provider="none",
        database_path=str(lifecycle.database_path),
    )
    worker = LifecycleWorker(
        lambda: repository, lambda: FakeResolver(records), settings
    )
    claimed = repository.claim_lifecycle_run(
        worker_id=worker._worker_id, lease_seconds=30, max_attempts=3
    )
    assert claimed is not None
    original_complete = repository.complete_lifecycle_run
    monkeypatch.setattr(
        repository,
        "complete_lifecycle_run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("simulated finalize crash")
        ),
    )

    with pytest.raises(RuntimeError, match="simulated finalize crash"):
        worker._process(claimed, Event())
    first = lifecycle.get_prepared_publication(created.run.status.run_id)
    assert first is not None

    with sqlite3.connect(lifecycle.database_path) as connection:
        connection.execute(
            "UPDATE capability_run_lifecycle SET lease_expires_at = "
            "'2000-01-01T00:00:00+00:00' WHERE run_id = ?",
            (created.run.status.run_id,),
        )
    recovered_worker = LifecycleWorker(
        lambda: repository, lambda: FakeResolver(records), settings
    )
    recovered = repository.claim_lifecycle_run(
        worker_id=recovered_worker._worker_id,
        lease_seconds=30,
        max_attempts=3,
    )
    assert recovered is not None
    monkeypatch.setattr(repository, "complete_lifecycle_run", original_complete)
    monkeypatch.setattr(
        capability,
        "invoke_shared_contract_v2",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("recovery regenerated the v2 result")
        ),
    )

    recovered_worker._process(recovered, Event())

    terminal = lifecycle.get_lifecycle_run(created.run.status.run_id)
    second = lifecycle.get_prepared_publication(created.run.status.run_id)
    assert sink.publish_calls == 2
    assert terminal is not None
    assert terminal.status.status == "completed"
    assert terminal.publication_state == "published"
    assert second is not None
    assert second.result_envelope == first.result_envelope
    assert second.canonical_result == first.canonical_result
    assert second.completion == first.completion


def test_embedded_fixture_digest_profiles_are_exact() -> None:
    cg = _load("check-generation-complete-result.json")
    semantics = cg["attack_match_semantics"]
    projection = {
        key: cg[key]
        for key in ("artifacts", "input_membership", "member_results", "test_inputs")
    }
    bundle = _load("candidate-bundle.json")
    candidate = bundle["primary_candidate"]
    bundle_preimage = deepcopy(bundle)
    bundle_preimage.pop("bundle_digest")
    bundle_preimage["primary_candidate"].pop("candidate_digest")

    assert cg["content_digest"] == digest_without(cg, "content_digest")
    assert semantics["semantics_digest"] == digest_without(
        semantics, "semantics_digest"
    )
    assert semantics["source_binding"]["check_generation"][
        "source_projection_digest"
    ] == digest(projection)
    assert candidate["candidate_digest"] == digest_without(
        candidate, "candidate_digest"
    )
    assert bundle["bundle_digest"] == digest(bundle_preimage)
    assert rfc8785.dumps({"b": 1, "a": 2}) == b'{"a":2,"b":1}'
    assert datetime.fromisoformat(CREATED_AT).tzinfo == UTC


def test_cg_additive_content_digest_is_optional() -> None:
    _request, records = _chain()
    cg = deepcopy(records["check-generation"].result["run_result"])
    cg.pop("content_digest", None)
    cg.pop("digest_profile", None)
    semantics = _validate_cg(cg, OfflineSchemaCatalog())
    assert semantics["contract_id"] == "attack-match-semantics@2.0"


def test_shared_v2_fixture_manifest_is_exact() -> None:
    manifest = _load("manifest.json")
    assert set(manifest) == {"manifest_version", "fixture_set", "fixtures"}
    assert manifest["manifest_version"] == 1
    assert manifest["fixture_set"] == "shared-attack-contracts-v2-ct@2026-09-12"
    entries = {item["name"]: item for item in manifest["fixtures"]}
    files = {
        path.name
        for path in FIXTURES.glob("*.json")
        if path.name != "manifest.json"
    }
    assert set(entries) == files
    for name, entry in entries.items():
        assert set(entry) == {"name", "source", "sha256", "byte_length"}
        raw = (FIXTURES / name).read_bytes()
        assert entry["sha256"] == f"sha256:{sha256(raw).hexdigest()}"
        assert entry["byte_length"] == len(raw)
        assert entry["source"]


def test_checked_in_api_schemas_exactly_match_contract_models() -> None:
    root = Path(__file__).parents[1]

    assert json.loads((root / "schemas/request.schema.json").read_text()) == (
        TypeAdapter(InvokeAPIRequest).json_schema()
    )
    assert json.loads((root / "schemas/result.schema.json").read_text()) == (
        ResultEnvelope.model_json_schema()
    )
