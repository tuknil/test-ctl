from control_translation.diagnostics import diagnostic_json, sanitize_for_logging


def test_diagnostic_payload_redacts_secrets_and_candidate_content():
    payload = {
        "request_id": "request-visible",
        "authorization": "Bearer credential-value",
        "nested": {
            "idempotency_key": "idempotency-secret",
            "client_secret": "client-secret-value",
            "candidate_artifact": {
                "content_ref": "deployable-rule-content",
                "content_hash": "sha256:visible-hash",
            },
        },
        "json_body_field_feature": {
            "field_path": ["credentials", "token"],
            "value": "arbitrary-upstream-scalar",
        },
    }

    sanitized = sanitize_for_logging(payload)
    serialized = diagnostic_json(payload)

    assert sanitized["request_id"] == "request-visible"
    assert sanitized["authorization"] == "[REDACTED]"
    assert sanitized["nested"]["candidate_artifact"]["content_ref"] == "[REDACTED]"
    assert sanitized["json_body_field_feature"]["value"] == "[REDACTED]"
    assert "sha256:visible-hash" in serialized
    assert "credential-value" not in serialized
    assert "idempotency-secret" not in serialized
    assert "client-secret-value" not in serialized
    assert "deployable-rule-content" not in serialized
    assert "arbitrary-upstream-scalar" not in serialized
