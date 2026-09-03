import json

from control_translation.adapters import get_adapter
from control_translation.adapters.akamai_waf import AkamaiWafAdapter
from control_translation.adapters.edr_s1 import EdrS1Adapter
from control_translation.adapters.firewall_generic import FirewallGenericAdapter
from control_translation.policy_reader.fixtures import FixturePolicyReader


def test_registry_resolves_known_adapters():
    assert isinstance(get_adapter("akamai-waf"), AkamaiWafAdapter)
    assert isinstance(get_adapter("firewall-generic"), FirewallGenericAdapter)
    assert isinstance(get_adapter("edr-s1"), EdrS1Adapter)


def test_registry_returns_none_for_unknown_target():
    assert get_adapter("unknown-tech") is None


def test_akamai_adapter_recognizes_request_argument_sql_injection():
    adapter = AkamaiWafAdapter()

    assert adapter.supports_feature(
        "Send a request to /public/submit.php targeting saveUser with a "
        "crafted value in the Researcher argument and observe whether SQL "
        "injection behavior occurs."
    )


def test_akamai_adapter_validates_expected_shape():
    adapter = AkamaiWafAdapter()
    valid = json.dumps(
        {
            "name": "block-cve-example",
            "operation": "AND",
            "conditions": [
                {
                    "type": "requestHeaderValueMatch",
                    "positiveMatch": True,
                    "header": "content-type",
                    "value": ["text/xml"],
                }
            ],
        }
    )
    result = adapter.validate_syntax(valid)
    assert result.valid is True

    invalid = "not a rule at all"
    result = adapter.validate_syntax(invalid)
    assert result.valid is False
    assert result.errors


def test_akamai_adapter_rejects_embedded_action():
    adapter = AkamaiWafAdapter()
    with_action = json.dumps(
        {
            "name": "bad",
            "operation": "AND",
            "action": "deny",
            "conditions": [
                {"type": "pathMatch", "positiveMatch": True, "value": ["/x"]}
            ],
        }
    )
    result = adapter.validate_syntax(with_action)
    assert result.valid is False
    assert any("action" in e.lower() for e in result.errors)


def test_akamai_adapter_rejects_synthetic_request_headers():
    adapter = AkamaiWafAdapter()
    synthetic_header = json.dumps(
        {
            "name": "bad-request-uri-header",
            "operation": "AND",
            "conditions": [
                {
                    "type": "requestHeaderValueMatch",
                    "positiveMatch": True,
                    "header": "Request-URI",
                    "value": ["/public/submit.php"],
                }
            ],
        }
    )

    result = adapter.validate_syntax(synthetic_header)

    assert result.valid is False
    assert any("synthetic" in error for error in result.errors)


def test_akamai_adapter_enforces_condition_specific_header_key():
    adapter = AkamaiWafAdapter()
    body_condition_with_header = json.dumps(
        {
            "name": "bad-body-header",
            "operation": "AND",
            "conditions": [
                {
                    "type": "argsPostMatch",
                    "positiveMatch": True,
                    "header": "Researcher",
                    "value": ["'"],
                }
            ],
        }
    )

    result = adapter.validate_syntax(body_condition_with_header)

    assert result.valid is False
    assert any("valid only" in error for error in result.errors)


def test_akamai_json_body_condition_requires_parameter():
    adapter = AkamaiWafAdapter()
    missing_parameter = json.dumps(
        {
            "operation": "AND",
            "conditions": [
                {
                    "type": "argsPostJSONMatch",
                    "positiveMatch": True,
                    "value": ["--require"],
                }
            ],
        }
    )

    result = adapter.validate_syntax(missing_parameter)

    assert result.valid is False
    assert any("parameter" in error for error in result.errors)


def test_firewall_adapter_validates_expected_shape():
    adapter = FirewallGenericAdapter()
    valid = (
        'set rulebase security rules "block-cve-example" from untrust to trust '
        "source any destination mgmt-server application any service tcp-8443 "
        "action deny"
    )
    result = adapter.validate_syntax(valid)
    assert result.valid is True

    invalid = "deny everything"
    result = adapter.validate_syntax(invalid)
    assert result.valid is False


def test_firewall_adapter_validates_xml_shape():
    adapter = FirewallGenericAdapter()
    valid_xml = (
        '<entry name="block-cve-example">'
        "<from><member>untrust</member></from>"
        "<to><member>trust</member></to>"
        "<source><member>any</member></source>"
        "<destination><member>mgmt-server</member></destination>"
        "<action>deny</action>"
        "</entry>"
    )
    result = adapter.validate_syntax(valid_xml)
    assert result.valid is True


def test_edr_adapter_validates_expected_shape():
    adapter = EdrS1Adapter()
    valid = json.dumps(
        {
            "data": {
                "name": "detect-cve-example",
                "severity": "Medium",
                "queryLang": "2.0",
                "s1ql": "EventType = 'Process Creation'",
                "treatAsThreat": "UNDEFINED",
            }
        }
    )
    result = adapter.validate_syntax(valid)
    assert result.valid is True

    invalid = "flag suspicious activity"
    result = adapter.validate_syntax(invalid)
    assert result.valid is False


def test_fixture_policy_reader_returns_known_snapshot():
    reader = FixturePolicyReader()
    snapshot = reader.read_snapshot("akamai-waf", "akamai-policy:example:rev-17")
    assert snapshot is not None
    assert snapshot.target_technology == "akamai-waf"


def test_fixture_policy_reader_returns_none_for_unknown_context():
    reader = FixturePolicyReader()
    snapshot = reader.read_snapshot("akamai-waf", "does-not-exist")
    assert snapshot is None
