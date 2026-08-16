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


def test_akamai_adapter_validates_expected_shape():
    adapter = AkamaiWafAdapter()
    valid = 'rule "block-cve-example": match header("Content-Type") ~ /(%|\\$)\\{.*\\}/ -> block'
    result = adapter.validate_syntax(valid)
    assert result.valid is True

    invalid = "not a rule at all"
    result = adapter.validate_syntax(invalid)
    assert result.valid is False
    assert result.errors


def test_firewall_adapter_validates_expected_shape():
    adapter = FirewallGenericAdapter()
    valid = 'rule "block-cve-example": deny inbound tcp/8443 from any to any'
    result = adapter.validate_syntax(valid)
    assert result.valid is True

    invalid = "deny everything"
    result = adapter.validate_syntax(invalid)
    assert result.valid is False


def test_edr_adapter_validates_expected_shape():
    adapter = EdrS1Adapter()
    valid = "detect process-chain: web-server -> shell -> network => block"
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
