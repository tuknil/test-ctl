"""Fixture ProvenMitigationPattern samples.

These are deterministic stand-ins for real output from `defense-generation`
-> `mitigation-check` + `bypass-validation` (upstream capabilities not yet
built). Modeled on the illustrative example in `docs/cfs-source.md`.
"""

from __future__ import annotations

from control_translation.contracts import ProvenMitigationPattern


FIXTURE_PROVEN_PATTERNS: dict[str, ProvenMitigationPattern] = {
    "proven-pattern:CVE-2017-5638:waf:fixture-1": ProvenMitigationPattern(
        proven_pattern_id="proven-pattern:CVE-2017-5638:waf:fixture-1",
        vulnerability_id="CVE-2017-5638",
        selected_control_class="waf",
        discriminator_id="discriminator:CVE-2017-5638:content-type-ognl",
        discriminator_description=(
            "Blocks suspicious OGNL expression syntax in the HTTP Content-Type "
            "header used by attacks against the Apache Struts Jakarta Multipart parser."
        ),
        pattern_summary=(
            "Reject requests whose Content-Type header contains OGNL expression "
            "markers associated with CVE-2017-5638. This is a compensating control; "
            "upgrade Apache Struts to a fixed version."
        ),
        # These are demo lineage records, not claims that this repository ran proof.
        proof_record_ids=[
            "mitigation-check-result:CVE-2017-5638:waf:fixture-1",
            "bypass-validation-result:CVE-2017-5638:waf:fixture-1",
        ],
    ),
    "proven-pattern:CVE-2021-44228:waf:fixture-1": ProvenMitigationPattern(
        proven_pattern_id="proven-pattern:CVE-2021-44228:waf:fixture-1",
        vulnerability_id="CVE-2021-44228",
        selected_control_class="waf",
        discriminator_id="discriminator:CVE-2021-44228:jndi-user-agent",
        discriminator_description=(
            "Blocks JNDI lookup syntax such as '${jndi:' in the HTTP User-Agent "
            "header before it reaches an application using vulnerable Log4j Core."
        ),
        pattern_summary=(
            "Reject User-Agent values containing direct JNDI lookup syntax associated "
            "with Log4Shell. This is a narrow compensating control; upgrade Log4j."
        ),
        proof_record_ids=[
            "mitigation-check-result:CVE-2021-44228:waf:fixture-1",
            "bypass-validation-result:CVE-2021-44228:waf:fixture-1",
        ],
    ),
    "proven-pattern:CVE-2021-44228:edr:fixture-1": ProvenMitigationPattern(
        proven_pattern_id="proven-pattern:CVE-2021-44228:edr:fixture-1",
        vulnerability_id="CVE-2021-44228",
        selected_control_class="edr",
        discriminator_id="discriminator:CVE-2021-44228:java-child-process",
        discriminator_description=(
            "Detects a Java process spawning a command shell or download utility, "
            "a practical post-exploitation process-chain signal for Log4Shell."
        ),
        pattern_summary=(
            "Alert when Java launches a shell, PowerShell, curl, wget, or certutil. "
            "This detection is not vulnerability remediation; upgrade Log4j."
        ),
        proof_record_ids=[
            "mitigation-check-result:CVE-2021-44228:edr:fixture-1",
            "bypass-validation-result:CVE-2021-44228:edr:fixture-1",
        ],
    ),
    "proven-pattern:CVE-2023-27997:firewall:fixture-1": ProvenMitigationPattern(
        proven_pattern_id="proven-pattern:CVE-2023-27997:firewall:fixture-1",
        vulnerability_id="CVE-2023-27997",
        selected_control_class="firewall",
        discriminator_id="discriminator:CVE-2023-27997:ssl-vpn-exposure",
        discriminator_description=(
            "Blocks inbound network connections from the untrusted zone to an "
            "affected FortiOS SSL-VPN gateway on TCP/443."
        ),
        pattern_summary=(
            "Temporarily isolate an affected FortiOS SSL-VPN listener from untrusted "
            "networks while applying Fortinet updates. This control interrupts VPN access."
        ),
        proof_record_ids=[
            "mitigation-check-result:CVE-2023-27997:firewall:fixture-1",
            "bypass-validation-result:CVE-2023-27997:firewall:fixture-1",
        ],
    ),
    "proven-pattern:CVE-EXAMPLE:waf:3": ProvenMitigationPattern(
        proven_pattern_id="proven-pattern:CVE-EXAMPLE:waf:3",
        vulnerability_id="CVE-EXAMPLE",
        selected_control_class="waf",
        discriminator_id="discriminator:CVE-EXAMPLE:cmd-param",
        discriminator_description=(
            "Blocks OGNL/EL expression syntax appearing in the Content-Type header."
        ),
        pattern_summary=(
            "Block requests whose Content-Type header contains OGNL/EL "
            "expression syntax (e.g. '%{...}' or '${...}')."
        ),
        proof_record_ids=[
            "mitigation-check-result:CVE-EXAMPLE:3",
            "bypass-validation-result:CVE-EXAMPLE:3",
        ],
    ),
    "proven-pattern:CVE-EXAMPLE:firewall:1": ProvenMitigationPattern(
        proven_pattern_id="proven-pattern:CVE-EXAMPLE:firewall:1",
        vulnerability_id="CVE-EXAMPLE",
        selected_control_class="firewall",
        discriminator_id="discriminator:CVE-EXAMPLE:mgmt-port",
        discriminator_description=(
            "Blocks inbound connections to the exposed management port from "
            "untrusted networks."
        ),
        pattern_summary=(
            "Deny inbound traffic to TCP/8443 (management interface) except "
            "from the trusted admin subnet."
        ),
        proof_record_ids=[
            "mitigation-check-result:CVE-EXAMPLE:1",
            "bypass-validation-result:CVE-EXAMPLE:1",
        ],
    ),
    "proven-pattern:CVE-EXAMPLE:edr:1": ProvenMitigationPattern(
        proven_pattern_id="proven-pattern:CVE-EXAMPLE:edr:1",
        vulnerability_id="CVE-EXAMPLE",
        selected_control_class="edr",
        discriminator_id="discriminator:CVE-EXAMPLE:proc-tree",
        discriminator_description=(
            "Flags a child process spawn chain unique to the exploit "
            "(e.g. web-server -> shell -> outbound network)."
        ),
        pattern_summary=(
            "Detect and block the web-server-to-shell-to-network process "
            "spawn chain associated with the exploit."
        ),
        proof_record_ids=[
            "mitigation-check-result:CVE-EXAMPLE:2",
            "bypass-validation-result:CVE-EXAMPLE:2",
        ],
    ),
}


def get_fixture_pattern(proven_pattern_id: str) -> ProvenMitigationPattern | None:
    return FIXTURE_PROVEN_PATTERNS.get(proven_pattern_id)
