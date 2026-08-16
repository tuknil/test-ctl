"""Fixture ProvenMitigationPattern samples.

These are deterministic stand-ins for real output from `defense-generation`
-> `mitigation-check` + `bypass-validation` (upstream capabilities not yet
built). Modeled on the illustrative example in `docs/cfs-source.md`.
"""

from __future__ import annotations

from control_translation.contracts import ProvenMitigationPattern


FIXTURE_PROVEN_PATTERNS: dict[str, ProvenMitigationPattern] = {
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
