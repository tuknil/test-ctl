"""Target-technology adapter registry.

One adapter per target control technology. Each adapter implements the
`TargetAdapter` protocol defined in `base.py`. Adding a new real integration
(e.g. real Akamai API access) means implementing a new adapter class and
registering it here -- the rest of the capability core does not change.
"""

from __future__ import annotations

from control_translation.adapters.akamai_waf import AkamaiWafAdapter
from control_translation.adapters.base import TargetAdapter
from control_translation.adapters.edr_s1 import EdrS1Adapter
from control_translation.adapters.firewall_generic import FirewallGenericAdapter


ADAPTER_REGISTRY: dict[str, TargetAdapter] = {
    "akamai-waf": AkamaiWafAdapter(),
    "firewall-generic": FirewallGenericAdapter(),
    "edr-s1": EdrS1Adapter(),
}


def get_adapter(target_technology: str) -> TargetAdapter | None:
    return ADAPTER_REGISTRY.get(target_technology)
