# Deployable Security Control Formats: Akamai WAF, Palo Alto PAN-OS, and SentinelOne STAR

## TL;DR
- **Akamai App & API Protector / Kona Site Defender** uses a JSON custom-rule object (`conditions[]` each with a `type`, `positiveMatch`, and `value`, joined by a top-level `operation` of AND/OR) POSTed to the Application Security API at `/appsec/v1/configs/{configId}/custom-rules`; creation requires an authenticated Akamai Control Center account with EdgeGrid API credentials.
- **Palo Alto PAN-OS** expresses a security policy rule as an XML `<entry>` under the security-rulebase XPath (set via the XML API with `action=set`) or as `set rulebase security rules ...` CLI commands; both surfaces are public-documented and require firewall/Panorama admin access to apply.
- **SentinelOne STAR** custom detection rules are created via `POST /web/api/v2.1/cloud-detection/rules` with a JSON body carrying an S1QL query plus response fields; STAR rules are cloud-only (not on-prem) and require an authenticated management console API token, and the authoritative API reference lives behind the licensed console.

## Key Findings
- All three formats are real and documented, but only Akamai and Palo Alto publish complete rule schemas on the open web; SentinelOne's authoritative v2.1 API reference is gated behind the customer console (`https://<your-console>.sentinelone.net/api-doc/`).
- Akamai custom rules are configuration-level JSON resources; the action (alert/deny/none) is assigned separately per security policy, not embedded in the rule body itself.
- PAN-OS offers two first-class administrative surfaces — the XML API and the CLI `set` syntax — that map 1:1, plus a newer REST API.
- SentinelOne STAR field names, auth header, and the cloud-only limitation are well-corroborated from official and official-adjacent sources even though the literal endpoint schema is not on the public web.

## Details

### 1. Akamai WAF (App & API Protector / Kona Site Defender)

**Format & where it lives.** A custom WAF rule is a JSON object created through the Akamai Application Security API (the EdgeGrid-authenticated `appsec` API), via `POST https://{hostname}/appsec/v1/configs/{configId}/custom-rules`. The body contains a `name`, a top-level `operation` (`AND` or `OR`) that joins an array of `conditions`, and each condition has a `type` (the request component to inspect), a `positiveMatch` boolean, and a `value` array; string conditions add flags such as `valueCase`, `valueWildcard`, and `valueNormalize`. Match conditions are expressed by `type`. Per Akamai TechDocs "CustomRule condition type values," these include `requestHeaderMatch` (request headers), `argsPostMatch` ("POST request body parameters"), `argsPostJSONMatch` ("POST request body parameters in JSON format"), `argsPostXMLMatch` (POST body in XML format), `pathMatch` (URI/path), `uriQueryMatch` (query parameters), `ipMatch`, `requestMethodMatch`, `cookieMatch`, and more; a related `requestHeaderValueMatch` type (with a `header` name and `value` array) is used in published rules to match on a specific header value. Custom rules can also carry a `tag` array, a `samplingRate`, and an `effectiveTimePeriod`. The action itself (`alert`, `deny`, or `none`) is **not** part of the custom rule object — it is assigned when the rule is associated with a security policy via `PUT /appsec/v1/configs/{configId}/versions/{versionNumber}/security-policies/{policyId}/custom-rules/{ruleId}`. Exceptions to built-in Kona/KRS rules are handled through separate "conditions and exceptions" endpoints using an `excludeCondition` array; rate-limiting is configured through separate rate-policy resources, not the custom rule body.

**Minimal working example** (real custom-rule JSON structure; this one blocks a request whose `content-type` header indicates XML and whose XML body contains OGNL expression syntax):

```json
{
  "name": "Block-XML-OGNL-Body",
  "description": "Blocks requests with an XML content type whose body contains OGNL expression syntax.",
  "operation": "AND",
  "conditions": [
    {
      "type": "requestHeaderValueMatch",
      "positiveMatch": true,
      "header": "content-type",
      "valueCase": false,
      "valueWildcard": true,
      "value": [ "text/xml", "application/xml" ]
    },
    {
      "type": "argsPostXMLMatch",
      "positiveMatch": true,
      "valueCase": true,
      "valueWildcard": true,
      "value": [ "*%{*", "*#context*", "*@java.lang.Runtime@*" ]
    }
  ],
  "tag": [ "OGNL", "RCE" ]
}
```

(For comparison, a real published Akamai custom rule blocking WordPress CVE-2026-63030 used the same shape with `"operation": "OR"` and `pathMatch` + `uriQueryMatch` conditions, confirming the `type`/`positiveMatch`/`value`/`valueWildcard`/`tag` field structure.)

**Paid/authenticated access.** Yes. Custom rule creation requires an Akamai Control Center account with the Application Security product entitlement (App & API Protector, or Kona Site Defender with the Advanced Security module) and EdgeGrid API credentials (a `.edgerc` client token/secret). The rule can be authored in the Control Center UI (Security Configuration → security policy → Custom Rules) or via the API/Terraform, but there is no way to activate a rule to Akamai's edge without an authenticated, licensed account.

**Doc link:** https://techdocs.akamai.com/application-security/reference/post-config-custom-rules (condition `type` values: https://techdocs.akamai.com/application-security/reference/crtval)

### 2. Palo Alto Networks firewall (PAN-OS)

**Format & where it lives.** A PAN-OS security policy rule is an XML `<entry name="...">` element in the security rulebase at the XPath `/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules`. It is created over the XML API with a URL request of the form `type=config&action=set&xpath=<xpath>&element=<xml>&key=<apikey>`, or equivalently with `set rulebase security rules <name> ...` commands in CLI configuration mode. Required/typical fields: `from`/`to` (source and destination security zones), `source`/`destination` (address objects or `any`), `application` (App-ID or `any`), `service` (a service object, `application-default`, or `any`), `action` (`allow`, `deny`, `drop`, `reset-client`, `reset-server`, `reset-both`), and `profile-setting`/`group` (a security profile group). Address objects live at `.../address/entry` (`ip-netmask`, `ip-range`, or `fqdn`) and service objects at `.../service/entry` (`protocol/tcp|udp/port`). The API key is obtained via the `type=keygen` request; changes sit in the candidate config until a `commit`.

**Minimal working example — XML API format** (one address object, one service object, one security rule):

```
# Address object
curl -k -X POST 'https://<fw>/api/?type=config&action=set&key=<APIKEY>&xpath=/config/devices/entry[@name=%27localhost.localdomain%27]/vsys/entry[@name=%27vsys1%27]/address/entry[@name=%27web-server%27]&element=<ip-netmask>10.1.1.100/32</ip-netmask>'

# Service object
curl -k -X POST 'https://<fw>/api/?type=config&action=set&key=<APIKEY>&xpath=/config/devices/entry[@name=%27localhost.localdomain%27]/vsys/entry[@name=%27vsys1%27]/service/entry[@name=%27tcp-8443%27]&element=<protocol><tcp><port>8443</port></tcp></protocol>'

# Security policy rule
curl -k -X POST 'https://<fw>/api/?type=config&action=set&key=<APIKEY>&xpath=/config/devices/entry[@name=%27localhost.localdomain%27]/vsys/entry[@name=%27vsys1%27]/rulebase/security/rules/entry[@name=%27Allow-Web%27]&element=<from><member>trust</member></from><to><member>untrust</member></to><source><member>any</member></source><destination><member>web-server</member></destination><application><member>web-browsing</member></application><service><member>tcp-8443</member></service><action>allow</action><profile-setting><group><member>Strict-Profiles</member></group></profile-setting>'
```

**Minimal working example — CLI `set` form** (equivalent):

```
# configure
set address web-server ip-netmask 10.1.1.100/32
set service tcp-8443 protocol tcp port 8443
set rulebase security rules Allow-Web from trust to untrust source any destination web-server application web-browsing service tcp-8443 action allow
set rulebase security rules Allow-Web profile-setting group Strict-Profiles
set rulebase security rules Allow-Web log-end yes
commit
```

**Paid/authenticated access.** The format itself is fully public. Applying it requires administrative credentials on the firewall or Panorama (an API key generated from an admin account, or CLI login); no separate paid portal beyond the device.

**Doc link:** XML API configuration reference — https://docs.paloaltonetworks.com/ngfw/api/pan-os-xml-api-request-types-and-actions/configuration-api ; PAN-OS XML/REST API getting-started reference — https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-panorama-api/get-started-with-the-pan-os-xml-api

### 3. SentinelOne (S1) EDR — STAR custom detection rules

**Format & where it lives.** A STAR (Storyline Active Response) rule is a JSON object created through the SentinelOne Management Console API at `POST /web/api/v2.1/cloud-detection/rules`, authenticated with an `Authorization: ApiToken <token>` header and `Content-Type: application/json`. The detection logic is a Deep Visibility / Singularity Data Lake S1QL query carried in the `s1ql` field, with `queryType` (`events`) and `queryLang` (`"1.0"` or `"2.0"`). Core fields: `name`, `description`, `severity` (`Low`/`Medium`/`High`/`Critical`), `expirationMode` (`Permanent`/`Temporary`) with an `expiration` ISO-8601 timestamp when temporary, `networkQuarantine` (boolean response action), and `treatAsThreat` (`Malicious`/`Suspicious`/`UNDEFINED` — where `UNDEFINED` is alert-only and the Malicious/Suspicious values drive the mitigating "mark as threat" action, including process kill and quarantine per the agent's policy). Scope is set through a `filter` object using `accountIds`, `siteIds`, and/or `groupIds`. These fields map 1:1 to the arguments of the `sentinelone-create-star-rule` command in the Cortex XSOAR SentinelOne v2 integration, which wraps the underlying v2.1 API.

**Minimal working example** (STAR rule detecting a successful outbound network connection to FTP, alert-only, scoped to a site):

```json
POST /web/api/v2.1/cloud-detection/rules
Authorization: ApiToken <YOUR_API_TOKEN>
Content-Type: application/json

{
  "data": {
    "name": "Detect Outbound FTP Data Exfil",
    "description": "Alerts on successful outbound network connections to FTP (port 21).",
    "severity": "Medium",
    "queryType": "events",
    "queryLang": "2.0",
    "s1ql": "EventType = 'IP Connect' AND DstPort = 21 AND ConnectionStatus = 'SUCCESS'",
    "expirationMode": "Permanent",
    "networkQuarantine": false,
    "treatAsThreat": "UNDEFINED"
  },
  "filter": {
    "siteIds": ["225494730938493804"]
  }
}
```

(A process-behavior variant swaps the query, e.g. `"s1ql": "EventType = 'Process Creation' AND SrcProcName ContainsCIS 'powershell' AND SrcProcCmdLine ContainsCIS '-enc'"`, with `"treatAsThreat": "Malicious"` and `"networkQuarantine": true` to enable kill/quarantine.)

**Paid/authenticated access.** Yes — and more restricted than the other two. STAR custom rules are supported only in cloud-hosted SentinelOne environments. Per Elastic's official SentinelOne integration docs: "STAR Custom Rules are supported in Cloud environments, but are not supported in on-premises environments. Because of this, the alert data stream is not supported in on-premises environments." The rationale, per SentinelOne support in elastic/integrations GitHub Issue #11015, is that "Custom Rules are based on Deep Visibility™ queries, and a completely On-Prem Deep Visibility™ server is not available, [so] the endpoint https://<console_name>/web/api/v2.1/cloud-detection/alerts will not function as expected in an On-Premise console setup." Creating them requires an authenticated management console with a valid API token (generated per user/service user in the console) and the appropriate entitlement (Singularity Complete / CWPP); scopes without the entitlement return, verbatim, `status code 403: {"errors":[{"code":4030010,"detail":"This scope does not have Custom Rules enabled.","title":"Insufficient permissions"}]}`. The authoritative v2.1 API reference is only reachable when logged into the licensed console (`https://<your-console>.sentinelone.net/api-doc/`), so the exact request schema cannot be obtained from public docs alone — the field names above are corroborated from the Cortex XSOAR integration reference and SentinelOne's own STAR materials rather than a public API page.

**Doc link:** Cortex XSOAR SentinelOne v2 integration reference (documents the `sentinelone-create-star-rule` fields and the underlying v2.1 API) — https://xsoar.pan.dev/docs/reference/integrations/sentinel-one-v2 ; SentinelOne STAR overview — https://www.sentinelone.com/blog/customize-your-edr-to-adapt-to-your-environment-with-sentinelone-storyline-active-response-star/

## Recommendations
- **Akamai:** Emit the `conditions[]` JSON and manage the rule action separately via the security-policy custom-rule-action endpoint. Author and validate against a cloned (inactive) configuration version, deploy to staging first, then activate to production. Store EdgeGrid credentials in `.edgerc`. Threshold to change approach: if you need rate-limiting rather than allow/deny/alert, use rate-policy resources instead of custom rules.
- **Palo Alto:** Generate the CLI `set` form for human-reviewable change sets and the XML API form for automation; they are interchangeable. Always create referenced address/service objects before the rule and finish with a `commit`. For multi-firewall fleets, target Panorama device groups (pre-rulebase XPath) instead of a single vsys.
- **SentinelOne:** Because the authoritative schema is console-gated, validate generated payloads against a live tenant's `/api-doc/` before shipping, and treat the field names here as high-confidence-but-verify. Gate the feature to cloud tenants only and handle the `403` (code `4030010`) entitlement error explicitly. Default `treatAsThreat` to `UNDEFINED` (alert-only) in generated rules and require an explicit opt-in for `networkQuarantine`/kill actions.
- **Cross-cutting:** For all three, generate to an inactive/candidate state and require an explicit activation/commit step so artifacts can be reviewed before they affect live traffic.

## Caveats
- Akamai custom rules affect all inactive versions of a security configuration when edited but not already-activated versions; rolling back means re-activating a prior version.
- The Akamai example's `argsPostXMLMatch`/`requestHeaderValueMatch` condition types and flags are drawn from the published condition-type list and a real-world published rule; confirm exact flag support for your rule format version, as available condition types evolve.
- PAN-OS XPaths shown use the default `localhost.localdomain`/`vsys1`; multi-vsys or Panorama-managed firewalls use different XPaths (e.g. `pre-rulebase`). URL-encode XPath special characters as shown.
- SentinelOne: the literal endpoint path and the `{"data":..., "filter":...}` envelope are inferred from the confirmed `/web/api/v2.1/cloud-detection/` base and the documented command mapping; the exact JSON envelope should be confirmed against an authenticated console. SentinelOne is deprecating legacy Deep Visibility and S1QL 1.0: per its deprecation notice (published Feb 13, 2026), "Starting February 15, 2026, you can create new custom detection rules only using S1QL 2.0. All existing S1QL 1.0 custom detection rules will be automatically migrated to S1QL 2.0," and "If you use Legacy Deep Visibility APIs (or legacy UI features that depend on them), you must migrate before February 15, 2027 to avoid disruption."