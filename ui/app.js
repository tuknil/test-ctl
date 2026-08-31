const PATTERN_TO_CLASS = {
  "proven-pattern:CVE-2017-5638:waf:fixture-1": {
    vulnerability_id: "CVE-2017-5638",
    selected_control_class: "waf",
    discriminator_id: "discriminator:CVE-2017-5638:content-type-ognl",
    discriminator_description:
      "Blocks suspicious OGNL expression syntax in the HTTP Content-Type header used by attacks against the Apache Struts Jakarta Multipart parser.",
    pattern_summary:
      "Reject requests whose Content-Type header contains OGNL expression markers associated with CVE-2017-5638. This is a compensating control; upgrade Apache Struts to a fixed version.",
    proof_record_ids: [
      "mitigation-check-result:CVE-2017-5638:waf:fixture-1",
      "bypass-validation-result:CVE-2017-5638:waf:fixture-1",
    ],
  },
  "proven-pattern:CVE-2021-44228:waf:fixture-1": {
    vulnerability_id: "CVE-2021-44228",
    selected_control_class: "waf",
    discriminator_id: "discriminator:CVE-2021-44228:jndi-user-agent",
    discriminator_description:
      "Blocks JNDI lookup syntax such as '${jndi:' in the HTTP User-Agent header before it reaches an application using vulnerable Log4j Core.",
    pattern_summary:
      "Reject User-Agent values containing direct JNDI lookup syntax associated with Log4Shell. This is a narrow compensating control; upgrade Log4j.",
    proof_record_ids: [
      "mitigation-check-result:CVE-2021-44228:waf:fixture-1",
      "bypass-validation-result:CVE-2021-44228:waf:fixture-1",
    ],
  },
  "proven-pattern:CVE-2021-44228:edr:fixture-1": {
    vulnerability_id: "CVE-2021-44228",
    selected_control_class: "edr",
    discriminator_id: "discriminator:CVE-2021-44228:java-child-process",
    discriminator_description:
      "Detects a Java process spawning a command shell or download utility, a practical post-exploitation process-chain signal for Log4Shell.",
    pattern_summary:
      "Alert when Java launches a shell, PowerShell, curl, wget, or certutil. This detection is not vulnerability remediation; upgrade Log4j.",
    proof_record_ids: [
      "mitigation-check-result:CVE-2021-44228:edr:fixture-1",
      "bypass-validation-result:CVE-2021-44228:edr:fixture-1",
    ],
  },
  "proven-pattern:CVE-2023-27997:firewall:fixture-1": {
    vulnerability_id: "CVE-2023-27997",
    selected_control_class: "firewall",
    discriminator_id: "discriminator:CVE-2023-27997:ssl-vpn-exposure",
    discriminator_description:
      "Blocks inbound network connections from the untrusted zone to an affected FortiOS SSL-VPN gateway on TCP/443.",
    pattern_summary:
      "Temporarily isolate an affected FortiOS SSL-VPN listener from untrusted networks while applying Fortinet updates. This control interrupts VPN access.",
    proof_record_ids: [
      "mitigation-check-result:CVE-2023-27997:firewall:fixture-1",
      "bypass-validation-result:CVE-2023-27997:firewall:fixture-1",
    ],
  },
  "proven-pattern:CVE-EXAMPLE:waf:3": {
    vulnerability_id: "CVE-EXAMPLE",
    selected_control_class: "waf",
    discriminator_id: "discriminator:CVE-EXAMPLE:cmd-param",
    discriminator_description:
      "Blocks OGNL/EL expression syntax appearing in the Content-Type header.",
    pattern_summary:
      "Block requests whose Content-Type header contains OGNL/EL expression syntax.",
    proof_record_ids: [
      "mitigation-check-result:CVE-EXAMPLE:3",
      "bypass-validation-result:CVE-EXAMPLE:3",
    ],
  },
  "proven-pattern:CVE-EXAMPLE:firewall:1": {
    vulnerability_id: "CVE-EXAMPLE",
    selected_control_class: "firewall",
    discriminator_id: "discriminator:CVE-EXAMPLE:mgmt-port",
    discriminator_description:
      "Blocks inbound connections to the exposed management port from untrusted networks.",
    pattern_summary:
      "Deny inbound traffic to TCP/8443 (management interface) except from the trusted admin subnet.",
    proof_record_ids: [
      "mitigation-check-result:CVE-EXAMPLE:1",
      "bypass-validation-result:CVE-EXAMPLE:1",
    ],
  },
  "proven-pattern:CVE-EXAMPLE:edr:1": {
    vulnerability_id: "CVE-EXAMPLE",
    selected_control_class: "edr",
    discriminator_id: "discriminator:CVE-EXAMPLE:proc-tree",
    discriminator_description:
      "Flags a child process spawn chain unique to the exploit (web-server -> shell -> outbound network).",
    pattern_summary:
      "Detect and block the web-server-to-shell-to-network process spawn chain associated with the exploit.",
    proof_record_ids: [
      "mitigation-check-result:CVE-EXAMPLE:2",
      "bypass-validation-result:CVE-EXAMPLE:2",
    ],
  },
};

const resultEl = document.getElementById("result");
const submitBtn = document.getElementById("submit");
const patternSelect = document.getElementById("pattern");
const targetSelect = document.getElementById("target");
const contextSelect = document.getElementById("context");
const formExplanation = document.getElementById("formExplanation");
const inferenceStatusEl = document.getElementById("inferenceStatus");
const inferenceModeSelect = document.getElementById("inferenceMode");
const copyInferenceConfigBtn = document.getElementById("copyInferenceConfig");
const inferenceSwitchHelp = document.getElementById("inferenceSwitchHelp");

let inferenceRuntime = null;

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function renderInferenceStatus(runtime) {
  inferenceRuntime = runtime;
  const live = runtime.execution_mode === "live";
  inferenceStatusEl.className = live ? "inference-live" : "inference-fixture";
  inferenceStatusEl.innerHTML = `<strong>${live ? "Live LLM enabled" : "Fixture mode"}</strong> · Provider: <code>${escapeHtml(runtime.provider)}</code> · Model: <code>${escapeHtml(runtime.model)}</code>${live && !runtime.credentials_configured ? " · credentials missing" : ""}`;
  inferenceModeSelect.value = runtime.provider === "att-inference" && live ? "att-inference" : "fixture";
  updateInferenceSwitchHelp();
}

function updateInferenceSwitchHelp() {
  const selected = inferenceModeSelect.value;
  if (selected === "att-inference") {
    inferenceSwitchHelp.textContent = "To switch safely, copy the configuration, add the AT&T base URL and API key to .env, then restart the service. Browser controls never receive or save credentials.";
  } else {
    inferenceSwitchHelp.textContent = "Fixture mode is deterministic and makes no LLM call. Copy the configuration and restart the service to switch back.";
  }
}

async function loadInferenceStatus() {
  try {
    const response = await fetch("/inference");
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    renderInferenceStatus(await response.json());
  } catch (error) {
    inferenceStatusEl.textContent = `Unable to load inference status: ${String(error)}`;
  }
}

inferenceModeSelect.addEventListener("change", updateInferenceSwitchHelp);
copyInferenceConfigBtn.addEventListener("click", async () => {
  const config = inferenceModeSelect.value === "att-inference"
    ? "RUN_MODE=live\nMODEL_PROVIDER=att-inference\nMODEL_NAME=<ATT_INFERENCE_MODEL_ID>\nATT_INFERENCE_BASE_URL=<ATT_INFERENCE_OPENAI_COMPATIBLE_BASE_URL>\nATT_INFERENCE_API_KEY=<SET_IN_YOUR_SECRET_STORE>"
    : "RUN_MODE=fixture\nMODEL_PROVIDER=openai\nMODEL_NAME=gpt-4o-mini";
  try {
    await navigator.clipboard.writeText(config);
    copyInferenceConfigBtn.textContent = "Configuration copied";
  } catch (_) {
    copyInferenceConfigBtn.textContent = "Copy unavailable";
  }
  setTimeout(() => { copyInferenceConfigBtn.textContent = "Copy configuration"; }, 1800);
});

loadInferenceStatus();

const PATTERN_EXPLANATIONS = {
  "proven-pattern:CVE-2017-5638:waf:fixture-1": {
    title: "Apache Struts remote-code-execution virtual patch",
    translation: "Akamai WAF rule that inspects Content-Type for OGNL expression markers.",
    expected: "translated",
    caveat: "Compensating control only. Upgrade Apache Struts to a fixed release.",
    target: "akamai-waf",
    context: "akamai-policy:example:rev-17",
  },
  "proven-pattern:CVE-2021-44228:waf:fixture-1": {
    title: "Log4Shell request-layer virtual patch",
    translation: "Akamai WAF rule that rejects direct ${jndi: syntax in User-Agent.",
    expected: "translated (narrower)",
    caveat: "Encoded variants and other headers may bypass this narrow match. Upgrade Log4j.",
    target: "akamai-waf",
    context: "akamai-policy:example:rev-17",
  },
  "proven-pattern:CVE-2021-44228:edr:fixture-1": {
    title: "Log4Shell post-exploitation behavior detection",
    translation: "SentinelOne query that alerts when Java starts a shell or download utility.",
    expected: "translated",
    caveat: "This detects behavior, not the vulnerability itself, and may produce false positives. Upgrade Log4j.",
    target: "edr-s1",
    context: "edr-policy:example:rev-1",
  },
  "proven-pattern:CVE-2023-27997:firewall:fixture-1": {
    title: "FortiOS SSL-VPN emergency isolation",
    translation: "Firewall rule denying untrusted inbound TCP/443 to the SSL-VPN gateway.",
    expected: "translated",
    caveat: "This interrupts remote-access VPN service. Apply the Fortinet update as the authoritative fix.",
    target: "firewall-generic",
    context: "firewall-policy:dmz:rev-1",
  },
  "proven-pattern:CVE-EXAMPLE:waf:3": {
    title: "Synthetic WAF translation example",
    translation: "Akamai WAF rule matching OGNL/EL markers in Content-Type.",
    expected: "translated",
    caveat: "Synthetic fixture for demonstrating the successful WAF path.",
    target: "akamai-waf",
    context: "akamai-policy:example:rev-17",
  },
  "proven-pattern:CVE-EXAMPLE:firewall:1": {
    title: "Synthetic firewall conflict example",
    translation: "Firewall deny rule for an exposed management service on TCP/8443.",
    expected: "scope-declined",
    caveat: "The example policy snapshot contains a conflicting allow rule.",
    target: "firewall-generic",
    context: "firewall-policy:example:rev-4",
  },
  "proven-pattern:CVE-EXAMPLE:edr:1": {
    title: "Synthetic EDR process-chain example",
    translation: "SentinelOne query detecting a web server spawning a command shell.",
    expected: "translated",
    caveat: "Alert-only fixture; an analyst must validate the event.",
    target: "edr-s1",
    context: "edr-policy:example:rev-1",
  },
};

function renderSelectionExplanation(container, info, target, context, controlClass = "control") {
  container.textContent = "";

  if (!info) {
    const p = document.createElement("p");
    p.textContent = "Select an example to see what it demonstrates.";
    container.appendChild(p);
    return;
  }

  const targetMismatch = target && target !== info.target;
  const contextMismatch = context && context !== info.context;
  const mismatch = targetMismatch || contextMismatch;

  const h3 = document.createElement("h3");
  h3.textContent = "What this selection demonstrates";
  container.appendChild(h3);

  const titleP = document.createElement("p");
  const titleStrong = document.createElement("strong");
  titleStrong.textContent = info.title;
  titleP.appendChild(titleStrong);
  container.appendChild(titleP);

  const generatedP = document.createElement("p");
  const generatedStrong = document.createElement("strong");
  generatedStrong.textContent = "Generated control:";
  generatedP.appendChild(generatedStrong);
  generatedP.appendChild(document.createTextNode(" " + info.translation));
  container.appendChild(generatedP);

  const expectedP = document.createElement("p");
  const expectedStrong = document.createElement("strong");
  expectedStrong.textContent = "Expected result:";
  expectedP.appendChild(expectedStrong);
  expectedP.appendChild(document.createTextNode(" "));
  const expectedSpan = document.createElement("span");
  expectedSpan.className = `state ${info.expected.split(" ")[0]}`;
  expectedSpan.textContent = info.expected;
  expectedP.appendChild(expectedSpan);
  container.appendChild(expectedP);

  const whyP = document.createElement("p");
  const whyStrong = document.createElement("strong");
  whyStrong.textContent = "Why this target:";
  whyP.appendChild(whyStrong);
  whyP.appendChild(document.createTextNode(" "));
  const targetCode = document.createElement("code");
  targetCode.textContent = info.target;
  whyP.appendChild(targetCode);
  whyP.appendChild(document.createTextNode(" can express the selected "));
  const controlCode = document.createElement("code");
  controlCode.textContent = controlClass;
  whyP.appendChild(controlCode);
  whyP.appendChild(document.createTextNode(" pattern."));
  container.appendChild(whyP);

  const policyP = document.createElement("p");
  const policyStrong = document.createElement("strong");
  policyStrong.textContent = "Policy snapshot:";
  policyP.appendChild(policyStrong);
  policyP.appendChild(document.createTextNode(" "));
  const contextCode = document.createElement("code");
  contextCode.textContent = context || info.context;
  policyP.appendChild(contextCode);
  policyP.appendChild(document.createTextNode(" is read to check for obvious conflicts."));
  container.appendChild(policyP);

  const importantP = document.createElement("p");
  importantP.className = "selection-warning";
  const importantStrong = document.createElement("strong");
  importantStrong.textContent = "Important:";
  importantP.appendChild(importantStrong);
  importantP.appendChild(document.createTextNode(" " + info.caveat));
  container.appendChild(importantP);

  if (mismatch) {
    const mismatchP = document.createElement("p");
    mismatchP.className = "selection-warning";
    const mismatchStrong = document.createElement("strong");
    mismatchStrong.textContent = "Selection mismatch:";
    mismatchP.appendChild(mismatchStrong);
    mismatchP.appendChild(
      document.createTextNode(
        " The target or policy context differs from the recommended values. The request may be declined or lack context.",
      ),
    );
    container.appendChild(mismatchP);
  }
}

function updateFormExplanation({ syncTarget = false } = {}) {
  const info = PATTERN_EXPLANATIONS[patternSelect.value];
  if (syncTarget && info) {
    targetSelect.value = info.target;
    contextSelect.value = info.context;
  }
  renderSelectionExplanation(
    formExplanation,
    info,
    targetSelect.value,
    contextSelect.value,
    PATTERN_TO_CLASS[patternSelect.value]?.selected_control_class,
  );
}

patternSelect.addEventListener("change", () => updateFormExplanation({ syncTarget: true }));
targetSelect.addEventListener("change", () => updateFormExplanation());
contextSelect.addEventListener("change", () => updateFormExplanation());
updateFormExplanation();

function badgeClass(state) {
  return state || "unknown";
}

function renderResult(envelope) {
  const r = envelope.structured_result;
  const candidate = r.primary_candidate;
  const inference = envelope.inference || inferenceRuntime;

  const inferenceHtml = inference ? `
    <section class="inference-result">
      <strong>Inference evidence</strong>
      <p>Mode: <code>${escapeHtml(inference.execution_mode)}</code> · Provider: <code>${escapeHtml(inference.provider)}</code> · Model: <code>${escapeHtml(inference.model)}</code></p>
      <p><strong>LLM invoked for this request: ${inference.llm_invoked ? "yes" : "no"}</strong>${inference.llm_invoked ? " — the request reached the live translation agent." : " — this was a fixture run or the request ended before model invocation."}</p>
    </section>` : "";

  let candidateHtml = '<p class="empty">No candidate produced.</p>';
  if (candidate) {
    candidateHtml = `
      <div class="kv">
        <dt>Candidate id</dt><dd>${candidate.candidate_id}</dd>
        <dt>Artifact type</dt><dd>${candidate.candidate_artifact.artifact_type}</dd>
        <dt>Translation</dt><dd>${candidate.implements_discriminator.translation}</dd>
      </div>
      <label>Candidate artifact</label>
      <pre>${candidate.candidate_artifact.content_ref}</pre>
      <label>Justification</label>
      <p>${candidate.implements_discriminator.justification}</p>
      ${
        candidate.translation_assumptions.length
          ? `<label>Assumptions</label><ul class="compact">${candidate.translation_assumptions
              .map((a) => `<li>${a}</li>`)
              .join("")}</ul>`
          : ""
      }
      ${
        candidate.limitations.length
          ? `<label>Limitations</label><ul class="compact">${candidate.limitations
              .map((l) => `<li>${l}</li>`)
              .join("")}</ul>`
          : ""
      }
      ${
        candidate.placement.conflict_notes.length
          ? `<label>Conflicts</label><ul class="compact">${candidate.placement.conflict_notes
              .map((c) => `<li>${c}</li>`)
              .join("")}</ul>`
          : ""
      }
    `;
  }

  resultEl.innerHTML = `
    <h2>Result <span class="badge ${badgeClass(r.terminal_state)}">${r.terminal_state}</span></h2>
    <div class="kv">
      <dt>Run id</dt><dd>${envelope.run_id}</dd>
      <dt>Status</dt><dd>${envelope.status}</dd>
      <dt>Vulnerability</dt><dd>${r.subject.vulnerability_id}</dd>
      <dt>Target technology</dt><dd>${r.input_bindings.target_technology}</dd>
      <dt>Outcome reason</dt><dd>${r.outcome_reason.code}</dd>
    </div>
    <label>Prose summary</label>
    <p>${r.prose_summary}</p>
    <label>Outcome detail</label>
    <p>${r.outcome_reason.detail}</p>
    ${inferenceHtml}
    <h3>Candidate</h3>
    ${candidateHtml}
  `;
}

function renderError(message) {
  resultEl.innerHTML = `<p class="empty">Error: ${message}</p>`;
}

submitBtn.addEventListener("click", async () => {
  submitBtn.disabled = true;
  submitBtn.textContent = "Translating...";
  resultEl.innerHTML = '<p class="empty">Working...</p>';

  const patternId = patternSelect.value;
  const targetTechnology = targetSelect.value;
  const contextId = contextSelect.value;
  const pattern = PATTERN_TO_CLASS[patternId];

  const body = {
    input: {
      proven_pattern: {
        proven_pattern_id: patternId,
        ...pattern,
      },
      target_context: {
        target_technology: targetTechnology,
        target_policy_context_id: contextId,
      },
    },
  };

  try {
    const resp = await fetch("/invoke", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await resp.json();
    if (!resp.ok) {
      renderError(JSON.stringify(data));
    } else {
      renderResult(data);
      loadRuns(0);
    }
  } catch (err) {
    renderError(String(err));
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = "Translate";
  }
});

// JSON Mode functionality
const formModeBtn = document.getElementById("formModeBtn");
const jsonModeBtn = document.getElementById("jsonModeBtn");
const formPanel = document.querySelector(".panel:not(.json-input-panel):not(.result-card):not(.json-output-panel)");
const jsonInputPanel = document.getElementById("jsonInputPanel");
const jsonOutputPanel = document.getElementById("jsonOutputPanel");
const jsonInput = document.getElementById("jsonInput");
const jsonOutput = document.getElementById("jsonOutput");
const submitJsonBtn = document.getElementById("submitJson");
const copyJsonBtn = document.getElementById("copyJson");
const jsonExplanation = document.getElementById("jsonExplanation");

// Example JSON templates
const EXAMPLE_JSONS = {
  "cve-2017-5638-akamai": {
    input: {
      proven_pattern: {
        proven_pattern_id: "proven-pattern:CVE-2017-5638:waf:fixture-1",
        vulnerability_id: "CVE-2017-5638",
        selected_control_class: "waf",
        discriminator_id: "discriminator:CVE-2017-5638:content-type-ognl",
        discriminator_description: "Blocks suspicious OGNL expression syntax in the HTTP Content-Type header used by attacks against the Apache Struts Jakarta Multipart parser.",
        pattern_summary: "Reject requests whose Content-Type header contains OGNL expression markers associated with CVE-2017-5638. This is a compensating control; upgrade Apache Struts to a fixed version.",
        proof_record_ids: [
          "mitigation-check-result:CVE-2017-5638:waf:fixture-1",
          "bypass-validation-result:CVE-2017-5638:waf:fixture-1"
        ]
      },
      target_context: {
        target_technology: "akamai-waf",
        target_policy_context_id: "akamai-policy:example:rev-17"
      }
    }
  },
  "cve-2021-44228-akamai": {
    input: {
      proven_pattern: {
        proven_pattern_id: "proven-pattern:CVE-2021-44228:waf:fixture-1",
        vulnerability_id: "CVE-2021-44228",
        selected_control_class: "waf",
        discriminator_id: "discriminator:CVE-2021-44228:jndi-user-agent",
        discriminator_description: "Blocks JNDI lookup syntax such as '${jndi:' in the HTTP User-Agent header before it reaches an application using vulnerable Log4j Core.",
        pattern_summary: "Reject User-Agent values containing direct JNDI lookup syntax associated with Log4Shell. This is a narrow compensating control; upgrade Log4j.",
        proof_record_ids: [
          "mitigation-check-result:CVE-2021-44228:waf:fixture-1",
          "bypass-validation-result:CVE-2021-44228:waf:fixture-1"
        ]
      },
      target_context: {
        target_technology: "akamai-waf",
        target_policy_context_id: "akamai-policy:example:rev-17"
      }
    }
  },
  "cve-2021-44228-edr": {
    input: {
      proven_pattern: {
        proven_pattern_id: "proven-pattern:CVE-2021-44228:edr:fixture-1",
        vulnerability_id: "CVE-2021-44228",
        selected_control_class: "edr",
        discriminator_id: "discriminator:CVE-2021-44228:java-child-process",
        discriminator_description: "Detects a Java process spawning a command shell or download utility, a practical post-exploitation process-chain signal for Log4Shell.",
        pattern_summary: "Alert when Java launches a shell, PowerShell, curl, wget, or certutil. This detection is not vulnerability remediation; upgrade Log4j.",
        proof_record_ids: [
          "mitigation-check-result:CVE-2021-44228:edr:fixture-1",
          "bypass-validation-result:CVE-2021-44228:edr:fixture-1"
        ]
      },
      target_context: {
        target_technology: "edr-s1",
        target_policy_context_id: "edr-policy:example:rev-1"
      }
    }
  },
  "cve-2023-27997-firewall": {
    input: {
      proven_pattern: {
        proven_pattern_id: "proven-pattern:CVE-2023-27997:firewall:fixture-1",
        vulnerability_id: "CVE-2023-27997",
        selected_control_class: "firewall",
        discriminator_id: "discriminator:CVE-2023-27997:ssl-vpn-exposure",
        discriminator_description: "Blocks inbound network connections from the untrusted zone to an affected FortiOS SSL-VPN gateway on TCP/443.",
        pattern_summary: "Temporarily isolate an affected FortiOS SSL-VPN listener from untrusted networks while applying Fortinet updates. This control interrupts VPN access.",
        proof_record_ids: [
          "mitigation-check-result:CVE-2023-27997:firewall:fixture-1",
          "bypass-validation-result:CVE-2023-27997:firewall:fixture-1"
        ]
      },
      target_context: {
        target_technology: "firewall-generic",
        target_policy_context_id: "firewall-policy:dmz:rev-1"
      }
    }
  },
  "waf-translated": {
    input: {
      proven_pattern: {
        proven_pattern_id: "proven-pattern:CVE-EXAMPLE:waf:3",
        vulnerability_id: "CVE-EXAMPLE",
        selected_control_class: "waf",
        discriminator_id: "discriminator:CVE-EXAMPLE:cmd-param",
        discriminator_description: "Blocks OGNL/EL expression syntax appearing in the Content-Type header.",
        pattern_summary: "Block requests whose Content-Type header contains OGNL/EL expression syntax.",
        proof_record_ids: [
          "mitigation-check-result:CVE-EXAMPLE:3",
          "bypass-validation-result:CVE-EXAMPLE:3"
        ]
      },
      target_context: {
        target_technology: "akamai-waf",
        target_policy_context_id: "akamai-policy:example:rev-17"
      }
    }
  },
  "firewall-conflict": {
    input: {
      proven_pattern: {
        proven_pattern_id: "proven-pattern:CVE-EXAMPLE:firewall:1",
        vulnerability_id: "CVE-EXAMPLE",
        selected_control_class: "firewall",
        discriminator_id: "discriminator:CVE-EXAMPLE:mgmt-port",
        discriminator_description: "Blocks inbound connections to the exposed management port from untrusted networks.",
        pattern_summary: "Deny inbound traffic to TCP/8443 (management interface) except from the trusted admin subnet.",
        proof_record_ids: [
          "mitigation-check-result:CVE-EXAMPLE:1",
          "bypass-validation-result:CVE-EXAMPLE:1"
        ]
      },
      target_context: {
        target_technology: "firewall-generic",
        target_policy_context_id: "firewall-policy:example:rev-4"
      }
    }
  },
  "edr-stub": {
    input: {
      proven_pattern: {
        proven_pattern_id: "proven-pattern:CVE-EXAMPLE:edr:1",
        vulnerability_id: "CVE-EXAMPLE",
        selected_control_class: "edr",
        discriminator_id: "discriminator:CVE-EXAMPLE:proc-tree",
        discriminator_description: "Flags a child process spawn chain unique to the exploit (web-server -> shell -> outbound network).",
        pattern_summary: "Detect and block the web-server-to-shell-to-network process spawn chain associated with the exploit.",
        proof_record_ids: [
          "mitigation-check-result:CVE-EXAMPLE:2",
          "bypass-validation-result:CVE-EXAMPLE:2"
        ]
      },
      target_context: {
        target_technology: "edr-s1",
        target_policy_context_id: "edr-policy:example:rev-1"
      }
    }
  },
  "missing-context": {
    input: {
      proven_pattern: {
        proven_pattern_id: "proven-pattern:CVE-EXAMPLE:waf:3",
        vulnerability_id: "CVE-EXAMPLE",
        selected_control_class: "waf",
        discriminator_id: "discriminator:CVE-EXAMPLE:cmd-param",
        discriminator_description: "Blocks OGNL/EL expression syntax appearing in the Content-Type header.",
        pattern_summary: "Block requests whose Content-Type header contains OGNL/EL expression syntax.",
        proof_record_ids: [
          "mitigation-check-result:CVE-EXAMPLE:3",
          "bypass-validation-result:CVE-EXAMPLE:3"
        ]
      },
      target_context: {
        target_technology: "akamai-waf",
        target_policy_context_id: "unknown-context:none"
      }
    }
  },
  "unsupported-tech": {
    input: {
      proven_pattern: {
        proven_pattern_id: "proven-pattern:CVE-EXAMPLE:waf:3",
        vulnerability_id: "CVE-EXAMPLE",
        selected_control_class: "waf",
        discriminator_id: "discriminator:CVE-EXAMPLE:cmd-param",
        discriminator_description: "Blocks OGNL/EL expression syntax appearing in the Content-Type header.",
        pattern_summary: "Block requests whose Content-Type header contains OGNL/EL expression syntax.",
        proof_record_ids: [
          "mitigation-check-result:CVE-EXAMPLE:3",
          "bypass-validation-result:CVE-EXAMPLE:3"
        ]
      },
      target_context: {
        target_technology: "unsupported-xyz",
        target_policy_context_id: "some-policy:1"
      }
    }
  }
};

const exampleSelect = document.getElementById("exampleSelect");
jsonInput.value = JSON.stringify(EXAMPLE_JSONS["cve-2017-5638-akamai"], null, 2);

function updateJsonExplanation(key) {
  const request = EXAMPLE_JSONS[key];
  if (!request) {
    renderSelectionExplanation(jsonExplanation, null);
    return;
  }
  const patternId = request.input.proven_pattern.proven_pattern_id;
  const terminalStateOverrides = {
    "firewall-conflict": {
      expected: "scope-declined",
      caveat: "This request intentionally conflicts with an existing allow rule in the fixture policy.",
    },
    "missing-context": {
      expected: "insufficient-context",
      caveat: "The unknown policy ID intentionally has no snapshot, so conflict checking cannot continue.",
    },
    "unsupported-tech": {
      expected: "scope-declined",
      caveat: "The fake target technology is intentionally outside this service's supported scope.",
    },
  };
  const baseInfo = PATTERN_EXPLANATIONS[patternId];
  const info = baseInfo ? {
    ...baseInfo,
    ...(terminalStateOverrides[key] || {}),
  } : {
    title: "Terminal-state demonstration",
    translation: request.input.proven_pattern.pattern_summary,
    expected: key === "missing-context" ? "insufficient-context" : "scope-declined",
    caveat: "This request intentionally demonstrates a non-success terminal state.",
    target: request.input.target_context.target_technology,
    context: request.input.target_context.target_policy_context_id,
  };
  renderSelectionExplanation(
    jsonExplanation,
    info,
    request.input.target_context.target_technology,
    request.input.target_context.target_policy_context_id,
    request.input.proven_pattern.selected_control_class,
  );
}

updateJsonExplanation("cve-2017-5638-akamai");

exampleSelect.addEventListener("change", () => {
  const key = exampleSelect.value;
  if (key && EXAMPLE_JSONS[key]) {
    jsonInput.value = JSON.stringify(EXAMPLE_JSONS[key], null, 2);
  }
  updateJsonExplanation(key);
});

let lastResponseJson = null;

formModeBtn.addEventListener("click", () => {
  formModeBtn.classList.add("active");
  jsonModeBtn.classList.remove("active");
  formPanel.style.display = "block";
  jsonInputPanel.style.display = "none";
  resultEl.style.display = "block";
  jsonOutputPanel.style.display = "none";
});

jsonModeBtn.addEventListener("click", () => {
  jsonModeBtn.classList.add("active");
  formModeBtn.classList.remove("active");
  formPanel.style.display = "none";
  jsonInputPanel.style.display = "block";
  resultEl.style.display = "none";
  jsonOutputPanel.style.display = "block";
});

submitJsonBtn.addEventListener("click", async () => {
  submitJsonBtn.disabled = true;
  submitJsonBtn.textContent = "Sending...";
  jsonOutput.textContent = "Working...";

  let body;
  try {
    body = JSON.parse(jsonInput.value);
  } catch (e) {
    jsonOutput.textContent = "Invalid JSON: " + e.message;
    submitJsonBtn.disabled = false;
    submitJsonBtn.textContent = "Send JSON";
    return;
  }

  try {
    const resp = await fetch("/invoke", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await resp.json();
    lastResponseJson = data;
    jsonOutput.textContent = JSON.stringify(data, null, 2);
    if (resp.ok) loadRuns(0);
  } catch (err) {
    jsonOutput.textContent = "Error: " + String(err);
    lastResponseJson = null;
  } finally {
    submitJsonBtn.disabled = false;
    submitJsonBtn.textContent = "Send JSON";
  }
});

copyJsonBtn.addEventListener("click", () => {
  if (lastResponseJson) {
    navigator.clipboard.writeText(JSON.stringify(lastResponseJson, null, 2));
    copyJsonBtn.textContent = "Copied!";
    setTimeout(() => { copyJsonBtn.textContent = "Copy JSON"; }, 1500);
  }
});

// Durable runs dashboard
const RUNS_PAGE_SIZE = 10;
const runsTableBody = document.getElementById("runsTableBody");
const runsStatus = document.getElementById("runsStatus");
const refreshRunsBtn = document.getElementById("refreshRuns");
const previousRunsBtn = document.getElementById("previousRuns");
const nextRunsBtn = document.getElementById("nextRuns");
const runsPageLabel = document.getElementById("runsPageLabel");
const runDetail = document.getElementById("runDetail");
const runDetailStatus = document.getElementById("runDetailStatus");
const runDetailMetadata = document.getElementById("runDetailMetadata");
const runDetailSummary = document.getElementById("runDetailSummary");
const runArtifactDetails = document.getElementById("runArtifactDetails");
const runArtifactContent = document.getElementById("runArtifactContent");
let runsOffset = 0;

function appendTextElement(parent, tagName, text, className = "") {
  const element = document.createElement(tagName);
  element.textContent = text;
  if (className) element.className = className;
  parent.appendChild(element);
  return element;
}

function formatTimestamp(value) {
  const timestamp = new Date(value);
  return Number.isNaN(timestamp.getTime()) ? value : timestamp.toLocaleString();
}

function setDashboardCounts(data) {
  const counts = data.terminal_state_counts || {};
  document.getElementById("runCountTotal").textContent = String(data.total);
  document.getElementById("runCountTranslated").textContent = String(counts.translated || 0);
  document.getElementById("runCountReview").textContent = String(
    (counts["scope-declined"] || 0) +
    (counts["insufficient-context"] || 0) +
    (counts["cannot-express"] || 0),
  );
  document.getElementById("runCountMalfunction").textContent = String(counts.malfunction || 0);
}

function renderRuns(data) {
  runsTableBody.replaceChildren();
  setDashboardCounts(data);

  if (data.items.length === 0) {
    runsStatus.textContent = data.total === 0
      ? "No stored runs yet. Submit a translation to create the first durable run."
      : "No runs are available on this page.";
  } else {
    runsStatus.textContent = `Showing ${data.offset + 1}–${data.offset + data.items.length} of ${data.total} stored runs.`;
  }

  data.items.forEach((run) => {
    const row = document.createElement("tr");
    appendTextElement(row, "td", formatTimestamp(run.completed_at));
    const vulnerabilityCell = appendTextElement(row, "td", "");
    appendTextElement(vulnerabilityCell, "code", run.vulnerability_id);
    appendTextElement(row, "td", run.target_technology);
    const stateCell = appendTextElement(row, "td", "");
    appendTextElement(stateCell, "span", run.terminal_state, `badge ${badgeClass(run.terminal_state)}`);
    appendTextElement(row, "td", run.artifact_type || "None");
    const actionCell = appendTextElement(row, "td", "");
    const button = appendTextElement(actionCell, "button", "View", "row-action secondary-btn");
    button.type = "button";
    button.setAttribute("aria-label", `View run ${run.run_id}`);
    button.addEventListener("click", () => loadRunDetail(run.run_id));
    runsTableBody.appendChild(row);
  });

  const currentPage = Math.floor(data.offset / data.limit) + 1;
  const totalPages = Math.max(1, Math.ceil(data.total / data.limit));
  runsPageLabel.textContent = `Page ${currentPage} of ${totalPages}`;
  previousRunsBtn.disabled = data.offset === 0;
  nextRunsBtn.disabled = !data.has_more;
}

async function loadRuns(offset = runsOffset) {
  runsOffset = Math.max(0, offset);
  refreshRunsBtn.disabled = true;
  runsStatus.textContent = "Loading stored runs…";
  try {
    const response = await fetch(`/v1/runs?limit=${RUNS_PAGE_SIZE}&offset=${runsOffset}`);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    renderRuns(await response.json());
  } catch (error) {
    runsTableBody.replaceChildren();
    runsStatus.textContent = `Unable to load stored runs: ${String(error)}`;
  } finally {
    refreshRunsBtn.disabled = false;
  }
}

function addMetadata(label, value) {
  appendTextElement(runDetailMetadata, "dt", label);
  appendTextElement(runDetailMetadata, "dd", value);
}

async function loadRunDetail(runId) {
  runDetail.hidden = false;
  runDetailStatus.textContent = "Loading translation details…";
  runDetailMetadata.replaceChildren();
  runDetailSummary.replaceChildren();
  runArtifactDetails.hidden = true;
  runArtifactContent.textContent = "";
  runDetail.scrollIntoView({ behavior: "smooth", block: "nearest" });

  try {
    const response = await fetch(`/runs/${encodeURIComponent(runId)}`);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const envelope = await response.json();
    const result = envelope.structured_result;
    const candidate = result.primary_candidate;
    runDetailStatus.textContent = "";
    addMetadata("Run ID", envelope.run_id);
    addMetadata("Result ID", envelope.result_id);
    addMetadata("Correlation ID", envelope.correlation_id);
    addMetadata("Terminal state", result.terminal_state);
    addMetadata("Vulnerability", result.subject.vulnerability_id);
    addMetadata("Target", result.input_bindings.target_technology);
    addMetadata("Outcome", result.outcome_reason.code);
    appendTextElement(runDetailSummary, "h4", "Translation summary");
    appendTextElement(runDetailSummary, "p", result.prose_summary);
    appendTextElement(runDetailSummary, "h4", "Outcome detail");
    appendTextElement(runDetailSummary, "p", result.outcome_reason.detail);
    if (candidate) {
      appendTextElement(runDetailSummary, "h4", "Candidate translation");
      appendTextElement(runDetailSummary, "p", candidate.implements_discriminator.translation);
      runArtifactContent.textContent = candidate.candidate_artifact.content_ref;
      runArtifactDetails.hidden = false;
    }
  } catch (error) {
    runDetailStatus.textContent = `Unable to load translation details: ${String(error)}`;
  }
}

refreshRunsBtn.addEventListener("click", () => loadRuns(runsOffset));
previousRunsBtn.addEventListener("click", () => loadRuns(runsOffset - RUNS_PAGE_SIZE));
nextRunsBtn.addEventListener("click", () => loadRuns(runsOffset + RUNS_PAGE_SIZE));
document.getElementById("closeRunDetail").addEventListener("click", () => {
  runDetail.hidden = true;
});

loadRuns(0);
