const PATTERN_TO_CLASS = {
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

function badgeClass(state) {
  return state || "unknown";
}

function renderResult(envelope) {
  const r = envelope.structured_result;
  const candidate = r.primary_candidate;

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

  const patternId = document.getElementById("pattern").value;
  const targetTechnology = document.getElementById("target").value;
  const contextId = document.getElementById("context").value;
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
    }
  } catch (err) {
    renderError(String(err));
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = "Translate";
  }
});
