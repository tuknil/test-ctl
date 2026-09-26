# Defense Generation artifacts, verbatim

`wazuh-candidate.xml` is a Defense Generation `primary_candidate
.artifact_content` for `artifact_type: wazuh-rule`, copied byte for byte from
the Mitigation Check service that consumes it (`wazuh-eval/candidate_test.go`
and `api/executor_edr_test.go` in the mitigation-check repository, which carry
the same rule).

It is here so the Wazuh -> SentinelOne compiler is tested against what the
producer actually emits rather than a hand-authored rule. The producer's
dialect is its own canonical observable vocabulary -- `event.type`,
`src.process.cmdline` and the rest -- with `type="pcre2"` on every field, which
is not the Sysmon or auditd field naming a generic Wazuh ruleset uses.

The matching telemetry the producer's proof loop runs this rule against is:

    {"event":{"type":"Process Creation"},
     "src":{"process":{"cmdline":"powershell.exe -EncodedCommand SQBFAFgA"}}}

which is what establishes that `src.process.*` is the process being executed,
not its parent.
