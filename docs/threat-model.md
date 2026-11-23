# Threat model

Seori reads security logs and can perform restricted actions on a lab endpoint. Its API, scenarios, credentials and exported evidence cross separate trust boundaries.

| Asset or boundary | Failure to consider | Current control and practical limit |
| --- | --- | --- |
| Local HTTP API | Another origin starts a run in the user's browser | Loopback-only binding, origin and Host checks, optional bearer authentication |
| Scenario files | A file supplies arbitrary code or shell fragments | Validated JSON schema and an action allowlist; scenario contributions still need code review |
| SSH endpoint | Address or options redirect command execution | Explicit target configuration, strict host-key checks, argument arrays and no shell interpolation |
| Remote action | A test modifies unrelated files | Fixed watch root, generated run paths, bounded harmless content and checked cleanup |
| Wazuh manager credentials | Secrets leak into errors or evidence | Environment-based configuration, bounded/redacted responses and exports |
| Indexer read access | A reader acquires unnecessary administrative capabilities | Dedicated read identity recommended; actual Wazuh role configuration belongs to lab setup |
| TLS identity | A different service is accepted as Wazuh | Verified certificate chains and names; no insecure-skip option |
| Incoming logs | Malicious content executes in the report or browser | Untrusted text handling, escaping and bounded payloads |
| Required CI check | Missing evidence yields a green build | Only PASS exits successfully; uncertainty blocks the gate |
| Pull-request pipeline | Untrusted code receives live credentials | Offline software/fixture checks only; live jobs require a separately secured trusted workflow |
| Endpoint cleanup | Process termination leaves changes behind | Checked normal cleanup and a persistent dirty-target marker; disposable VM restoration remains an operator responsibility |

## Residual risks

There is no external watchdog or VM orchestrator in this release. A killed controller cannot guarantee cleanup on the endpoint. A durable marker blocks subsequent live jobs after an interrupted or unverified operation. Restore the VM externally before acknowledging restoration and starting another live suite. Do not treat Python `finally` execution as an availability guarantee.

The controller trusts its own machine and the configured endpoints to the extent needed to obtain observations. A compromised target can falsify command output; a compromised SIEM can falsify alerts. This tool is a regression checker, not an independent forensic attestation service.

Anyone allowed to modify application code can change both a detector and its expectations. Review expected-policy changes separately from implementation changes. The tool cannot establish whether an intentionally weakened expectation is acceptable.

Run history and exports can contain usernames, addresses, paths and message bodies. Keep the database and artifact directory private. Redaction is defence in depth, not a reason to publish unreviewed operational logs. Synthetic fixtures use documentation addresses and invented identities.

## Before remote exposure

Version 0.1 rejects direct non-loopback binding, including when a bearer token is set. Use an SSH tunnel for access to a controller on another machine. Optional local authentication uses `DCI_API_TOKEN` with at least 32 characters; the token stays in browser memory. A future remotely exposed installation requires a reviewed authentication setup, TLS termination, a trusted network boundary, retention policy and deployment-specific testing.
