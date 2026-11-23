# Writing a scenario

A scenario declares a specific expected result. It does not guess the security policy from a log or automatically establish that a host is secure.

Required fields are `id`, `version`, `title`, `description`, `kind`, `timeout_seconds` and `expect`. IDs are lowercase slugs. `kind` is `positive` or `control`; both are evaluated against the same explicit alert-count expectations.

```json
{
  "id": "ssh-invalid-user",
  "version": "1.0.0",
  "title": "SSH: invalid account",
  "description": "One invalid-account event should match the native rule.",
  "kind": "positive",
  "timeout_seconds": 45,
  "expect": {
    "min_alerts": 1,
    "predicates": [
      {"field": "rule.id", "op": "eq", "value": "5710"}
    ]
  },
  "replay": [
    "Nov 17 12:00:00 detectionci-lab sshd[29205]: Invalid user dci_fixture from 192.0.2.25 port 48928"
  ],
  "metadata": {"supported_modes": ["replay"]}
}
```

All predicates must hold for the same alert. `min_alerts` and `max_alerts` constrain the number of matching alerts, not every unrelated audit event. Supported operators are equality, membership, substring containment and the conservatively validated regular-expression subset implemented by the evaluator.

For a control, set both `min_alerts` and `max_alerts` to zero for the particular rule or behaviour that should not match. Ordinary operations may still produce legitimate audit alerts. A successful login control, for example, only rejects a match against the invalid-user rule; it does not require a silent SIEM.

## Fixtures and faults

`fixture.alerts` holds synthetic Wazuh-shaped objects. `fixture.checkpoints` holds named observations with `observed`, `missing` or `unavailable` status. A missing required checkpoint contradicts the expectation. An unavailable observation limits what can be concluded. Fixture checkpoints cannot prove actual action execution or event delivery.

The separate fault directory contains examples with `expected_verdict`. This label documents the expected evaluator result; it must not override that result into PASS. A deliberately failing security run remains a non-passing run.

## Live actions

Only `file_create`, `file_modify` and `file_delete` are accepted by the initial live executor. Configure the registered endpoint and watch root outside the scenario. The engine creates a unique filename and adds its path to the alert correlation predicates. Detection rules match the general lab scope, not the unique test filename.

Add a new action only with an execution implementation, scoped permissions, a cleanup strategy, failure-path tests and an integration experiment. Do not infer an ATT&CK technique from a filename alone. The current harmless FIM scenarios test a telemetry mechanism, so they do not claim to emulate particular intrusion techniques.

## Review a new scenario

Record the source of expected fields and rule IDs, the supported versions, ordinary controls, known blind spots and the exact claim its successful result supports. Verify that an old event, another endpoint's event or another file's event cannot satisfy it. Check failure and unavailable-observation behaviour as well as the happy path.
