# Verification and demonstration

## Wazuh integration status

All three SSH replay scenarios passed on Wazuh Manager **4.14.10-1** with pre-recorded log lines. The reports record the manager's logtest results and the assertions applied to them. During public release preparation on 23 November 2026, the Replay suite reproduced all three PASS verdicts on the same manager version. [Replay command and JSON reports](../README.md#replay-ssh-logs-on-linux)

The **Live FIM smoke test** workflow passed `fim-file-created` in one manually dispatched run. The Wazuh agent monitored the standard `ubuntu-24.04` runner VM, with Wazuh Manager and Indexer **4.14.10** in containers on that runner. Seori matched an indexed alert for rule `100200` with `syscheck.event=added`, the registered agent ID and the unique file path. The workflow also confirmed removal of that file. The run includes disk-space measurements and the `live-fim-report` JSON and HTML artifact. Live modification and deletion scenarios remain unverified. [Passing workflow run](https://github.com/dakonya/Seori/actions/runs/45172139322)

## Initial build verification

The initial implementation environment had Python 3.13.5, no Docker command, no configured Wazuh endpoint and no accelerated VM device. The table records what was exercised in that environment.

| Experiment | Expected scope | Initial status |
| --- | --- | --- |
| Scenario validation | Format, bounds and matcher configuration | Verified locally: 12 default scenarios and 4 fault scenarios |
| Labelled fixture verification | Evaluator and expected-fault semantics | Verified locally: all 16 declared outcomes matched |
| Default fixture suite and report export | Queue, engine, persistence and HTML/JSON output | Verified locally: 12 fixture PASS results; Wazuh was not contacted |
| Unit and controlled transport tests | State, cancellation, client and report behaviour | 147 passed, 5 loopback socket tests skipped; 0 failures/errors; details in verification-results.json |
| HTTP API request parsing | Real HTTP handler using in-memory wire connections | Run, report, baseline, comparison, cancellation/auth guards exercised without listening sockets |
| Browser rendering | Actual interactive layout and browser behaviour | NOT RUN: local file access rejected by browser policy; listening sockets unavailable |
| Native manager replay | Actual pinned Wazuh decoder and rule behaviour | NOT RUN in initial environment |
| VM FIM create/modify/delete | Actual endpoint-to-indexer detection path | NOT RUN in initial environment |
| Independent installation | Reproduction by someone other than the developer | NOT RUN in initial environment |

Five tests skipped in that environment because the execution sandbox rejected local socket binding. In-memory HTTP transport tests exercised the request parser. [Initial machine-readable verification record](verification-results.json)

## Release preparation checks

On Python 3.13.5, all 152 unit and transport tests passed, including the five loopback socket tests. Use the commands below to verify the current checkout.

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q seori detectionci tests
python3 -m seori validate
python3 -m seori verify-fixtures
python3 -m seori suite --mode fixture --output artifacts/fixture-suite
```

The default catalogue contains twelve synthetic fixtures. The separate fault catalogue contains four intentionally non-passing cases. `verify-fixtures` checks that those cases produce their declared results; it does not turn a security FAIL into PASS.

## Integration acceptance experiment

Use a fresh VM snapshot and a pinned Wazuh installation. Record the exact Wazuh image versions, loaded rules, agent version, VM image, configuration hashes, host resource limits and clock alignment. Confirm the actual agent ID, certificate trust and SSH host key before execution.

1. Start the create-file live scenario. Confirm the generated unique path appears in the target VM observation and the corresponding indexed alert.
2. Run modification and deletion separately. Confirm the baseline file's creation is indexed before the measured modification or deletion. Check cleanup and restore state between suites.
3. Save a baseline from the passing runs.
4. In the lab only, change the relevant custom rule so that it cannot match the controlled operation. Restart or reload the manager as required by the pinned installation. Repeat the scenario and retain its non-passing report.
5. Restore the rule and verify the same scenario passes.
6. Disable collection of the test path in the lab agent configuration and repeat. The expected alert must not be reported as successfully observed. Restore the agent configuration and repeat.
7. Make the indexer temporarily unavailable. Verify that the run reports the visibility/transport problem, rather than claiming that the detector conclusively failed or passed.
8. Cancel a run and separately interrupt the controller process. Check persisted state and endpoint cleanup. Restore the VM if the controller cannot confirm cleanup.

These experiments have different causes and evidence. A deadline with an absent alert establishes failure of the expected observed path; it does not automatically establish whether the cause is the agent, delivery or rule logic.

## Measurements

Record numerator and denominator for scenario successes. Keep positive cases, ordinary controls and infrastructure failures separate. A synthetic control set does not estimate a production false-positive rate. Three FIM operations do not imply broad ATT&CK coverage.

Observation delay is measured from the relevant action to the controller observing the indexed alert. It includes sensor processing, transport, indexing and polling. Record the polling interval. For small samples publish individual values; percentile claims need enough repetitions and a stated method.

## Reproduction record

Copy this table into an actual experiment report and fill it from captured output:

| Field | Measured value |
| --- | --- |
| Source revision and release | |
| Python and operating-system versions | |
| Wazuh manager, indexer and agent versions | |
| Loaded rule/configuration hashes | |
| Scenario ID and version | |
| Mode | |
| Run ID and evidence export | |
| Target snapshot/image | |
| Required checkpoints observed | |
| Verdict and explanation | |
| Observation delay and polling interval | |
| Cleanup/restore result | |
| Known limitations | |

## Interview demonstration

A short honest demonstration shows one baseline pass, a deliberately introduced regression, its non-passing evidence and recovery after the fix. Explain which observations are independent, why an old alert cannot satisfy this run, and what a missing checkpoint prevents you from concluding. Keep fixture demonstrations visibly labelled as fixture demonstrations.
