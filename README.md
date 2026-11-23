# DetectionCI

DetectionCI checks for detection regressions after a rule or configuration change. It runs scenarios with explicit alert expectations and exports the verdict, observed alerts and evidence hashes in JSON and HTML reports.

The three SSH replay scenarios passed on Wazuh Manager **4.14.10-1** using pre-recorded log lines. Replay verifies Wazuh's decoders and rules for those inputs. End-to-end live verification with a Wazuh agent is pending.

## Replay SSH logs on Linux

Install Podman with your distribution's package manager. On Debian or Ubuntu, use `sudo apt install podman`. Run the suite from the root of the cloned repository as a regular user with rootless Podman.

```bash
bash lab/detectionci-replay.sh --suite
```

The first build downloads the Ubuntu base image and Wazuh packages. `bash lab/detectionci-replay.sh` runs just `ssh-invalid-user`. The script prints the directory for the generated JSON and HTML reports under `reports/`.

| Scenario | Expected rule matches | Rule returned by Wazuh | Verdict |
| --- | --- | --- | --- |
| [ssh-invalid-user](examples/replay/ssh-invalid-user.json) | At least one match for `5710` | `5710` | PASS |
| [ssh-single-not-bruteforce](examples/replay/ssh-single-not-bruteforce.json) | Zero matches for `5712` after a single failed login | `5710` | PASS |
| [ssh-success-control](examples/replay/ssh-success-control.json) | Zero matches for `5710` after a successful login | `5715` | PASS |

Each control counts matches for its specified rule. Wazuh returned one alert in each control, with a different rule ID from the one under test. The matching count was zero in both controls, so both passed.

## Run locally

Requirements: Python 3.11 or newer on Linux or macOS; Windows users can run it in WSL2. The application uses the standard library and SQLite; no package download is required for fixture mode.

From the project directory:

```bash
python3 -m detectionci --help
python3 -m detectionci validate
python3 -m detectionci verify-fixtures
python3 -m detectionci suite --mode fixture --output artifacts/fixture-suite
python3 -m detectionci serve --host 127.0.0.1 --port 8787
```

Open http://127.0.0.1:8787. Select a scenario, choose a supported mode and start a run. The interface shows only stored runs and their actual results.

Русская инструкция: [START_HERE_RU.md](START_HERE_RU.md). A sample **synthetic fixture** report is in [examples/fixture-fim-created.html](examples/fixture-fim-created.html); it is not evidence of a live Wazuh detection.

Run one check and export its evidence:

```bash
python3 -m detectionci run ssh-invalid-user --mode fixture --json --output artifacts/ssh
```

Global options such as `--db`, `--config` and `--scenarios` go before the command:

```bash
python3 -m detectionci --db artifacts/demo.sqlite3 run fim-file-created --mode fixture
```

## What each mode proves

| Mode | Input and execution | Valid conclusion |
| --- | --- | --- |
| Fixture | Embedded synthetic alerts and checkpoints | The evaluator produces the expected result for those supplied inputs |
| Replay | Raw log lines submitted to a real Wazuh manager logtest session | Those lines match the expected native rules and decoder behaviour |
| Live | A restricted action in a registered Linux VM, followed by actual alert queries | The observed action-to-indexed-alert path satisfies the scenario |

Replay does not exercise the endpoint agent or delivery path. Live does not infer unobserved stages inside Wazuh. A missing or unavailable checkpoint stays visible in the report.

## Scenario catalogue

Twelve default scenarios cover three lab-scoped FIM operations, SSH rule replay, ordinary controls and evaluator correlation/counting cases. The six fixture-only cases are software checks, not six additional supported live attack techniques. Supported modes are recorded in each scenario's metadata.

The live actions create, modify or delete a uniquely named harmless file under `/var/lib/detectionci/watch`. There is no arbitrary command, target-address or script field in the web API. File changes confirm monitoring of the configured lab path; they do not establish broad intrusion coverage.

Four intentionally non-passing fixture scenarios live in `fixtures/fault-scenarios/`. They exercise missing alerts, missing delivery checkpoints, unavailable observations and a control that incorrectly triggers. Their `expected_verdict` labels document expected software behaviour; a security run still returns a nonzero exit code for a non-PASS result.

## Wazuh lab

For live tests, prepare a separate Linux VM with a Wazuh agent, Python 3 and OpenSSH access with a verified host key. The controller needs access to the Wazuh APIs with trusted TLS certificates. The lab guide covers the pinned `wazuh-docker` release `v4.14.10`, custom FIM rules, agent setup and commands for the configured lab. [Wazuh lab guide](lab/README.md)

## Verification and trust

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q detectionci tests
python3 -m detectionci validate
python3 -m detectionci verify-fixtures
python3 -m detectionci suite --mode fixture --output artifacts/fixture-suite
```

The repository includes transport-level tests using controlled responses. The initial build environment lacked Docker, a Wazuh service and VM acceleration. The verification guide records those initial checks, the later manager replay and the remaining live acceptance experiments. [Verification guide](docs/verification.md)

Only PASS is a successful required CI check. FAIL, ERROR, INCONCLUSIVE and CANCELLED must not become a green security gate. CI in this repository runs software and fixture checks without Wazuh credentials. It does not expose a privileged live runner to pull requests.

## Design and limits

- [Architecture and state model](docs/architecture.md)
- [Threat model and trust boundaries](docs/threat-model.md)
- [Scenario format and authoring](docs/scenarios.md)
- [Verification and demonstration](docs/verification.md)
- [Wazuh lab setup](lab/README.md)

Python and SQLite keep the controller lightweight and runnable without external runtime dependencies. Wazuh remains responsible for detection. DetectionCI owns execution, matching, evidence and regression reporting.

The current live executor covers three FIM operations. A persistent dirty-target marker blocks further live work after an interruption or unverified cleanup; `target reset --acknowledge-restored` records an external restoration, not an automated restore. A broader scenario catalogue, signed release provenance, multiple SIEM backends, distributed runners, an external watchdog and automatic VM snapshot restoration are further work. Run live tests only on a disposable or explicitly restored lab VM.
