# DetectionCI 0.1.0

This release implements a local detection-validation controller, SQLite run state, CLI, dashboard, redacted reports and immutable baselines. It has three execution scopes: synthetic fixture logic, native Wazuh replay, and a constrained SSH/FIM live path.

The default catalogue contains twelve scenarios. Three include live file operations and three include native SSH replay logs. Four separate fault cases verify non-passing and inconclusive evaluation. Catalogue size is not a count of verified live techniques.

## Engineering checks

Tests cover atomic job claims, cancellation races, crash recovery, target recovery locks, redaction, HTML escaping, input bounds, TLS policy, replay-session cleanup, stale event isolation and observation deadlines. The vetted file helper is also executed against temporary directories, including tests that reject symlinks, hard links and unsafe operation inputs.

A separate review found and corrected three implementation defects before packaging: authentication and routing interpreted request targets differently; a wrong-event FIM baseline could be accepted; a late indexer response could satisfy an expired observation window. Each correction has a regression test.

The initial build recorded 147 successful automated tests, five skipped socket tests and no failures. All sixteen labelled fixture cases produced their expected verdicts. [Initial verification record](verification-results.json)

## Integration boundary

The initial build environment did not run Wazuh integration. In a later run, all three SSH scenarios passed on Wazuh Manager **4.14.10-1** using pre-recorded log lines. Live verification from the endpoint agent through the indexer remains pending, along with browser rendering and an independent installation. [Replay results and reports](../README.md#replay-ssh-logs-on-linux)

Live observations confirm the remote file state and indexed alerts. They do not independently observe every collection or manager-processing stage. Negative live assertions remain inconclusive without independent collection-coverage evidence. VM restoration is an operator action; the controller preserves a block after unverified cleanup or interruption.

Direct remote HTTP serving is disabled. The supported deployment is a loopback controller, optionally accessed through an SSH tunnel. Distributed workers, automated hypervisor snapshots, a broader live catalogue and further SIEM adapters are outside this release.
