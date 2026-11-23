# Wazuh and Linux lab

This guide prepares the separate lab for live tests. All three SSH scenarios passed on Wazuh Manager **4.14.10-1** using pre-recorded logs. Live verification with a Wazuh agent and indexer remains pending. [Linux/Podman replay and JSON reports](../README.md#replay-ssh-logs-on-linux)

## Topology and requirements

Use a Wazuh central installation and a separate Linux VM monitored by its agent. The DetectionCI controller connects to the manager API for replay, to the indexer for live alert queries and to the VM through OpenSSH for the restricted file action.

The reference Wazuh Docker release is **v4.14.10**. The official quickstart recommends 4 vCPU, 8 GiB RAM and 50 GB of storage for a small central deployment. A 16 GB laptop running a browser, a central installation and a VM needs an actual resource check; no performance or memory measurements of that topology are available yet.

DetectionCI itself requires Python 3.11+ on Linux or macOS. On Windows use WSL2. The target needs Python 3, OpenSSH and the Wazuh agent; the three live file operations do not require root execution.

## 1. Prepare the official central stack

On the machine where you intend to run Docker:

```bash
python3 lab/prepare_wazuh.py
python3 lab/prepare_wazuh.py --fetch
```

The first command prints the plan. The second downloads the official release into `lab/vendor/wazuh-docker`, records its resolved commit and adds a single-file mount for the custom FIM rules. It refuses to overwrite an existing destination. It does not install Docker, change kernel settings, create certificates or start services.

Review the pinned official deployment instructions for Docker requirements, kernel limits and certificate generation. Inspect published ports and replace the release's example credentials before exposing any service. Keep this lab on a private or host-only network.

From the prepared `single-node` directory, the official certificate and start commands are:

```bash
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose -f docker-compose.yml -f compose.detectionci.yml config
docker compose -f docker-compose.yml -f compose.detectionci.yml up -d
```

Review the expanded `config` output locally: it may contain credentials, so do not add it to a public report. The overlay mounts `detectionci_fim.xml` at the manager's custom-rules location. Verify the rule IDs do not conflict with your existing local rules.

This preparation uses the official release tag, not a newly invented Compose definition. The recorded resolved commit supports reproduction. For stronger source pinning, review that commit and pin the reviewed revision in your own deployment process.

## 2. Set up the endpoint VM

Install the same supported Wazuh agent release using the official agent instructions and enrol it into the lab manager. Do not substitute a container agent for a VM when claiming host filesystem coverage.

Inside the disposable VM, create a dedicated test identity and directory. These commands are examples for a fresh Ubuntu lab VM; adapt them if the identity already exists:

```bash
sudo useradd --create-home --shell /bin/bash dci
sudo install -d -o dci -g dci -m 0750 /var/lib/detectionci/watch
```

Provision only the controller's dedicated public SSH key to the `dci` account using your normal trusted administrative channel. Keep its private key on the controller. The executor does not need sudo access.

Merge the `directories` entry from `agent-syscheck-fragment.xml` into the existing `<syscheck>` section of `/var/ossec/etc/ossec.conf`. Do not replace the complete configuration with the fragment and do not add duplicate top-level sections without checking the agent's configuration rules. Restart the lab agent and wait for its initial scan to finish.

The directory must exist before the agent starts watching it. Record its actual agent ID from Wazuh. The default `001` in the example configuration is a placeholder, not automatic discovery.

## 3. Configure trust and credentials

Verify the VM's SSH host-key fingerprint through its console or another independent trusted channel. Build a dedicated `known_hosts` file and confirm the fingerprint before the first live run. `ssh-keyscan` can collect a key but cannot authenticate it by itself. DetectionCI does not disable host-key verification.

Configure a certificate chain trusted by the controller for both the Wazuh manager API and indexer. The server certificate's names must match `manager_url` or `indexer_url`. The manager API's certificate is separate from the manager's event-transport certificate; do not assume the Docker stack's generated indexer CA automatically covers every API certificate. Configure the API certificate according to the pinned Wazuh documentation.

If the services use different trusted CAs, a PEM bundle can contain both. Set `ca_file` to the absolute path to that bundle. Do not use an insecure TLS bypass. Use trusted internal DNS or a deliberate host mapping so the validated hostnames resolve to the correct lab services.

Create a dedicated manager identity allowed to use logtest, and a separate indexer identity allowed to search only the necessary `wazuh-alerts-4.x-*` indexes. The application does not provision those accounts or change Wazuh security roles. Check the exact role syntax on the pinned version.

Edit `config.example.json` and export its referenced values:

```bash
export DCI_WAZUH_MANAGER_USERNAME='detectionci'
export DCI_WAZUH_MANAGER_PASSWORD='your-manager-password'
export DCI_WAZUH_INDEXER_USERNAME='detectionci-reader'
export DCI_WAZUH_INDEXER_PASSWORD='your-indexer-password'
```

The configuration loader expands an entire `${DCI_*}` string from the environment. Hostnames and paths in the example must be replaced. Keep configuration and SSH private-key permissions private.

## 4. Run replay before live

Use these commands to check replay against the manager configured for this lab. The Podman command in the project README runs all three SSH scenarios in a dedicated container. [Podman quick start](../README.md#replay-ssh-logs-on-linux)

```bash
python3 -m detectionci --config lab/config.example.json run ssh-invalid-user --mode replay --output artifacts/replay-ssh
python3 -m detectionci --config lab/config.example.json run ssh-success-control --mode replay --output artifacts/replay-control
```

These commands submit saved strings to Wazuh logtest. They do not attempt SSH authentication or confirm agent collection. Each scenario uses an isolated session so the single-failure control is not contaminated by a prior burst.

## 5. Run the live FIM checks

Take a clean VM snapshot before the first live suite. Ensure the agent's initial scan completed and alerts are indexed. Then run:

```bash
python3 -m detectionci --config lab/config.example.json run fim-file-created --mode live --output artifacts/live-create
python3 -m detectionci --config lab/config.example.json run fim-file-modified --mode live --output artifacts/live-modify
python3 -m detectionci --config lab/config.example.json run fim-file-deleted --mode live --output artifacts/live-delete
```

The executor streams a fixed Python implementation over SSH. The scenario cannot replace it with arbitrary code. It operates on a newly generated path under the configured watch root. For modification and deletion, the engine first creates a baseline and waits until its added event is actually observed before performing the measured operation.

The independent source checkpoint is the remote filesystem observation, not a claim that an OS journal record was collected. The current live mode does not observe the manager's internal delivery stage. The indexer query and matching alert establish the observed endpoint-to-indexed-alert result.

Custom lab rules:

| Live operation | Native parent | Custom rule | Correlation |
| --- | --- | --- | --- |
| Create | 554 | 100200 | Agent ID, time, unique `syscheck.path`, event `added` |
| Modify | 550 | 100201 | Agent ID, time, unique `syscheck.path`, event `modified` |
| Delete | 553 | 100202 | Agent ID, time, unique `syscheck.path`, event `deleted` |

No broad ATT&CK technique coverage is inferred from these harmless file operations. Live zero-alert controls remain INCONCLUSIVE until independent collection coverage can make an absence-of-alert conclusion reliable; use replay or fixture controls for the supported software checks.

## Interruption and recovery

The controller places a durable dirty marker before live execution. A crash or unverified cleanup leaves the target blocked for further live jobs. Inspect it with:

```bash
python3 -m detectionci target status
```

Stop the worker, restore the VM externally and check its state. Only then acknowledge the restoration:

```bash
python3 -m detectionci target reset --acknowledge-restored
```

The reset command records the operator's acknowledgement; it does not restore a VM. Snapshot management and an external watchdog are not included. A clean normal cleanup result is useful evidence but does not guarantee recovery after the controller machine fails.

## Official sources

Checked 17 November 2026. Recheck version-specific instructions when changing a dependency.

- [Wazuh Docker deployment](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html)
- [Official Wazuh Docker source](https://github.com/wazuh/wazuh-docker/tree/v4.14.10)
- [Wazuh release notes](https://documentation.wazuh.com/current/release-notes/)
- [Wazuh quickstart requirements](https://documentation.wazuh.com/current/quickstart.html)
- [Custom FIM rules and field mapping](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/creating-custom-fim-rules.html)
- [Testing decoders and rules](https://documentation.wazuh.com/current/user-manual/ruleset/testing.html)
- [Securing the Wazuh server API](https://documentation.wazuh.com/current/user-manual/api/securing-api.html)
