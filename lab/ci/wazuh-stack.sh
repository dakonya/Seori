#!/usr/bin/env bash
set -euo pipefail
umask 077

if (( $# < 1 )); then
    printf 'Usage: bash lab/ci/wazuh-stack.sh DIRECTORY [up|agent-id NAME|wait-alerts|regress-rule|restore-rule|diagnostics|down]\n' >&2
    exit 2
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
run_dir=$(realpath -m -- "$1")
single_node="$run_dir/wazuh-docker/single-node"
credentials="$run_dir/wazuh.env"
command=${2:-up}

compose() {
    docker compose --project-name detectionci-live \
        -f "$single_node/docker-compose.yml" -f "$script_dir/wazuh-compose.yml" "$@"
}

load_credentials() {
    set -a
    # shellcheck disable=SC1090
    source "$credentials"
    set +a
}

wait_for() {
    local description=$1 deadline=$((SECONDS + $2))
    shift 2
    until "$@"; do
        if (( SECONDS >= deadline )); then
            printf 'Timed out waiting for %s.\n' "$description" >&2
            return 1
        fi
        sleep 3
    done
    printf 'Ready: %s\n' "$description"
}

indexer_request() {
    local path=$1
    shift
    curl --silent --fail --max-time 8 --noproxy '*' \
        --cacert "$DCI_WAZUH_CA_FILE" \
        --user "$DCI_WAZUH_INDEXER_USERNAME:$DCI_WAZUH_INDEXER_PASSWORD" \
        "$@" "$DCI_WAZUH_INDEXER_URL$path"
}

indexer_ready() {
    indexer_request '/_cluster/health?wait_for_status=yellow&timeout=4s' |
        jq --exit-status '.timed_out == false and (.status == "yellow" or .status == "green")' >/dev/null
}

manager_status() {
    compose exec -T wazuh.manager /var/ossec/bin/wazuh-control status
}

manager_ready() {
    local status
    # The aggregate status exits nonzero when optional daemons are stopped.
    status=$(manager_status 2>/dev/null || true)
    [[ "$status" == *'wazuh-analysisd is running'* &&
       "$status" == *'wazuh-authd is running'* &&
       "$status" == *'wazuh-remoted is running'* ]]
}

filebeat_output() {
    compose exec -T wazuh.manager /usr/share/filebeat/bin/filebeat test output \
        -c /etc/filebeat/filebeat.yml -path.home /usr/share/filebeat \
        -path.config /etc/filebeat -path.data /var/lib/filebeat
}

filebeat_ready() {
    filebeat_output >/dev/null 2>&1
}

alerts_ready() {
    indexer_request '/wazuh-alerts-4.x-*/_count' |
        jq --exit-status '._shards.total > 0 and ._shards.failed == 0 and .count > 0' >/dev/null
}

agent_reconnected() {
    sudo grep -qx "status='connected'" /var/ossec/var/run/wazuh-agentd.state &&
        compose exec -T wazuh.manager /var/ossec/bin/agent_control -i "$1" -j |
        jq --exit-status --arg id "$1" --argjson since "$2" \
            '.error == 0 and .data.id == $id and .data.status == "Active" and
             ((.data.lastKeepAlive | tonumber) > $since)' >/dev/null 2>&1
}

write_phase_rule() {
    python3 - "$script_dir/../detectionci_fim.xml" "$single_node/config/detectionci_fim.xml" "$command" <<'PY'
from pathlib import Path
import re
import sys
from tempfile import NamedTemporaryFile

original, staged = map(Path, sys.argv[1:3])
phase = sys.argv[3]
if staged.is_symlink() or original.samefile(staged):
    raise SystemExit("Expected a separate temporary XML file")

baseline = original.read_bytes()
rules = list(re.finditer(rb'<rule\b[^>]*\bid="100200"[^>]*>.*?</rule>', baseline, re.DOTALL))
field = b'<field name="file" type="pcre2">^/var/lib/detectionci/watch/</field>'
if len(rules) != 1 or rules[0].group().count(field) != 1:
    raise SystemExit("Expected one original path filter in rule 100200")

rule = rules[0]
regressed_rule = rule.group().replace(field, field.replace(b"/watch/", b"/watch-regression/"))
regressed = baseline[:rule.start()] + regressed_rule + baseline[rule.end():]
current = staged.read_bytes()
if phase == "regress-rule":
    if current != baseline:
        raise SystemExit("Temporary Wazuh rules differ from the original XML")
    replacement = regressed
else:
    if current not in (baseline, regressed):
        raise SystemExit("Temporary Wazuh rules contain unexpected edits")
    replacement = baseline

with NamedTemporaryFile(dir=staged.parent, delete=False) as copy:
    temporary = Path(copy.name)
    try:
        copy.write(replacement)
        copy.close()
        temporary.chmod(0o644)
        temporary.replace(staged)
    finally:
        temporary.unlink(missing_ok=True)
PY
}

case "$command" in
    up)
        if [[ "${GITHUB_ACTIONS:-}" != true ]]; then
            echo 'Run this stack setup on the disposable GitHub Actions runner.' >&2
            exit 2
        fi
        mkdir -p -- "$run_dir"
        python3 "$script_dir/../prepare_wazuh.py" --fetch --destination "$run_dir/wazuh-docker"
        # The image copies this public file into the rules directory as root.
        # Analysisd loads rules after dropping privileges to the wazuh user.
        chmod 0644 "$single_node/config/detectionci_fim.xml"

        indexer_password=$(openssl rand -hex 24)
        api_password="Aa1!$(openssl rand -hex 16)"
        printf '::add-mask::%s\n' "$indexer_password" "$api_password"
        {
            printf 'DCI_WAZUH_INDEXER_URL=https://wazuh.indexer:9200\n'
            printf 'DCI_WAZUH_INDEXER_USERNAME=admin\n'
            printf 'DCI_WAZUH_INDEXER_PASSWORD=%q\n' "$indexer_password"
            printf 'DCI_WAZUH_API_PASSWORD=%q\n' "$api_password"
            printf 'DCI_WAZUH_CA_FILE=%q\n' "$run_dir/indexer-ca.pem"
        } > "$credentials"
        load_credentials

        if (( $(sysctl -n vm.max_map_count) < 262144 )); then
            sudo sysctl -w vm.max_map_count=262144
        fi
        printf '127.0.0.1 wazuh.indexer\n' | sudo tee -a /etc/hosts >/dev/null

        echo 'Pulling Wazuh Manager and Indexer images.'
        compose pull wazuh.manager wazuh.indexer

        # Initialize OpenSearch Security with a generated password and the admin role.
        hash=$(docker run --rm --network none --env JAVA_HOME=/usr/share/wazuh-indexer/jdk \
            --entrypoint /bin/bash wazuh/wazuh-indexer:4.14.10 \
            /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "$indexer_password" |
            tail -n 1)
        if [[ ! "$hash" =~ ^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$ ]]; then
            echo 'The Wazuh Indexer password hasher failed.' >&2
            exit 1
        fi
        users_file="$single_node/config/wazuh_indexer/internal_users.yml"
        cat > "$users_file" <<EOF
_meta:
  type: internalusers
  config_version: 2
admin:
  hash: '$hash'
  reserved: true
  backend_roles: [admin]
EOF
        chmod 0644 "$users_file" "$single_node/config/wazuh_indexer/wazuh.indexer.yml"

        echo 'Generating ephemeral Wazuh certificates.'
        docker compose --project-name detectionci-live \
            -f "$single_node/generate-indexer-certs.yml" run --rm -T generator
        # The generator makes its root-owned output directory non-traversable.
        # Copy the public CA only; leave all certificate keys in that directory.
        sudo install -o "$(id -u)" -m 0644 \
            "$single_node/config/wazuh_indexer_ssl_certs/root-ca.pem" "$DCI_WAZUH_CA_FILE"
        test -r "$DCI_WAZUH_CA_FILE"

        echo 'Starting Wazuh Indexer.'
        compose up -d wazuh.indexer
        wait_for 'authenticated TLS to Wazuh Indexer' 180 indexer_ready

        echo 'Starting Wazuh Manager with the project FIM rules and Filebeat.'
        compose up -d wazuh.manager
        wait_for 'Wazuh Manager analysis, enrollment and agent transport' 180 manager_ready
        wait_for 'Filebeat output to Wazuh Indexer' 90 filebeat_ready
        compose exec -T wazuh.manager rpm -q --qf 'Wazuh Manager %{VERSION}-%{RELEASE}\n' wazuh-manager
        ;;
    agent-id)
        load_credentials
        compose exec -T wazuh.manager /var/ossec/bin/agent_control -lc -j |
            jq --exit-status --raw-output --arg name "${3:?Agent name required}" \
                '.data[] | select(.id != "000" and .name == $name and .status == "Active") | .id'
        ;;
    wait-alerts)
        load_credentials
        wait_for 'an actual Wazuh alert in Wazuh Indexer' 120 alerts_ready
        ;;
    regress-rule|restore-rule)
        if [[ "${GITHUB_ACTIONS:-}" != true || -z "${RUNNER_TEMP:-}" ||
              "$run_dir" != "$(realpath -m -- "$RUNNER_TEMP")/"* ]]; then
            echo 'Rule changes apply only to the temporary GitHub Actions stack.' >&2
            exit 2
        fi
        : "${DCI_CI_AGENT_ID:?A registered Live FIM agent ID is required}"
        load_credentials
        write_phase_rule

        # The image copies the mounted XML into /var/ossec at startup. Recreate
        # the bind mount while retaining Manager, agent registration and Filebeat data.
        compose up -d --force-recreate --no-deps wazuh.manager
        manager_container=$(compose ps -q wazuh.manager)
        manager_started=$(docker inspect --format '{{.State.StartedAt}}' "$manager_container")
        manager_epoch=$(date -d "$manager_started" +%s)
        wait_for 'Wazuh Manager analysis, enrollment and agent transport' 180 manager_ready

        expected=$(sha256sum "$single_node/config/detectionci_fim.xml")
        loaded=$(compose exec -T wazuh.manager sha256sum /var/ossec/etc/rules/detectionci_fim.xml)
        if [[ "${expected%% *}" != "${loaded%% *}" ]]; then
            echo 'The active Wazuh FIM XML does not match the staged rule.' >&2
            exit 1
        fi
        printf 'Active FIM XML SHA-256 %s\n' "${loaded%% *}"
        wait_for 'Filebeat output to Wazuh Indexer' 90 filebeat_ready
        wait_for "agent $DCI_CI_AGENT_ID keepalive after Manager restart" 150 \
            agent_reconnected "$DCI_CI_AGENT_ID" "$manager_epoch"
        ;;
    diagnostics)
        [[ -f "$credentials" && -f "$single_node/docker-compose.yml" ]] || exit 0
        load_credentials
        compose ps -a || true
        indexer_request '/_cluster/health' --show-error --output /dev/null \
            --write-out 'Indexer health HTTP status: %{http_code}\n' || true
        manager_status 2>/dev/null | grep -E '^wazuh-(analysisd|authd|remoted) (is running|not running)' || true
        containers=$(compose ps -aq wazuh.manager wazuh.indexer)
        if [[ -n "$containers" ]]; then
            while IFS= read -r container; do
                docker inspect --format '{{.Name}} status={{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}}' "$container"
            done <<< "$containers"
        fi
        {
            compose logs --no-color --tail 100 wazuh.indexer wazuh.manager
            filebeat_output
        } 2>&1 |
            sed -e "s/$DCI_WAZUH_INDEXER_PASSWORD/[REDACTED]/g" -e "s/$DCI_WAZUH_API_PASSWORD/[REDACTED]/g" |
            grep -iE 'error|fatal|exception|no space|disk watermark|failed|connection refused|not running|publish_address|OpenSearch Security.*initialized' || true
        ;;
    down)
        [[ -f "$credentials" && -f "$single_node/docker-compose.yml" ]] || exit 0
        load_credentials
        compose down --volumes --remove-orphans
        ;;
    *)
        echo 'Unknown stack command.' >&2
        exit 2
        ;;
esac
