#!/usr/bin/env bash
# From the Seori project directory: bash lab/seori-replay.sh [--suite]
set -euo pipefail
umask 077
if (( $# == 0 )); then
    replay_args=(run ssh-invalid-user)
elif [[ $# == 1 && $1 == --suite ]]; then
    replay_args=(suite)
else
    echo "Использование: bash lab/seori-replay.sh [--suite]" >&2
    exit 2
fi
project_dir=$(pwd -P)
if [[ ! -f "$project_dir/seori/__main__.py" || ! -f "$project_dir/detectionci/__main__.py" || ! -f "$project_dir/scenarios/ssh-invalid-user.json" ]]; then
    echo "Сначала перейди в каталог Seori, затем повтори запуск." >&2
    exit 2
fi
if ! command -v podman >/dev/null; then
    echo "Для Debian установи Podman: sudo apt install podman" >&2
    exit 2
fi
if (( EUID == 0 )); then
    echo "Запусти скрипт от обычного пользователя (без sudo)." >&2
    exit 2
fi
podman info >/dev/null
build_dir=$(mktemp -d)
trap 'rm -rf -- "$build_dir"' EXIT

# Only this empty build context and the recipe below are sent to the builder.
cat > "$build_dir/Containerfile" <<'CONTAINERFILE'
FROM docker.io/library/ubuntu:24.04
RUN set -eu; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates curl gnupg python3 procps; \
    curl --fail --silent --show-error --location https://packages.wazuh.com/key/GPG-KEY-WAZUH -o /tmp/wazuh-key; \
    gpg --batch --yes --dearmor -o /usr/share/keyrings/wazuh.gpg /tmp/wazuh-key; \
    chmod 0644 /usr/share/keyrings/wazuh.gpg; \
    echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' > /etc/apt/sources.list.d/wazuh.list; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends wazuh-manager=4.14.10-1; \
    rm -f /tmp/wazuh-key; \
    rm -rf /var/lib/apt/lists/*
CONTAINERFILE

podman build --layers --iidfile "$build_dir/image-id" "$build_dir"
image_id=$(cat "$build_dir/image-id")
mkdir -p "$project_dir/reports"
report_dir=$(mktemp -d "$project_dir/reports/replay-ssh-XXXXXXXX")
echo "Каталог отчёта: $report_dir"
# Only the new report directory is writable. Code and scenarios are read-only.
# The host's active dashboard has its own database.
podman run --rm -i --network=none --hostname seori-replay \
    -v "$project_dir/seori:/project/seori:ro" \
    -v "$project_dir/detectionci:/project/detectionci:ro" \
    -v "$project_dir/scenarios:/project/scenarios:ro" \
    -v "$report_dir:/reports:rw" \
    -w /project -e PYTHONDONTWRITEBYTECODE=1 "$image_id" bash -s -- "${replay_args[@]}" <<'REPLAY'
set -euo pipefail
# Both clients and server run inside the same isolated network namespace.
cat > /var/ossec/api/configuration/api.yaml <<'API'
host: ['127.0.0.1']
port: 55000
https:
  enabled: false
API
/var/ossec/bin/wazuh-control start
cat > /tmp/dci-config.json <<'JSON'
{"wazuh":{"manager_url":"http://127.0.0.1:55000","manager_username":"wazuh","manager_password":"wazuh"}}
JSON
# Wait until the manager issues a token; never print or store that token.
ready=false
for ((attempt=0; attempt < 30; attempt++)); do
    if curl --silent --fail --max-time 4 --user wazuh:wazuh -X POST \
            'http://127.0.0.1:55000/security/user/authenticate?raw=true' -o /dev/null; then
        ready=true
        break
    fi
    sleep 2
done
if [[ "$ready" != true ]]; then
    echo "Wazuh Manager не ответил на запрос авторизации. Replay ещё не выполнен." >&2
    /var/ossec/bin/wazuh-control status || true
    exit 1
fi

dpkg-query -W -f='Wazuh Manager ${Version}\n' wazuh-manager
python3 -m seori --db /tmp/replay.sqlite3 --config /tmp/dci-config.json \
    "$@" --mode replay --output /reports
REPLAY
echo "Открой HTML-отчёт в $report_dir"
