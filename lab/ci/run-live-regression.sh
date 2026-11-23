#!/usr/bin/env bash
set -euo pipefail
umask 077

if (( $# != 1 )) || [[ ${GITHUB_ACTIONS:-} != true ]]; then
    echo 'Run the Live FIM regression on the disposable GitHub Actions runner.' >&2
    exit 2
fi

ci_dir=$1
reports="$ci_dir/reports"
config="$ci_dir/config.json"
: "${DCI_CI_AGENT_ID:?}" "${GITHUB_STEP_SUMMARY:?}"

set -a
source "$ci_dir/wazuh.env"
set +a
export PYTHONPATH=.

run_phase() {
    local phase=$1
    printf '\n=== %s ===\n' "$phase"
    python3 -m seori --db "$ci_dir/runs.sqlite3" --config "$config" \
        run fim-file-created --mode live --output "$reports/$phase"
}

run_phase baseline
python3 lab/ci/verify-live-report.py "$reports/baseline" "$DCI_CI_AGENT_ID"

bash lab/ci/wazuh-stack.sh "$ci_dir" regress-rule
if run_phase regression; then
    echo 'The regressed rule unexpectedly passed the live scenario.' >&2
    exit 1
else
    status=$?
    if (( status != 1 )); then
        printf 'Unexpected Seori exit status in regression phase: %s\n' "$status" >&2
        exit "$status"
    fi
fi
python3 lab/ci/verify-live-regression.py "$reports" "$DCI_CI_AGENT_ID" "$config" --capture-regression

bash lab/ci/wazuh-stack.sh "$ci_dir" restore-rule
run_phase restored
python3 lab/ci/verify-live-regression.py "$reports" "$DCI_CI_AGENT_ID" "$config" \
    | tee -a "$GITHUB_STEP_SUMMARY"
