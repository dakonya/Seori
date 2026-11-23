#!/usr/bin/env bash
# Provision the endpoint on the disposable GitHub-hosted runner VM.
set -euo pipefail
umask 077

if (( $# != 1 )) || [[ $1 != /* || ${GITHUB_ACTIONS:-} != true ]]; then
    echo 'Run this script on the GitHub Actions runner with an absolute state directory.' >&2
    exit 2
fi
: "${GITHUB_ENV:?GitHub Actions environment file is required}"

ci_dir=$1
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
agent_name=seori-live
agent_version=4.14.10-1
ssh_user=dci-fim
ssh_port=2222
watch_root=/var/lib/detectionci/watch
agent_log=/var/ossec/logs/ossec.log

mkdir -p -- "$ci_dir"
curl --fail --silent --show-error --location --retry 3 \
    https://packages.wazuh.com/key/GPG-KEY-WAZUH |
    gpg --batch --dearmor --output "$ci_dir/wazuh-apt.gpg"
sudo install -m 0644 "$ci_dir/wazuh-apt.gpg" /usr/share/keyrings/dci-wazuh.gpg
printf '%s\n' 'deb [signed-by=/usr/share/keyrings/dci-wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' |
    sudo tee /etc/apt/sources.list.d/dci-wazuh.list >/dev/null
sudo apt-get update -o Acquire::Retries=3
sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    -o DPkg::Lock::Timeout=60 \
    "wazuh-agent=$agent_version" openssh-server
dpkg-query -W -f='Wazuh Agent ${Version}\n' wazuh-agent

sudo useradd --create-home --shell /bin/bash "$ssh_user"
sudo install -d -o "$ssh_user" -g "$ssh_user" -m 0711 "$watch_root"

# Use a dedicated loopback listener, with a local key as the host trust source.
ssh-keygen -q -t ed25519 -N '' -f "$ci_dir/ssh-id"
ssh-keygen -q -t ed25519 -N '' -f "$ci_dir/ssh-host"
printf '[127.0.0.1]:%s %s\n' "$ssh_port" "$(cut -d ' ' -f 1,2 "$ci_dir/ssh-host.pub")" > "$ci_dir/ssh-known-hosts"
sed 's/^/restrict /' "$ci_dir/ssh-id.pub" > "$ci_dir/ssh-authorized-keys"
sudo install -d -o "$ssh_user" -g "$ssh_user" -m 0700 "/home/$ssh_user/.ssh"
sudo install -o "$ssh_user" -g "$ssh_user" -m 0600 "$ci_dir/ssh-authorized-keys" "/home/$ssh_user/.ssh/authorized_keys"
sudo install -d -m 0755 /run/sshd
cat > "$ci_dir/sshd_config" <<EOF
Port $ssh_port
ListenAddress 127.0.0.1
HostKey "$ci_dir/ssh-host"
PidFile "$ci_dir/sshd.pid"
AllowUsers $ssh_user
AuthorizedKeysFile .ssh/authorized_keys
AuthenticationMethods publickey
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
PermitTTY no
DisableForwarding yes
UsePAM yes
EOF
sudo /usr/sbin/sshd -t -f "$ci_dir/sshd_config"
sudo /usr/sbin/sshd -f "$ci_dir/sshd_config"
ssh -p "$ssh_port" -i "$ci_dir/ssh-id" -o BatchMode=yes -o IdentitiesOnly=yes \
    -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$ci_dir/ssh-known-hosts" \
    -o ConnectTimeout=5 -- "$ssh_user@127.0.0.1" \
    "test -w '$watch_root' && command -v python3 >/dev/null"

# Scope the agent to the isolated FIM directory for this exercise.
sudo tee /var/ossec/etc/ossec.conf >/dev/null <<EOF
<ossec_config>
  <client>
    <server>
      <address>127.0.0.1</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <enrollment>
      <enabled>yes</enabled>
      <manager_address>127.0.0.1</manager_address>
      <port>1515</port>
      <agent_name>$agent_name</agent_name>
    </enrollment>
  </client>
  <syscheck>
    <disabled>no</disabled>
    <scan_on_start>yes</scan_on_start>
    <directories realtime="yes" check_all="yes">$watch_root</directories>
  </syscheck>
  <rootcheck><disabled>yes</disabled></rootcheck>
  <sca><enabled>no</enabled></sca>
  <wodle name="syscollector"><disabled>yes</disabled></wodle>
</ossec_config>
EOF
sudo systemctl daemon-reload
sudo systemctl restart wazuh-agent

agent_id=
for (( attempt=0; attempt<60; attempt++ )); do
    if sudo grep -qx "status='connected'" /var/ossec/var/run/wazuh-agentd.state 2>/dev/null &&
        sudo grep -Fq 'Real-time file integrity monitoring started.' "$agent_log" &&
        local_id=$(sudo awk -v name="$agent_name" '$2 == name { print $1 }' /var/ossec/etc/client.keys) &&
        [[ $local_id =~ ^[0-9]+$ ]] &&
        manager_id=$(bash "$script_dir/wazuh-stack.sh" "$ci_dir" agent-id "$agent_name") &&
        [[ $manager_id == "$local_id" ]]; then
        agent_id=$local_id
        break
    fi
    sleep 2
done
if [[ -z $agent_id ]]; then
    echo 'The Wazuh agent did not become active and ready for real-time FIM.' >&2
    sudo journalctl -u wazuh-agent --lines=20 --no-pager >&2 || true
    sudo grep -E 'wazuh-(agentd|syscheckd):' "$agent_log" |
        grep -viE 'password|private key|token|secret' | tail -n 20 >&2 || true
    exit 1
fi

printf 'Agent %s is active with real-time FIM on %s.\n' "$agent_id" "$watch_root"
{
    printf 'DCI_CI_AGENT_ID=%s\n' "$agent_id"
    printf 'DCI_CI_SSH_USER=%s\n' "$ssh_user"
    printf 'DCI_CI_SSH_PORT=%s\n' "$ssh_port"
    printf 'DCI_CI_SSH_KEY=%s\n' "$ci_dir/ssh-id"
    printf 'DCI_CI_SSH_KNOWN_HOSTS=%s\n' "$ci_dir/ssh-known-hosts"
} >> "$GITHUB_ENV"
