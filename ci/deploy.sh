#!/usr/bin/env bash
set -euo pipefail
[[ "${CI_COMMIT_REF_PROTECTED:-}" == true && "${OPLA_DEPLOY_ENABLED:-}" == 1 ]] || exit 2
for variable in OPLA_DEPLOY_INVENTORY OPLA_DEPLOY_VARS OPLA_SSH_PRIVATE_KEY OPLA_SSH_KNOWN_HOSTS; do
  [[ -n "${!variable:-}" && -s "${!variable}" && -f "${!variable}" ]] || {
    printf 'Missing protected file variable: %s\n' "$variable" >&2
    exit 2
  }
done
sha256sum -c dist/SHA256SUMS
umask 077
ssh_dir="$(mktemp -d)"
trap 'rm -rf "$ssh_dir"' EXIT
cp "$OPLA_SSH_PRIVATE_KEY" "$ssh_dir/id"
cp "$OPLA_SSH_KNOWN_HOSTS" "$ssh_dir/known_hosts"
chmod 600 "$ssh_dir/id" "$ssh_dir/known_hosts"
export ANSIBLE_HOST_KEY_CHECKING=True
export ANSIBLE_SSH_ARGS="-o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$ssh_dir/known_hosts"
ansible-playbook -i "$OPLA_DEPLOY_INVENTORY" ansible/site.yml \
  --private-key "$ssh_dir/id" \
  -e "@$OPLA_DEPLOY_VARS" \
  -e "opla_bpf_object=$CI_PROJECT_DIR/dist/xdp_ddos_protect.o"
