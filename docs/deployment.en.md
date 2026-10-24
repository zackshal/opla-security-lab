# Ansible deployment: local, SSH, VPN and bastion

[Русский](deployment.md) · **English**

## Existing profiles and boundaries

| Profile | Playbook | Installs/checks | Still separate |
|---|---|---|---|
| Lab host | `ansible/lab-host.yml` | QEMU/libguestfs/network/build packages; explicit optional Docker | Images, VM launch, monitoring/API setup and email |
| Security node | `ansible/site.yml` | Runtime packages, XDP, Suricata, nginx, local Zabbix/PostgreSQL and telemetry | Docker Compose, controller BPF object, VPN and lab scan-policy/poller migration |
| Preflight | `ansible/preflight.yml` | Read-only prerequisites | Not verifier, enforcement or reboot acceptance |

These automate bounded tasks, not one-click installation on arbitrary operating systems. Dedicated-server deployment/reboot/idempotence acceptance remains outstanding. Site requires Debian 13; lab host supports Debian 12/13 amd64.

The controller needs Python/Ansible, project sources and SSH. Targets need Python 3 and become access. Local connection uses the controller as target.

## Prepare a dedicated QEMU host

Only on a dedicated host with /dev/kvm:

```bash
ansible-playbook -i ansible/inventory.lab-local.example.ini \
  ansible/lab-host.yml --syntax-check
ansible-playbook -i ansible/inventory.lab-local.example.ini \
  ansible/lab-host.yml -K -e opla_prepare_lab_host=true
```

Existing Docker Compose is retained. On a genuinely clean host without Docker, explicit `-e opla_install_docker=true` adds the official Docker apt repository and installs Docker CE/Compose. This is not a migration tool for an existing Docker distribution.

No user is added to the docker group and no SSH key is generated. Configure operator access separately. Afterwards follow bootstrap → role images → up → ready. Host dependencies do not fix the separate Debian 12 Suricata/libhtp2 guest image dependency issue.

## Private server configuration

Do not apply site.yml to the working lab host; it changes nginx, vendor Suricata and BPF attachment. Use a dedicated Debian 13 node with a data interface separate from management.

```bash
umask 077
mkdir -p "$HOME/.config/opla/deploy"
cp ansible/vars.example.yml "$HOME/.config/opla/deploy/vars.yml"
cp ansible/inventory.example.ini "$HOME/.config/opla/deploy/hosts.ini"
ansible-vault create "$HOME/.config/opla/deploy/vault.yml"
```

Set interface, home network, host name, reviewed image tags and `opla_bpf_object` (a path on the controller). Documentation addresses in 192.0.2.0/24 are placeholders. Do not enable management-interface override to bypass an accidental interface choice.

Remove vault_db_password/vault_zabbix_password from plaintext vars and put distinct passwords in Vault: database at least 24 characters from A–Z/a–z/0–9/_/-, Zabbix at least 16 without CHANGE_. Keep the Vault password separately. Avoid --diff with real secrets.

Install Docker Compose on the target first. Use a reviewed CI BPF artifact or compile with clang/libbpf headers; verify SHA256SUMS. Build metadata does not replace target-kernel verification.

## SSH

Example private inventory:

```ini
[opla]
security-node ansible_host=192.0.2.10 ansible_user=operator ansible_connection=ssh ansible_python_interpreter=/usr/bin/python3
```

Replace the address; use an existing SSH agent/IdentityFile, not a private key in Git. Verify host keys through a trusted channel; do not disable host key checking.

```bash
ansible -i "$HOME/.config/opla/deploy/hosts.ini" opla -m ansible.builtin.ping
ansible-playbook -i "$HOME/.config/opla/deploy/hosts.ini" \
  ansible/preflight.yml -K -e "@$HOME/.config/opla/deploy/vars.yml"
ansible-playbook -i "$HOME/.config/opla/deploy/hosts.ini" \
  ansible/site.yml -K --ask-vault-pass \
  -e "@$HOME/.config/opla/deploy/vars.yml" \
  -e "@$HOME/.config/opla/deploy/vault.yml"
```

Ansible ping checks remote Python execution, not ICMP. Check services, XDP, fresh metrics and an external client after deployment.

## VPN and bastion

VPN supplies a route; Ansible still uses SSH over it. Tor SOCKS/HTTP is not a replacement for a management VPN.

```bash
ip route get 10.66.0.10
ssh operator@10.66.0.10 true
```

Copy inventory.vpn.example.ini privately and replace addresses. VPN creation, keys and its firewall are not automated here. Do not choose the management wg0/tun0 as the protected data interface. Controller proxy variables do not automatically route target apt/Docker traffic.

inventory.jump.example.ini uses ProxyJump. Verify keys for both hosts; the bastion does not require an extra Ansible agent. VPN and ProxyJump can be combined when the addresses are reachable.

## Local server connection

On a separate Debian 13 security node:

```bash
ansible-playbook -i ansible/inventory.local.example.ini \
  ansible/preflight.yml -K -e "@$HOME/.config/opla/deploy/vars.yml"
ansible-playbook -i ansible/inventory.local.example.ini \
  ansible/site.yml -K --ask-vault-pass \
  -e "@$HOME/.config/opla/deploy/vars.yml" \
  -e "@$HOME/.config/opla/deploy/vault.yml"
```

This changes the current system, not a QEMU guest. Check conflicts on localhost 8080/10051 and nginx; local connection provides no isolation.

## Acceptance

```bash
sudo systemctl status opla-xdp opla-telemetry opla-suricata --no-pager
sudo bpftool net show
sudo bpftool prog show pinned /sys/fs/bpf/opla-server/program
sudo journalctl -u opla-telemetry -n 30 --no-pager
```

Server pins differ from lab pins. The lab scan-policy wrapper is hardcoded to lab maps and is not a server policy tool. Passive detection and Gmail/Proton polling are not installed by site.yml; optional mail is native Zabbix SMTP.

Repeat deployment, engine failure, management reachability, reboot and rollback require separate tests. Syntax checks establish none of these guarantees.
