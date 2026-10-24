# Ansible

[Русский](README.md) · **English**

See [deployment](../docs/deployment.en.md) for local execution, SSH, VPN and bastion examples.

| Playbook | Purpose | Target |
|---|---|---|
| `lab-host.yml` | QEMU/KVM dependencies; explicit optional Docker installation | Dedicated Debian 12/13 amd64 host |
| `preflight.yml` | Read-only interface, Compose and controller BPF object checks | Debian 13 security node |
| `site.yml` | XDP, Suricata, nginx, local Zabbix/PostgreSQL and telemetry | Dedicated Debian 13 security node |

`lab-host.yml` does not create VMs/images or start monitoring. `site.yml` requires Docker Compose and a precompiled controller-side BPF object; it does not create the three-VM lab. It does not install the lab's passive AF_PACKET detector, Tor or Gmail/Proton polling daemon. Optional mail configuration uses Zabbix's native media type.

Example inventories contain no usable credentials. Local connection runs on the current machine; VPN examples still use SSH over an existing VPN route. VPN creation is not implemented.
