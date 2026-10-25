# Software tools and versions

[Русский](software.md) · **English**

## 1 Observed environment

The following values come from the user's `make versions` output of 24 October 2026. They describe an observed environment, not recommendations for the newest versions.

| Component | Recorded value |
|---|---|
| Host kernel | 7.2.9+deb13-amd64; package 7.2.9-1~bpo13+1 |
| Host QEMU | 10.0.13; package 1:10.0.13+ds-0+deb13u1 |
| Host nftables | 1.1.3 |
| Host Python | 3.13.5 |
| Host cloud-image-utils | 0.33-1 |
| Host dnsmasq | 2.91-1+deb13u2 |
| Host libguestfs-tools | 1:1.54.1-2+deb13u1; recheck `virt-customize` binary |
| Victim kernel | 6.1.0-54-cloud-amd64; 6.1.190-1 |
| Clang | 14.0.6 |
| bpftool | 7.1.0; libbpf 1.1 shown in version output |
| libbpf-dev | 1:1.1.2-0+deb12u1 |
| nginx | 1.22.1-9+deb12u10 |
| hping3 | 3.a2.ds2-10 |
| curl | 7.88.1-10+deb12u15 |
| tcpdump | 4.99.3-1 |
| Zabbix | alpine-7.0.19 server/web image |
| PostgreSQL | 16.10-alpine image; database `server_version` not separately captured |

Docker Engine/Compose versions and container RepoDigests still need recording. The host has Debian 13 packages, but `/etc/os-release` was not included in the protocol. `install-host.sh` automates Debian 12 only. An earlier `virt-customize` binary reported 1.52.3; reconcile with `command -v virt-customize`, `virt-customize --version` and `dpkg-query -W libguestfs-tools`.

The recorded SHA256 of the original base image is `b1b018dc1046fb21815f6cfe4b67ac1d56bc841e19c4ba2c16073031386ad774`. It is not proof that the nginx-prepared image is unchanged.

## 2 Free/open-source tool reference

The following Debian 12 upstream series are planning targets, not necessarily the exact versions used in the observed host. Individual package files may carry different license notices; consult `/usr/share/doc/<package>/copyright`.

| Tool / target series | Role | License overview | Official source |
|---|---|---|---|
| Debian 12, Linux 6.1 | Host and guests | Various free licenses; kernel GPL-2.0-only | https://www.debian.org/ |
| QEMU 7.2 and KVM | Host virtualization | QEMU GPL-2.0, component exceptions | https://www.qemu.org/ |
| cloud-init 22.4 | Guest initialization | Apache-2.0 OR GPL-3.0 | https://github.com/canonical/cloud-init |
| cloud-image-utils | cloud-localds seed images | GPL-3.0 | https://launchpad.net/cloud-utils |
| libguestfs/virt-resize 1.48 | Host image preparation | Library LGPL-2.1+, tools GPL-2.0+ | https://libguestfs.org/ |
| Clang/LLVM 14 | Guest BPF compilation | Apache-2.0 WITH LLVM-exception | https://llvm.org/ |
| GCC 12, GNU Make 4.3 | C packet harness and build | GPL-3.0+ with relevant runtime exception | https://gcc.gnu.org/ |
| libbpf 1.1 | BPF headers/library | LGPL-2.1-only OR BSD-2-Clause | https://github.com/libbpf/libbpf |
| bpftool | BPF load/map inspection | GPL-2.0-only OR BSD-2-Clause; dependencies vary | https://github.com/libbpf/bpftool |
| iproute2 6.1 | Network state and XDP attachment | GPL-2.0 | https://git.kernel.org/pub/scm/network/iproute2/iproute2.git/ |
| nftables 1.0 | Host network isolation | GPL-2.0 | https://netfilter.org/projects/nftables/ |
| dnsmasq | Lab bridge DHCP | GPL-2.0 OR GPL-3.0 | https://thekelleys.org.uk/dnsmasq/doc.html |
| OpenSSH 9.2 | SSH/scp | BSD and other free licenses | https://www.openssh.com/ |
| nginx 1.22 | Victim HTTP service | BSD-2-Clause | https://nginx.org/ |
| hping3 3.a2.ds2 | Bounded attacker SYN workload | GPL-2.0 | https://github.com/antirez/hping |
| Python 3.11 | Collector, API, tests, TUI | PSF-2.0 and component licenses | https://www.python.org/ |
| curl 7.88 | HTTP probing | curl license | https://curl.se/docs/copyright.html |
| tcpdump 4.99 | PCAP capture | BSD-3-Clause | https://www.tcpdump.org/ |
| socat 1.7 | Serial console | GPL-2.0 | http://www.dest-unreach.org/socat/ |
| systemd 252 | Services and VMs | Primarily LGPL-2.1+; some GPL components | https://systemd.io/ |
| util-linux 2.38 | flock and mountpoint | Various free licenses | https://github.com/util-linux/util-linux |
| Git 2.39 | Version control | GPL-2.0 | https://git-scm.com/ |
| Docker Engine/Compose v2 | Host monitoring containers | Apache-2.0 for Moby/Compose | https://github.com/moby/moby |
| Zabbix 7.0.19 | Metrics, events, dashboards | AGPL-3.0 | https://www.zabbix.com/license |
| PostgreSQL 16.10 | Zabbix database | PostgreSQL License | https://www.postgresql.org/about/licence/ |

Debian package revisions and image digests can change; record `make versions` and container RepoDigests at acceptance. Fixed image tags alone do not provide byte-for-byte reproducibility. Docker Desktop and proprietary plugins are not part of the planned stack.

## 3 Planning requirements and installation

| Location | Planning minimum | Software | Installation |
|---|---|---|---|
| Debian 12 amd64 host | 4 cores, 12 GiB RAM, 30 GiB disk, KVM | QEMU, libguestfs, cloud-localds, nftables, dnsmasq, Python, SSH, Docker/Compose | `sudo ./bin/install-host.sh` |
| Debian 12 victim | 2 vCPU, 2 GiB RAM, 10 GiB virtual disk | Clang, libbpf-dev, bpftool, nginx, iproute2, Python | `make image`; `cloud-init/victim.yaml` |
| Debian 12 attacker | 1 vCPU, 1 GiB RAM, 10 GiB virtual disk | hping3, SSH, tcpdump | `make image`; `cloud-init/attacker.yaml` |
| Debian 12 client | 1 vCPU, 512 MiB RAM, 10 GiB virtual disk | curl, SSH | `make image`; `cloud-init/client.yaml` |
| Host containers | Reserve 3 GiB RAM and at least 5 GiB disk | Zabbix, PostgreSQL | `make monitoring-up` |

These are estimated resources, not measured minima. All VMs use a prepared backing image with separate overlays. Packages are installed in all three guests for ease of reproduction, while the VM roles are distinct.

## 4 Record versions after testing

```bash
make versions
docker image inspect zabbix/zabbix-server-pgsql:alpine-7.0.19 \
  --format '{{json .RepoDigests}}'
docker image inspect zabbix/zabbix-web-nginx-pgsql:alpine-7.0.19 \
  --format '{{json .RepoDigests}}'
docker image inspect postgres:16.10-alpine --format '{{json .RepoDigests}}'
```

Save output to the ignored `reports/` directory and retain downloaded/prepared SHA256 manifests. Keep prepared images outside Git. Docker installation follows https://docs.docker.com/engine/install/debian/ (consulted 23 October 2026).
