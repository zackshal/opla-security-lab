#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
role="${1:-victim}"
mode="${2:-build}"
[[ "$mode" == build || "$mode" == resume ]] || {
  echo 'usage: prepare-image.sh ROLE [resume]' >&2; exit 2;
}
case "$role" in
  victim) output=debian-12-xdp.qcow2; size=10G
    install_packages=clang,llvm,libbpf-dev,linux-libc-dev,bpftool,iproute2,python3,python3-yaml,nginx,hping3,curl,tcpdump,cloud-init,openssh-server,gcc,make,nftables,logrotate
    packages="$install_packages,suricata,suricata-update" ;;
  attacker) output=debian-12-attacker.qcow2; size=4G
    packages=hping3,nmap,arp-scan,yersinia,tcpdump,curl,python3,iproute2,cloud-init,openssh-server
    install_packages="$packages" ;;
  client) output=debian-12-client.qcow2; size=4G
    packages=curl,python3,iproute2,cloud-init,openssh-server
    install_packages="$packages" ;;
  *) echo 'role: victim|attacker|client' >&2; exit 2;;
esac
cd "$ROOT/images"
proxy_tmp=""
cleanup_proxy_tmp() {
  if [[ -n "$proxy_tmp" ]]; then
    rm -f -- "$proxy_tmp/99opla-proxy"
    rmdir -- "$proxy_tmp" 2>/dev/null || true
  fi
}
trap cleanup_proxy_tmp EXIT
if [[ "$mode" == build ]] && python3 "$ROOT/bin/opla-image-verify.py" --select "$role" >/dev/null 2>&1; then
  echo "PASS: current $role image already exists; preserving it."
  exit 0
fi
for tool in virt-customize virt-resize virt-cat qemu-img; do
  command -v "$tool" >/dev/null || { echo "BLOCKED: required image tool is missing: $tool" >&2; exit 2; }
done
[[ -f debian-12-base.qcow2 ]] || { echo 'Run make bootstrap' >&2; exit 1; }
stem="${output%.qcow2}"
resume_build=0
if [[ "$mode" == resume ]]; then
  mapfile -t partials < <(compgen -G "$stem*.part" || true)
  if [[ "${#partials[@]}" -ne 1 ]]; then
    echo "BLOCKED: resume requires exactly one candidate for $role; found ${#partials[@]}." >&2
    printf '  images/%s\n' "${partials[@]}" >&2
    exit 2
  fi
  partial="${partials[0]}"
  output="${partial%.part}"
  [[ "$partial" == "$stem"*.qcow2.part && -f "$partial" && ! -L "$partial" ]] || {
    echo "BLOCKED: unsafe partial candidate for $role" >&2; exit 2;
  }
  [[ ! -e "$output" && ! -L "$output" &&
     ! -e "$output.sha256" && ! -e "$output.role" && ! -e "$output.packages" ]] || {
    echo "BLOCKED: final image or metadata already exists beside $partial" >&2; exit 2;
  }
  case "$role" in victim) expected_size=$((10 * 1024**3));;
    attacker|client) expected_size=$((4 * 1024**3));; esac
  qemu-img info --output=json "$partial" | python3 -c '
import json,sys
info=json.load(sys.stdin)
expected=int(sys.argv[1])
if info.get("format") != "qcow2" or info.get("virtual-size") != expected or info.get("backing-filename"):
    raise SystemExit("BLOCKED: partial image identity/size is not resumable")
' "$expected_size"
  qemu-img check -f qcow2 "$partial"
  resume_build=1
elif compgen -G "$stem*.part" >/dev/null; then
  echo "BLOCKED: incomplete image generation exists for $role; inspect before retrying:" >&2
  compgen -G "$stem*.part" | sed 's#^#  images/#' >&2
  exit 2
fi
if [[ "$resume_build" -eq 0 ]] && { compgen -G "$stem*.qcow2" >/dev/null ||
   compgen -G "$stem.qcow2."* >/dev/null; }; then
  generation=2
  while [[ -e "$stem-g$generation.qcow2" || -e "$stem-g$generation.qcow2.part" ||
          -e "$stem-g$generation.qcow2.sha256" || -e "$stem-g$generation.qcow2.role" ||
          -e "$stem-g$generation.qcow2.packages" ]]; do
    ((generation+=1))
  done
  output="$stem-g$generation.qcow2"
fi
if [[ "$resume_build" -eq 0 ]]; then
  qemu-img create -f qcow2 "$output.part" "$size"
  virt-resize --expand /dev/sda1 debian-12-base.qcow2 "$output.part"
fi
# The base image may contain an operator-local apt proxy such as
# 127.0.0.1:10809. Inside libguestfs that loopback is not the host proxy.
# Remove only proxy directives from the temporary role image; never edit base.
virt-customize -a "$output.part" --run-command \
  'for f in /etc/apt/apt.conf /etc/apt/apt.conf.d/*; do if [ -f "$f" ]; then sed -i -E "/Acquire::.*::Proxy/Id" "$f"; fi; done'
if [[ -n "${OPLA_GUEST_APT_PROXY:-}" ]]; then
  proxy_tmp="$(mktemp -d "${TMPDIR:-/tmp}/opla-image-proxy.XXXXXX")"
  chmod 700 "$proxy_tmp"
  python3 - "$OPLA_GUEST_APT_PROXY" "$proxy_tmp/99opla-proxy" <<'PY'
import ipaddress
import os
import sys
from urllib.parse import urlsplit

value, destination = sys.argv[1:]
try:
    parsed = urlsplit(value)
    host = parsed.hostname
    port = parsed.port
    if (parsed.scheme != "http" or not host or parsed.username or parsed.password
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment
            or (port is not None and not 1 <= port <= 65535)):
        raise ValueError
    if host.lower() == "localhost":
        raise ValueError
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None and address.is_loopback:
        raise ValueError
except ValueError:
    raise SystemExit("OPLA_GUEST_APT_PROXY must be an http URL reachable from the libguestfs appliance, without credentials or localhost")

escaped = value.replace("\\", "\\\\").replace('"', '\\"')
with open(destination, "x", encoding="utf-8") as stream:
    stream.write(f'Acquire::http::Proxy "{escaped}";\n')
    stream.write(f'Acquire::https::Proxy "{escaped}";\n')
os.chmod(destination, 0o600)
PY
  virt-customize -a "$output.part" --upload \
    "$proxy_tmp/99opla-proxy:/etc/apt/apt.conf.d/99opla-proxy"
fi
# Verify every requested package inside the image before publishing it.
# The package list is defined by the selected VM role above.
verify_command=$(cat <<'GUEST_VERIFY'
set -eu

manifest=/etc/opla-dependencies-verified
temporary="${manifest}.tmp"
rm -f "$temporary"

for pkg in __PACKAGES__; do
    status=$(dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null) || {
        echo "BLOCKED: missing required package: $pkg" >&2
        exit 2
    }

    if [ "$status" != 'install ok installed' ]; then
        echo "BLOCKED: package not installed: $pkg" >&2
        exit 2
    fi

    dpkg-query -W -f='${binary:Package}\t${Version}\n' "$pkg" >> "$temporary"
done

mv "$temporary" "$manifest"
GUEST_VERIFY
)
verify_command="${verify_command/__PACKAGES__/${packages//,/ }}"

customize_args=(virt-customize -a "$output.part" --network --install "$install_packages")
if [[ "$role" == victim ]]; then
  # Bookworm's stable libhtp2 is too old for Suricata 7. Install both packages
  # from the already configured bookworm-backports suite as one dependency set.
  customize_args+=(--run-command 'apt-get -y -t bookworm-backports install suricata suricata-update')
fi
customize_args+=(--run-command "$verify_command" \
  --run-command 'dpkg-query -W > /etc/opla-packages.txt' \
  --run-command 'rm -f /etc/apt/apt.conf.d/99opla-proxy' \
  --run-command 'apt-get clean' \
  --run-command 'rm -rf /var/lib/apt/lists/*' \
  --run-command 'if command -v suricata >/dev/null; then systemctl disable suricata.service; fi' \
  --run-command 'cloud-init clean --logs')
if ! env -u http_proxy -u https_proxy -u all_proxy \
    -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY \
    "${customize_args[@]}"; then
  echo "BLOCKED: package preparation failed for $role. No image was published; inspect the retained candidate $output.part. Check direct repository access or set OPLA_GUEST_APT_PROXY to an HTTP proxy reachable from the libguestfs appliance (host localhost is not reachable there)." >&2
  exit 2
fi
if [[ "$role" == victim && "${SURICATA_ET_OPEN:-0}" == 1 ]]; then
  virt-customize -a "$output.part" --network --run-command 'suricata-update'
fi
qemu-img check -f qcow2 "$output.part"
mv "$output.part" "$output"
sha256sum "$output" > "$output.sha256"
printf '%s\n' "$role" > "$output.role"
# Publish the package inventory only after the in-guest dpkg verification has
# succeeded. The host verifier uses it to reject role images prepared before a
# required module (notably Suricata) was added to that role.
printf '%s\n' "${packages//,/ }" > "$output.packages"
