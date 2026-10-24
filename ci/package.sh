#!/usr/bin/env bash
set -euo pipefail
: "${CI_COMMIT_SHA:?GitLab commit SHA required}"
[[ "$CI_COMMIT_SHA" =~ ^[0-9a-f]{40,64}$ ]] || exit 2
sha256sum -c dist/SHA256SUMS
package_dir="$(mktemp -d)"
trap 'rm -rf "$package_dir"' EXIT
cp dist/xdp_ddos_protect.o dist/compiler.txt dist/packages.txt "$package_dir/"
printf '%s\n' "$CI_COMMIT_SHA" > "$package_dir/COMMIT"
printf '%s\n' 'THRESHOLD=100 MAX_SOURCES=4096; runtime scan policy defaults to off' > "$package_dir/BUILD"
printf '%s\n' 'BPF compilation is not kernel verifier or live enforcement acceptance.' > "$package_dir/VALIDATION"
(cd "$package_dir" && sha256sum xdp_ddos_protect.o compiler.txt packages.txt COMMIT BUILD VALIDATION > SHA256SUMS)
archive="dist/opla-bpf-${CI_COMMIT_SHA:0:12}.tar.gz"
tar -czf "$archive" -C "$package_dir" .
sha256sum "$archive" > dist/delivery.sha256
