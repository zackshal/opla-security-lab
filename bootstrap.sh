#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/images"
BASE_URL="${BASE_URL:-https://cloud.debian.org/images/cloud/bookworm/latest}"
NAME=debian-12-genericcloud-amd64.qcow2
# Update BASE_SHA512 only after reviewing the official Debian checksum file.
# This prevents a mutable `latest` URL from silently changing the lab base.
BASE_SHA512="${BASE_SHA512:-0464b5d4ae3aa4f658468d88da83af7857b71548b30d46dcb6282770955a747fb95a983476db90d25afd0653af607224c7ebd05122ab71faa106fd712aaad652}"
curl --fail --location "$BASE_URL/SHA512SUMS" -o SHA512SUMS.part
curl --fail --location "$BASE_URL/$NAME" -o "$NAME.part"
LINE="$(grep -E "[ *]$NAME$" SHA512SUMS.part)"
[[ -n "$LINE" ]] || { echo 'Образ отсутствует в SHA512SUMS' >&2; exit 1; }
ACTUAL_SHA512="$(awk '{print $1}' <<<"$LINE")"
[[ "$ACTUAL_SHA512" =~ ^[a-f0-9]{128}$ && "$ACTUAL_SHA512" == "$BASE_SHA512" ]] || {
  echo "BLOCKED: base image SHA-512 differs from pinned BASE_SHA512" >&2
  echo "  expected: $BASE_SHA512" >&2
  echo "  received: $ACTUAL_SHA512" >&2
  exit 2
}
printf '%s\n' "$LINE" | sed "s/$NAME$/$NAME.part/" | sha512sum -c -
mv "$NAME.part" debian-12-base.qcow2
sha256sum debian-12-base.qcow2 > downloaded.sha256
printf '%s\n' "$BASE_SHA512" > source-sha512.txt
printf '%s\n' "$BASE_URL/$NAME" > source-url.txt
rm SHA512SUMS.part
echo 'Базовый образ проверен. Теперь make image.'
