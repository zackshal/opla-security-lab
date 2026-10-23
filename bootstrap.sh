#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/images"
BASE_URL="${BASE_URL:-https://cloud.debian.org/images/cloud/bookworm/latest}"
NAME=debian-12-genericcloud-amd64.qcow2
# latest используется только для первого скачивания. Фактический хеш сохраняем рядом.
curl --fail --location "$BASE_URL/SHA512SUMS" -o SHA512SUMS.part
curl --fail --location "$BASE_URL/$NAME" -o "$NAME.part"
LINE="$(grep -E "[ *]$NAME$" SHA512SUMS.part)"
[[ -n "$LINE" ]] || { echo 'Образ отсутствует в SHA512SUMS' >&2; exit 1; }
printf '%s\n' "$LINE" | sed "s/$NAME$/$NAME.part/" | sha512sum -c -
mv "$NAME.part" debian-12-base.qcow2
sha256sum debian-12-base.qcow2 > downloaded.sha256
printf '%s\n' "$BASE_URL/$NAME" > source-url.txt
rm SHA512SUMS.part
echo 'Базовый образ проверен. Теперь make image.'
