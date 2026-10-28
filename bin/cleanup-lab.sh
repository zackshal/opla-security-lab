#!/usr/bin/env bash
set -euo pipefail
echo 'BLOCKED: legacy cleanup-lab.sh is disabled; use make lab-delete-plan and make lab-delete.' >&2
exit 2
