#!/usr/bin/env bash
# Portable live-acceptance orchestrator. Works locally, in GitLab, in GitHub.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/lib/common.sh"

log "live-acceptance start (platform=$CI_PLATFORM, dry_run=$OPLA_DRY_RUN)"

source "$HERE/lib/preflight.sh"
source "$HERE/lib/lifecycle.sh"
source "$HERE/lib/evidence.sh"

# Verify, but do not fail the pipeline here; the CI job decides via verification.json.
python3 "$HERE/verify-evidence.py" --check "$OUTPUT_DIR" || true

log "live-acceptance done. See $OUTPUT_DIR/manifest.json"
cat "$OUTPUT_DIR/verification.json" 2>/dev/null || true
