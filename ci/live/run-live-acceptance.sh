#!/usr/bin/env bash
# Portable live-acceptance orchestrator. Works locally, in GitLab, in GitHub.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/lib/common.sh"

log "live-acceptance start (platform=$CI_PLATFORM, dry_run=$OPLA_DRY_RUN)"

# A dry run must not probe the host or enter lifecycle code. Emit the same
# machine-readable shape as a real run, then let the verifier explain why this
# is not an acceptance result.
if [[ "$OPLA_DRY_RUN" == "1" ]]; then
  jq -n \
    --arg platform "$CI_PLATFORM" \
    --arg commit "$(git -c core.abbrev=40 rev-parse HEAD 2>/dev/null || echo unknown)" \
    '{
      schema_version: 1, platform: $platform, commit: $commit,
      git_dirty: true, lab: {id: "lab-DRYRUN00", scenario: "dry-run"},
      started_at: (now|todateiso8601), finished_at: (now|todateiso8601),
      preflight: {status: "SKIPPED", reason: "OPLA_DRY_RUN=1"},
      evidence: {status: "INCOMPLETE", missing: ["dry-run-is-not-acceptance"]},
      recovery: "SKIPPED", steps: [], artifacts: []
    }' > "$OUTPUT_DIR/manifest.json"
  python3 "$HERE/verify-evidence.py" --check "$OUTPUT_DIR"
  exit $?
fi

source "$HERE/lib/preflight.sh"
source "$HERE/lib/lifecycle.sh"
source "$HERE/lib/evidence.sh"

# Verification is the acceptance gate. Preserve its non-zero status so a blocked
# evidence set cannot be reported as a successful orchestrator run.
python3 "$HERE/verify-evidence.py" --check "$OUTPUT_DIR"

log "live-acceptance done. See $OUTPUT_DIR/manifest.json"
cat "$OUTPUT_DIR/verification.json" 2>/dev/null || true
