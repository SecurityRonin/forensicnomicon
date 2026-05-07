#!/usr/bin/env bash
# review_loop.sh — run /review-dfir-feeds in batches until no [ ] items remain.
#
# Uses the same pending-review.md.lock convention as pending_lock.py so that
# concurrent feed watch cron runs and fetch_all_sources.py invocations cannot
# corrupt the file during an agent's read-modify-write cycle.
#
# Usage:
#   scripts/review_loop.sh [--pending PATH] [--dry-run]
#
# Environment:
#   GITSIGN_CREDENTIAL_CACHE   — set before running if using gitsign (see CLAUDE.md)

set -euo pipefail

PENDING="archive/sources/pending-review.md"
DRY_RUN=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --pending)   PENDING="$2"; shift 2 ;;
    --pending=*) PENDING="${1#--pending=}"; shift ;;
    --dry-run)   DRY_RUN=true; shift ;;
    *)           echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

LOCK_PATH="${PENDING}.lock"

# ── Lock helpers ──────────────────────────────────────────────────────────────

acquire_lock() {
  while true; do
    # noclobber: atomic create-if-not-exists
    if (set -o noclobber; printf '%s' "$$" > "$LOCK_PATH") 2>/dev/null; then
      return 0
    fi
    # Check if the owner PID is still alive
    owner=$(cat "$LOCK_PATH" 2>/dev/null || echo "")
    if [[ -n "$owner" ]] && kill -0 "$owner" 2>/dev/null; then
      echo "[review_loop] lock held by PID $owner — waiting..."
      sleep 2
    else
      echo "[review_loop] stale lock (PID $owner dead) — stealing"
      rm -f "$LOCK_PATH"
    fi
  done
}

release_lock() {
  [[ -f "$LOCK_PATH" ]] && rm -f "$LOCK_PATH" || true
}

trap 'release_lock' EXIT INT TERM

# ── Main loop ─────────────────────────────────────────────────────────────────

batch=0
while grep -q '^\- \[ \]' "$PENDING"; do
  batch=$((batch + 1))
  remaining=$(grep -c '^\- \[ \]' "$PENDING")
  echo ""
  echo "══════════════════════════════════════════════"
  echo " Batch #${batch} — ${remaining} items remaining"
  echo "══════════════════════════════════════════════"

  if [[ "$DRY_RUN" == "true" ]]; then
    echo "[dry-run] would run: claude -p /review-dfir-feeds"
    # In dry-run, simulate by breaking after one iteration
    break
  fi

  acquire_lock
  claude -p "/review-dfir-feeds"
  release_lock
done

remaining=$(grep -c '^\- \[ \]' "$PENDING" 2>/dev/null || echo 0)
echo ""
echo "══════════════════════════════════════════════"
echo " review_loop done — ${batch} batches completed"
echo " ${remaining} [ ] items remaining"
echo "══════════════════════════════════════════════"
