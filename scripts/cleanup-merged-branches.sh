#!/usr/bin/env bash
# cleanup-merged-branches.sh
#
# Deletes remote branches that have been merged into main.
# Safe to run multiple times (skips already-deleted branches).
#
# Usage: bash scripts/cleanup-merged-branches.sh
#        bash scripts/cleanup-merged-branches.sh --dry-run

set -euo pipefail

DRY_RUN=false
if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN=true
  echo "[dry-run] No branches will be deleted."
fi

REMOTE="origin"
BASE="$REMOTE/main"

# Branches to always keep, regardless of merge status
KEEP=(
  "main"
  "master"
)

echo "Fetching latest remote refs..."
git fetch --all --prune

echo ""
echo "Branches merged into $BASE:"
MERGED=$(git branch -r --merged "$BASE" \
  | grep "^  $REMOTE/" \
  | sed "s|  $REMOTE/||" \
  | grep -v "^main$" \
  | grep -v "^master$" \
  | sort)

if [[ -z "$MERGED" ]]; then
  echo "  (none — already clean)"
  exit 0
fi

echo "$MERGED" | while IFS= read -r branch; do
  # Skip any branch in the keep list
  skip=false
  for keep in "${KEEP[@]}"; do
    if [[ "$branch" == "$keep" ]]; then
      skip=true
      break
    fi
  done
  if $skip; then
    echo "  [skip] $branch"
    continue
  fi

  if $DRY_RUN; then
    echo "  [would delete] $branch"
  else
    echo "  Deleting $branch..."
    git push "$REMOTE" --delete "$branch" || echo "  [warn] Failed to delete $branch (may already be gone)"
  fi
done

echo ""
echo "Done. Remaining remote branches:"
git branch -r | grep -v HEAD | sort
