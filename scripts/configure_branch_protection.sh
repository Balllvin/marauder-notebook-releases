#!/usr/bin/env bash

set -euo pipefail

REPOSITORY="Balllvin/marauder-notebook-releases"
BRANCH="main"
REQUIRED_CHECK="Verify publisher boundary"
APPLY=false

usage() {
  echo "usage: $0 [--apply]" >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply) APPLY=true ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
  shift
done

POLICY_FILE="$(mktemp "${TMPDIR:-/tmp}/notebook-branch-protection.XXXXXX")"
cleanup() {
  rm -f "$POLICY_FILE"
}
trap cleanup EXIT

cat >"$POLICY_FILE" <<JSON
{
  "required_status_checks": {
    "strict": true,
    "contexts": ["$REQUIRED_CHECK"]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": false,
    "required_approving_review_count": 0,
    "require_last_push_approval": false
  },
  "restrictions": null,
  "required_linear_history": true,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "block_creations": false,
  "required_conversation_resolution": true,
  "lock_branch": false,
  "allow_fork_syncing": true
}
JSON

if [[ "$APPLY" != "true" ]]; then
  echo "Dry run: branch protection was not changed. Review this policy, then rerun with --apply:"
  cat "$POLICY_FILE"
  exit 0
fi

[[ -n "${GH_TOKEN:-}" ]] || {
  echo "GH_TOKEN is required to apply branch protection." >&2
  exit 1
}
[[ "$(gh api "repos/$REPOSITORY" --jq .full_name)" == "$REPOSITORY" ]]
gh api \
  --method PUT \
  "repos/$REPOSITORY/branches/$BRANCH/protection" \
  --input "$POLICY_FILE" >/dev/null

ACTUAL_CHECKS="$(gh api \
  "repos/$REPOSITORY/branches/$BRANCH/protection" \
  --jq '.required_status_checks.contexts | sort | join("\n")')"
[[ "$ACTUAL_CHECKS" == "$REQUIRED_CHECK" ]] || {
  echo "Branch protection did not retain the exact required publisher check." >&2
  exit 1
}
echo "Protected $REPOSITORY/$BRANCH with required check: $REQUIRED_CHECK"
