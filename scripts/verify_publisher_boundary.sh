#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPOSITORY_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPOSITORY="Balllvin/marauder-notebook-releases"
REQUIRED_CHECK="Verify publisher boundary"
RECORD_STATUS=false
VERIFICATION_ROOT="$REPOSITORY_ROOT"

usage() {
  echo "usage: $0 [--root candidate-checkout] [--record-status]" >&2
}

die() {
  echo "error: $*" >&2
  exit 1
}

require_trusted_policy_checkout() {
  local canonical_main_line
  local origin_url
  local policy_commit

  [[ "$VERIFICATION_ROOT" != "$REPOSITORY_ROOT" ]] \
    || die "status recording requires a separate candidate checkout"
  cd "$REPOSITORY_ROOT"
  [[ -z "$(git status --porcelain)" ]] \
    || die "trusted publisher policy checkout must be clean"
  origin_url="$(git remote get-url origin)"
  case "$origin_url" in
    git@github.com:Balllvin/marauder-notebook-releases.git|\
    https://github.com/Balllvin/marauder-notebook-releases.git)
      ;;
    *) die "trusted publisher policy origin is not canonical" ;;
  esac
  git fetch origin refs/heads/main:refs/remotes/origin/main --prune
  policy_commit="$(git rev-parse HEAD^{commit})"
  [[ "$policy_commit" == "$(git rev-parse refs/remotes/origin/main^{commit})" ]] \
    || die "trusted publisher policy must be exact current origin/main"
  canonical_main_line="$(git ls-remote --exit-code \
    "https://github.com/$REPOSITORY.git" refs/heads/main)" \
    || die "canonical publisher main could not be verified"
  [[ "$canonical_main_line" == "$policy_commit"$'\t'"refs/heads/main" ]] \
    || die "trusted publisher policy must match canonical main"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --root)
      shift
      [[ $# -gt 0 ]] || { usage; exit 2; }
      VERIFICATION_ROOT="$1"
      ;;
    --record-status) RECORD_STATUS=true ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
  shift
done

VERIFICATION_ROOT="$(cd "$VERIFICATION_ROOT" && pwd)"
if [[ "$RECORD_STATUS" == "true" ]]; then
  require_trusted_policy_checkout
fi
cd "$VERIFICATION_ROOT"
[[ -z "$(git status --porcelain)" ]] || {
  echo "error: publisher checkout must be clean" >&2
  exit 1
}
COMMIT="$(git rev-parse HEAD^{commit})"
[[ "$COMMIT" =~ ^[0-9a-f]{40}$ ]]

ACTIONLINT_ROOT="$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/notebook-actionlint.XXXXXX")"
cleanup() {
  rm -rf "$ACTIONLINT_ROOT"
}
trap cleanup EXIT

"$SCRIPT_DIR/install_actionlint.sh" "$ACTIONLINT_ROOT"
"$ACTIONLINT_ROOT/actionlint" \
  .github/workflows/notebook-release-publish.yml \
  .github/workflows/publisher-ci.yml
python3 -m compileall -q scripts tests
bash -n scripts/*.sh
scripts/verify_openssl.sh >/dev/null
python3 -m unittest discover -s tests -p 'test_*.py' -v

if [[ "$RECORD_STATUS" == "true" ]]; then
  command -v gh >/dev/null || {
    echo "error: gh is required to record the local result" >&2
    exit 1
  }
  [[ "$(GH_PROMPT_DISABLED=1 gh api "repos/$REPOSITORY/commits/$COMMIT" --jq .sha)" == "$COMMIT" ]] || {
    echo "error: validated commit is not present in $REPOSITORY" >&2
    exit 1
  }
  GH_PROMPT_DISABLED=1 gh api --method POST \
    "repos/$REPOSITORY/statuses/$COMMIT" \
    -f state=success \
    -f context="$REQUIRED_CHECK" \
    -f description="Publisher boundary validation passed locally" >/dev/null
  echo "Recorded $REQUIRED_CHECK on $COMMIT."
else
  echo "Publisher boundary validation passed for $COMMIT."
fi
