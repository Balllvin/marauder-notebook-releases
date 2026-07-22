#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPOSITORY_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VERIFICATION_ROOT="$REPOSITORY_ROOT"

usage() {
  echo "usage: $0 [--root candidate-checkout]" >&2
}

die() {
  echo "error: $*" >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --root)
      shift
      [[ $# -gt 0 ]] || { usage; exit 2; }
      VERIFICATION_ROOT="$1"
      ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
  shift
done

VERIFICATION_ROOT="$(cd "$VERIFICATION_ROOT" && pwd)"
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

echo "Publisher boundary validation passed for $COMMIT."
