#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPOSITORY_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPOSITORY="Balllvin/marauder-notebook-releases"
INTAKE_REPOSITORY="Balllvin/marauder-notebook-release-intake"
REQUIRED_CHECK="Verify publisher boundary"
MODE=verify

usage() {
  echo "usage: $0 [--verify | --publish]" >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --verify) MODE=verify ;;
    --publish) MODE=publish ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
  shift
done

die() {
  echo "error: $*" >&2
  exit 1
}

for command in git gh jq python3 /usr/bin/ditto; do
  command -v "$command" >/dev/null || die "required command is unavailable: $command"
done
[[ "$(uname -s)" == "Darwin" ]] || die "Notebook publication must run on macOS"

canonical_github_repository_from_url() {
  /usr/bin/python3 - "$1" <<'PY'
from __future__ import annotations

import re
import sys
from urllib.parse import urlsplit

value = sys.argv[1]
repository = None
if value.startswith("git@github.com:"):
    repository = value.removeprefix("git@github.com:")
else:
    parsed = urlsplit(value)
    if (
        parsed.hostname == "github.com"
        and parsed.scheme in ("https", "ssh")
        and parsed.password is None
        and parsed.query == ""
        and parsed.fragment == ""
        and (parsed.username in (None, "git"))
    ):
        repository = parsed.path.lstrip("/")
if repository and repository.endswith(".git"):
    repository = repository[:-4]
if repository != "Balllvin/marauder-notebook-releases" or re.fullmatch(
    r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository or ""
) is None:
    raise SystemExit(1)
print(repository)
PY
}

cd "$REPOSITORY_ROOT"
[[ -z "$(git status --porcelain)" ]] || die "publisher checkout must be clean"
ORIGIN_REPOSITORY="$(canonical_github_repository_from_url "$(git remote get-url origin)")" \
  || die "origin must be the canonical $REPOSITORY repository"
[[ "$ORIGIN_REPOSITORY" == "$REPOSITORY" ]] \
  || die "origin must be the canonical $REPOSITORY repository"

git fetch origin refs/heads/main:refs/remotes/origin/main --prune
PUBLISHER_COMMIT="$(git rev-parse HEAD^{commit})"
ORIGIN_MAIN_COMMIT="$(git rev-parse refs/remotes/origin/main^{commit})"
[[ "$PUBLISHER_COMMIT" == "$ORIGIN_MAIN_COMMIT" ]] \
  || die "publisher must run from exact current origin/main"
CANONICAL_MAIN_LINE="$(git ls-remote --exit-code \
  "https://github.com/$REPOSITORY.git" refs/heads/main)" \
  || die "canonical publisher main could not be verified"
[[ "$CANONICAL_MAIN_LINE" == "$PUBLISHER_COMMIT"$'\t'"refs/heads/main" ]] \
  || die "publisher must match canonical protected main"

WORK_ROOT="$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/marauder-notebook-publisher.XXXXXX")"
cleanup() {
  rm -rf "$WORK_ROOT"
}
trap cleanup EXIT

PROTECTION="$WORK_ROOT/branch-protection.json"
GH_PROMPT_DISABLED=1 gh api \
  "repos/$REPOSITORY/branches/main/protection" >"$PROTECTION" \
  || die "unable to verify publisher branch protection"
jq -e --arg required_check "$REQUIRED_CHECK" '
  .required_status_checks.strict == true and
  (.required_status_checks.contexts | index($required_check) != null) and
  .enforce_admins.enabled == true and
  .required_linear_history.enabled == true and
  .required_conversation_resolution.enabled == true and
  .allow_force_pushes.enabled == false and
  .allow_deletions.enabled == false
' "$PROTECTION" >/dev/null \
  || die "publisher main does not have the required protected policy"
[[ "$(GH_PROMPT_DISABLED=1 gh api "repos/$REPOSITORY" --jq .visibility)" == "public" ]] \
  || die "publisher repository must be public"
[[ "$(GH_PROMPT_DISABLED=1 gh api "repos/$REPOSITORY/immutable-releases" \
  --jq '(.enabled == true) or (.enforced_by_owner == true)')" == "true" ]] \
  || die "publisher immutable releases must be enabled"

export GITHUB_REPOSITORY="$REPOSITORY"
export RUNNER_TEMP="$WORK_ROOT"
export NOTEBOOK_DISTRIBUTION_MODE=independent
export NOTEBOOK_EXPECTED_TEAM_IDENTIFIER=""

scripts/verify_openssl.sh >/dev/null
scripts/audit_latest_release.sh

RELEASES="$WORK_ROOT/releases.json"
SELECTION="$WORK_ROOT/selected-intake.json"
GH_PROMPT_DISABLED=1 gh api --paginate --slurp \
  "repos/$REPOSITORY/releases?per_page=100" >"$RELEASES"
python3 scripts/prepare_intake.py select \
  --repository-url "https://github.com/$INTAKE_REPOSITORY.git" \
  --releases "$RELEASES" \
  --result "$SELECTION"
AVAILABLE="$(jq -r '
  if (.available | type) == "boolean"
  then (.available | tostring)
  else error("available must be a boolean")
  end
' "$SELECTION")"
IGNORED_REF_COUNT="$(jq -er \
  '.ignored_ref_count | select(type == "number" and . >= 0 and floor == .)' \
  "$SELECTION")"
if [[ "$IGNORED_REF_COUNT" -gt 0 ]]; then
  echo "Ignored $IGNORED_REF_COUNT stale, malformed, or ambiguous intake refs."
fi
if [[ "$AVAILABLE" != "true" ]]; then
  echo "No locked unpublished Notebook release intake is waiting."
  exit 0
fi

INTAKE_CHECKOUT="$WORK_ROOT/intake-repository"
git init -q "$INTAKE_CHECKOUT"
git -C "$INTAKE_CHECKOUT" remote add origin \
  "https://github.com/$INTAKE_REPOSITORY.git"
git -C "$INTAKE_CHECKOUT" fetch --no-tags origin \
  main:refs/remotes/intake/main
git -C "$INTAKE_CHECKOUT" fetch --no-tags origin \
  '+refs/heads/publication/*:refs/remotes/intake/publication/*'

VERIFIED_INTAKE="$WORK_ROOT/verified-intake"
VERIFIED_RELEASE="$WORK_ROOT/verified-release.json"
OPENSSL_BIN="$(scripts/verify_openssl.sh)"
python3 scripts/prepare_intake.py prepare-pending \
  --repository "$INTAKE_CHECKOUT" \
  --selection "$SELECTION" \
  --output "$VERIFIED_INTAKE" \
  --openssl "$OPENSSL_BIN" \
  --trusted-main-ref refs/remotes/intake/main \
  --result "$VERIFIED_RELEASE"

INVALID_COUNT="$(jq -er \
  '.invalid_candidate_count | select(type == "number" and . >= 0 and floor == .)' \
  "$VERIFIED_RELEASE")"
if [[ "$INVALID_COUNT" -gt 0 ]]; then
  echo "Quarantined $INVALID_COUNT invalid intake candidate(s)."
fi
RELEASE_VERSION="$(jq -er .version "$VERIFIED_RELEASE")"
BUILD_NUMBER="$(jq -er .build_number "$VERIFIED_RELEASE")"
RELEASE_TAG="$(jq -er .tag "$VERIFIED_RELEASE")"
ARCHIVE_NAME="$(jq -er .archive "$VERIFIED_RELEASE")"
SOURCE_COMMIT="$(jq -er .source_commit "$VERIFIED_RELEASE")"
INTAKE_BRANCH="$(jq -er .branch "$VERIFIED_RELEASE")"
INTAKE_COMMIT="$(jq -er .intake_commit "$VERIFIED_RELEASE")"
PUBLICATION_LOCK_COMMIT="$(jq -er .publication_lock_commit "$VERIFIED_RELEASE")"

ARCHIVE="$VERIFIED_INTAKE/$ARCHIVE_NAME"
EXPANDED="$WORK_ROOT/expanded-release"
mkdir "$EXPANDED"
python3 scripts/verify_release_archive.py --archive "$ARCHIVE"
/usr/bin/ditto -x -k "$ARCHIVE" "$EXPANDED"
APP="$EXPANDED/Marauder Notebook.app"
[[ -d "$APP" && ! -L "$APP" ]] || die "verified archive has no ordinary app bundle"
EXTRA_ENTRY="$(/usr/bin/find "$EXPANDED" -mindepth 1 -maxdepth 1 \
  ! -name 'Marauder Notebook.app' -print -quit)"
[[ -z "$EXTRA_ENTRY" ]] || die "verified archive contains an unexpected root entry"
python3 scripts/verify_app_bundle.py \
  --app "$APP" \
  --release-version "$RELEASE_VERSION" \
  --build-number "$BUILD_NUMBER" \
  --distribution-mode independent

CURRENT_INTAKE_REF="$(git ls-remote --exit-code --heads \
  "https://github.com/$INTAKE_REPOSITORY.git" \
  "refs/heads/$INTAKE_BRANCH")"
[[ "$CURRENT_INTAKE_REF" == "$INTAKE_COMMIT"$'\t'"refs/heads/$INTAKE_BRANCH" ]] \
  || die "intake candidate changed during verification"

CURRENT_RELEASES="$WORK_ROOT/current-releases.json"
PUBLISHED_PLAN="$WORK_ROOT/published-source-plan.json"
GH_PROMPT_DISABLED=1 gh api --paginate --slurp \
  "repos/$REPOSITORY/releases?per_page=100" >"$CURRENT_RELEASES"
python3 scripts/release_state.py audit-published \
  --releases "$CURRENT_RELEASES" \
  --result "$PUBLISHED_PLAN"
LATEST_PUBLISHED_TAG="$(jq -er '.tags[-1] // ""' "$PUBLISHED_PLAN")"
SOURCE_LINK_ARGUMENTS=(
  --manifest "$VERIFIED_INTAKE/notebook-release.json"
  --openssl "$OPENSSL_BIN"
)
if [[ -n "$LATEST_PUBLISHED_TAG" ]]; then
  PREVIOUS_RELEASE="$WORK_ROOT/previous-signed-release"
  mkdir "$PREVIOUS_RELEASE"
  GH_PROMPT_DISABLED=1 gh release download "$LATEST_PUBLISHED_TAG" \
    --repo "$REPOSITORY" \
    --pattern notebook-release.json \
    --dir "$PREVIOUS_RELEASE"
  [[ -f "$PREVIOUS_RELEASE/notebook-release.json" && \
     ! -L "$PREVIOUS_RELEASE/notebook-release.json" ]] \
    || die "previous release manifest is unavailable"
  SOURCE_LINK_ARGUMENTS+=(
    --previous-manifest "$PREVIOUS_RELEASE/notebook-release.json"
  )
fi
python3 scripts/verify_intake.py assert-source-link "${SOURCE_LINK_ARGUMENTS[@]}"
python3 scripts/verify_intake.py assert-newer \
  --manifest "$VERIFIED_INTAKE/notebook-release.json" \
  --releases "$CURRENT_RELEASES"

if [[ "$MODE" == "verify" ]]; then
  echo "Verified locked Notebook release $RELEASE_TAG without publishing."
  exit 0
fi

python3 scripts/publish_release.py \
  --repository "$REPOSITORY" \
  --intake-repository "$INTAKE_REPOSITORY" \
  --publisher-commit "$PUBLISHER_COMMIT" \
  --release-version "$RELEASE_VERSION" \
  --build-number "$BUILD_NUMBER" \
  --release-tag "$RELEASE_TAG" \
  --archive-name "$ARCHIVE_NAME" \
  --source-commit "$SOURCE_COMMIT" \
  --intake-branch "$INTAKE_BRANCH" \
  --intake-commit "$INTAKE_COMMIT" \
  --publication-lock-commit "$PUBLICATION_LOCK_COMMIT" \
  --intake "$VERIFIED_INTAKE" \
  --work "$WORK_ROOT/publish-state" \
  --distribution-mode independent

scripts/audit_latest_release.sh
echo "Published and independently reverified $RELEASE_TAG."
