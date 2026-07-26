#!/usr/bin/env bash

set -euo pipefail

: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"

[[ "$(gh api "repos/$GITHUB_REPOSITORY/immutable-releases" \
  --jq '(.enabled == true) or (.enforced_by_owner == true)')" == "true" ]]

WORK_ROOT="$(mktemp -d "$RUNNER_TEMP/notebook-release-audit.XXXXXX")"
cleanup() {
  rm -rf "$WORK_ROOT"
}
trap cleanup EXIT

ALL_RELEASES="$WORK_ROOT/releases.json"
PUBLISHED_PLAN="$WORK_ROOT/published-plan.json"
gh api --paginate --slurp \
  "repos/$GITHUB_REPOSITORY/releases?per_page=100" >"$ALL_RELEASES"
python3 scripts/release_state.py audit-published \
  --releases "$ALL_RELEASES" \
  --result "$PUBLISHED_PLAN"
PUBLISHED_COUNT="$(jq -er '.tags | length' "$PUBLISHED_PLAN")"

OWNER="${GITHUB_REPOSITORY%%/*}"
REPOSITORY="${GITHUB_REPOSITORY#*/}"
# GraphQL variables are intentionally expanded by GitHub.
# shellcheck disable=SC2016
LATEST_QUERY="$(gh api graphql \
  -F owner="$OWNER" \
  -F name="$REPOSITORY" \
  -f query='query($owner: String!, $name: String!) {
    repository(owner: $owner, name: $name) {
      latestRelease { tagName isDraft isPrerelease }
    }
  }')"
if [[ "$(jq -r '.data.repository.latestRelease == null' <<<"$LATEST_QUERY")" == "true" ]]; then
  [[ "$PUBLISHED_COUNT" -eq 0 ]] || {
    echo "GitHub has published releases but reports no latest release." >&2
    exit 1
  }
  echo "No published Notebook release exists yet."
  exit 0
fi
[[ "$PUBLISHED_COUNT" -gt 0 ]]

printf '%s' "$LATEST_QUERY" | jq -e \
  '.data.repository.latestRelease.isDraft == false and
   .data.repository.latestRelease.isPrerelease == false' >/dev/null
RELEASE_TAG="$(jq -er '.data.repository.latestRelease.tagName' <<<"$LATEST_QUERY")"
[[ "$RELEASE_TAG" == "$(jq -er '.tags[-1]' "$PUBLISHED_PLAN")" ]]
LATEST_RELEASE="$(gh api "repos/$GITHUB_REPOSITORY/releases/tags/$RELEASE_TAG")"

printf '%s' "$LATEST_RELEASE" | jq -e \
  '.draft == false and .prerelease == false and .immutable == true' >/dev/null
[[ "$(printf '%s' "$LATEST_RELEASE" | jq -er '.tag_name')" == "$RELEASE_TAG" ]]
[[ "$RELEASE_TAG" =~ ^notebook-v([0-9]+)\.([0-9]+)\.([0-9]+)-([1-9][0-9]*)$ ]]

while IFS= read -r published_tag; do
  ATTESTED=false
  for attempt in 1 2 3; do
    : "$attempt"
    if gh release verify "$published_tag" --repo "$GITHUB_REPOSITORY" >/dev/null 2>&1; then
      ATTESTED=true
      break
    fi
    sleep 5
  done
  [[ "$ATTESTED" == "true" ]] || {
    echo "Published release $published_tag has no valid GitHub attestation." >&2
    exit 1
  }
done < <(jq -er '.tags[]' "$PUBLISHED_PLAN")

AUDIT="$WORK_ROOT/assets"
mkdir "$AUDIT"
gh release download "$RELEASE_TAG" --repo "$GITHUB_REPOSITORY" --dir "$AUDIT"
RELEASE_VERSION="$(jq -er '.version' "$AUDIT/notebook-release.json")"
BUILD_NUMBER="$(jq -er '.build_number' "$AUDIT/notebook-release.json")"
SOURCE_COMMIT="$(jq -er '.source.commit' "$AUDIT/notebook-release.json")"
PUBLICATION_BRANCH="publication/$RELEASE_VERSION-$BUILD_NUMBER-$SOURCE_COMMIT"
OPENSSL_BIN="$(scripts/verify_openssl.sh)"
python3 scripts/verify_intake.py validate \
  --intake "$AUDIT" \
  --branch "$PUBLICATION_BRANCH" \
  --openssl "$OPENSSL_BIN" \
  --allow-legacy-published \
  --result "$WORK_ROOT/verified-release.json"
[[ "$(jq -er '.tag' "$WORK_ROOT/verified-release.json")" == "$RELEASE_TAG" ]]
RELEASE_DISTRIBUTION_MODE="$(jq -er '.distribution_mode' "$WORK_ROOT/verified-release.json")"

EXPECTED_ASSETS="$WORK_ROOT/expected-assets"
ARCHIVE_NAME="$(jq -er '.archive' "$WORK_ROOT/verified-release.json")"

EXPANDED="$WORK_ROOT/expanded-release"
mkdir "$EXPANDED"
python3 scripts/verify_release_archive.py --archive "$AUDIT/$ARCHIVE_NAME"
/usr/bin/ditto -x -k "$AUDIT/$ARCHIVE_NAME" "$EXPANDED"
APP="$EXPANDED/Marauder Notebook.app"
[[ -d "$APP" && ! -L "$APP" ]]
EXTRA_ENTRY="$(/usr/bin/find "$EXPANDED" -mindepth 1 -maxdepth 1 ! -name 'Marauder Notebook.app' -print -quit)"
[[ -z "$EXTRA_ENTRY" ]]
VERIFY_ARGUMENTS=(
  --app "$APP"
  --release-version "$RELEASE_VERSION"
  --build-number "$BUILD_NUMBER"
  --distribution-mode "$RELEASE_DISTRIBUTION_MODE"
)
if [[ "$RELEASE_TAG" == "notebook-v1.0.4-5" ]]; then
  VERIFY_ARGUMENTS+=(--allow-legacy-automatic-update-default)
fi
if [[ "$RELEASE_DISTRIBUTION_MODE" == "developer-id" ]]; then
  [[ "${NOTEBOOK_EXPECTED_TEAM_IDENTIFIER:-}" =~ ^[A-Z0-9]{10}$ ]]
  VERIFY_ARGUMENTS+=(
    --expected-team-identifier "$NOTEBOOK_EXPECTED_TEAM_IDENTIFIER"
  )
elif [[ "$RELEASE_DISTRIBUTION_MODE" == "independent" ]]; then
  [[ "$RELEASE_DISTRIBUTION_MODE" == "independent" ]]
else
  [[ "$RELEASE_DISTRIBUTION_MODE" == "account-free" ]]
fi
python3 scripts/verify_app_bundle.py "${VERIFY_ARGUMENTS[@]}"
if [[ "$RELEASE_DISTRIBUTION_MODE" == "developer-id" ]]; then
  /usr/bin/xcrun stapler validate "$APP"
  /usr/sbin/spctl --assess --type execute --verbose=4 "$APP"
elif [[ "$RELEASE_DISTRIBUTION_MODE" == "account-free" ]]; then
  python3 scripts/verify_account_free_gatekeeper.py --app "$APP"
  echo "Verified account-free integrity and the required first-launch macOS approval boundary."
else
  echo "Verified one legacy independently signed release as historical input only."
fi

printf '%s\n' \
  "$ARCHIVE_NAME" \
  "$ARCHIVE_NAME.sha256" \
  appcast.xml \
  notebook-release.json \
  update-feed.json \
  | LC_ALL=C sort >"$EXPECTED_ASSETS"

VERIFIED=false
for attempt in 1 2 3 4 5 6 7 8 9 10 11 12; do
  : "$attempt"
  if gh release verify "$RELEASE_TAG" --repo "$GITHUB_REPOSITORY" >/dev/null 2>&1; then
    ASSETS_VERIFIED=true
    while IFS= read -r name; do
      if ! gh release verify-asset "$RELEASE_TAG" "$AUDIT/$name" \
        --repo "$GITHUB_REPOSITORY" >/dev/null 2>&1; then
        ASSETS_VERIFIED=false
        break
      fi
    done <"$EXPECTED_ASSETS"
    if [[ "$ASSETS_VERIFIED" == "true" ]]; then
      VERIFIED=true
      break
    fi
  fi
  sleep 5
done
[[ "$VERIFIED" == "true" ]] || {
  echo "The latest immutable release or one of its assets has no valid GitHub attestation." >&2
  exit 1
}

echo "Verified immutable release and asset attestations for $RELEASE_TAG."
