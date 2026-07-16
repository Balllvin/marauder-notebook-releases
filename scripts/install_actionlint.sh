#!/usr/bin/env bash

set -euo pipefail

VERSION="1.7.12"
DESTINATION="${1:-}"
[[ -n "$DESTINATION" ]] || {
  echo "usage: $0 <destination-directory>" >&2
  exit 2
}

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)
    ARCHIVE="actionlint_${VERSION}_darwin_arm64.tar.gz"
    SHA256="aba9ced2dee8d27fecca3dc7feb1a7f9a52caefa1eb46f3271ea66b6e0e6953f"
    ;;
  Darwin-x86_64)
    ARCHIVE="actionlint_${VERSION}_darwin_amd64.tar.gz"
    SHA256="5b44c3bc2255115c9b69e30efc0fecdf498fdb63c5d58e17084fd5f16324c644"
    ;;
  *)
    echo "unsupported actionlint runner architecture: $(uname -s)-$(uname -m)" >&2
    exit 1
    ;;
esac

mkdir -p "$DESTINATION"
[[ -z "$(find "$DESTINATION" -mindepth 1 -maxdepth 1 -print -quit)" ]] || {
  echo "actionlint destination must be empty" >&2
  exit 1
}
TEMPORARY="$(mktemp -d "${TMPDIR:-/tmp}/notebook-actionlint.XXXXXX")"
trap 'rm -rf "$TEMPORARY"' EXIT
curl --fail --location --silent --show-error \
  --proto '=https' --tlsv1.2 \
  "https://github.com/rhysd/actionlint/releases/download/v${VERSION}/${ARCHIVE}" \
  --output "$TEMPORARY/$ARCHIVE"
ACTUAL_SHA256="$(shasum -a 256 "$TEMPORARY/$ARCHIVE" | awk '{print $1}')"
[[ "$ACTUAL_SHA256" == "$SHA256" ]] || {
  echo "actionlint archive checksum mismatch" >&2
  exit 1
}
tar -xzf "$TEMPORARY/$ARCHIVE" -C "$TEMPORARY"
install -m 0755 "$TEMPORARY/actionlint" "$DESTINATION/actionlint"
"$DESTINATION/actionlint" -version | grep -Fx "${VERSION}" >/dev/null
