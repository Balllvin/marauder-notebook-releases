#!/usr/bin/env bash

set -euo pipefail

OPENSSL_BIN="$(brew --prefix openssl@3)/bin/openssl"
[[ -x "$OPENSSL_BIN" ]]
"$OPENSSL_BIN" version | grep -Eq '^OpenSSL 3\.'

WORK_ROOT="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/notebook-openssl.XXXXXX")"
cleanup() {
  rm -rf "$WORK_ROOT"
}
trap cleanup EXIT

printf '%s\n' 'Marauder Notebook release verifier' >"$WORK_ROOT/payload"
"$OPENSSL_BIN" genpkey -algorithm ED25519 -out "$WORK_ROOT/private.pem" >/dev/null 2>&1
"$OPENSSL_BIN" pkey -in "$WORK_ROOT/private.pem" -pubout -out "$WORK_ROOT/public.pem" >/dev/null 2>&1
"$OPENSSL_BIN" pkeyutl -sign \
  -inkey "$WORK_ROOT/private.pem" \
  -rawin \
  -in "$WORK_ROOT/payload" \
  -out "$WORK_ROOT/signature" >/dev/null 2>&1
"$OPENSSL_BIN" pkeyutl -verify \
  -pubin \
  -inkey "$WORK_ROOT/public.pem" \
  -rawin \
  -in "$WORK_ROOT/payload" \
  -sigfile "$WORK_ROOT/signature" >/dev/null 2>&1

printf '%s\n' "$OPENSSL_BIN"
