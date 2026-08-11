#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
RSPAMD_HOST=${RSPAMD_HOST:-127.0.0.1}
RSPAMD_PORT=${RSPAMD_PORT:-11333}
RSPAMC_BIN=${RSPAMC_BIN:-rspamc}
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

scan_message() {
  local fixture=$1

  if command -v "$RSPAMC_BIN" >/dev/null 2>&1; then
    "$RSPAMC_BIN" -h "$RSPAMD_HOST:$RSPAMD_PORT" <"$fixture"
  elif command -v docker >/dev/null 2>&1 &&
    docker compose -f "$REPO_ROOT/docker-compose.yml" ps --status running rspamd --quiet | grep -q .; then
    docker compose -f "$REPO_ROOT/docker-compose.yml" exec -T rspamd \
      rspamc -h 127.0.0.1:11333 <"$fixture"
  else
    printf 'rspamc is not installed and the Compose rspamd service is not running\n' >&2
    return 127
  fi
}

write_message() {
  local path=$1
  local subject=$2
  local url=$3

  cat >"$path" <<EOF
From: sender@example.org
To: recipient@example.net
Date: Tue, 11 Aug 2026 12:00:00 +0000
Message-ID: <${subject// /-}@example.org>
Subject: $subject
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit

Please review $url for more information.
EOF
}

assert_symbol_present() {
  local name=$1
  local output=$2

  if ! grep -Eq "(^|[^A-Z0-9_])${name}([^A-Z0-9_]|$)" "$output"; then
    printf 'expected %s in scan output:\n' "$name" >&2
    sed 's/^/  /' "$output" >&2
    exit 1
  fi
}

assert_symbol_absent() {
  local name=$1
  local output=$2

  if grep -Eq "(^|[^A-Z0-9_])${name}([^A-Z0-9_]|$)" "$output"; then
    printf 'did not expect %s in scan output:\n' "$name" >&2
    sed 's/^/  /' "$output" >&2
    exit 1
  fi
}

# Test 1: Cyrillic small a (U+0430) mixed with Latin letters is detected.
write_message "$TMP_DIR/cyrillic-apple.eml" "cyrillic apple homograph" \
  "https://аpple.com/account"
scan_message "$TMP_DIR/cyrillic-apple.eml" >"$TMP_DIR/cyrillic-apple.out"
assert_symbol_present IDN_HOMOGRAPH "$TMP_DIR/cyrillic-apple.out"

# Test 2: the all-ASCII legitimate domain is not flagged.
write_message "$TMP_DIR/ascii-apple.eml" "ascii apple domain" \
  "https://apple.com/account"
scan_message "$TMP_DIR/ascii-apple.eml" >"$TMP_DIR/ascii-apple.out"
assert_symbol_absent IDN_HOMOGRAPH "$TMP_DIR/ascii-apple.out"

# Test 3: Cyrillic small o (U+043E) in an otherwise Latin domain is detected.
write_message "$TMP_DIR/mixed-microsoft.eml" "mixed script microsoft homograph" \
  "https://micrоsoft.com/login"
scan_message "$TMP_DIR/mixed-microsoft.eml" >"$TMP_DIR/mixed-microsoft.out"
assert_symbol_present IDN_HOMOGRAPH "$TMP_DIR/mixed-microsoft.out"

# Test 4: a whole-script Cyrillic Apple lookalike is detected via its
# punycode form. Rspamd normalizes URL hostnames to punycode (xn--) before
# matching, so the raw Cyrillic URL is converted and matched by the
# xn--80ak6aa92e pattern.
write_message "$TMP_DIR/whole-script-apple.eml" "whole script apple homograph" \
  "https://аррӏе.com/account"
scan_message "$TMP_DIR/whole-script-apple.eml" >"$TMP_DIR/whole-script-apple.out"
assert_symbol_present IDN_HOMOGRAPH "$TMP_DIR/whole-script-apple.out"

# Tests 5-7: benign internationalized and ASCII domains must not be treated as
# homographs merely because IDNA serializes them as xn-- labels.
write_message "$TMP_DIR/buecher.eml" "benign buecher IDN" \
  "https://bücher.de/catalog"
scan_message "$TMP_DIR/buecher.eml" >"$TMP_DIR/buecher.out"
assert_symbol_absent IDN_HOMOGRAPH "$TMP_DIR/buecher.out"

write_message "$TMP_DIR/muenchen.eml" "benign muenchen IDN" \
  "https://münchen.de/"
scan_message "$TMP_DIR/muenchen.eml" >"$TMP_DIR/muenchen.out"
assert_symbol_absent IDN_HOMOGRAPH "$TMP_DIR/muenchen.out"

write_message "$TMP_DIR/navigator.eml" "benign navigator domain" \
  "https://navigator.de/"
scan_message "$TMP_DIR/navigator.eml" >"$TMP_DIR/navigator.out"
assert_symbol_absent IDN_HOMOGRAPH "$TMP_DIR/navigator.out"

printf 'idn_homograph_test: PASS\n'
