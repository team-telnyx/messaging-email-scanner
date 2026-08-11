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
  local body=$3

  cat >"$path" <<EOF
From: sender@example.org
To: recipient@example.net
Date: Tue, 11 Aug 2026 12:00:00 +0000
Message-ID: <${subject// /-}@example.org>
Subject: $subject
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit

$body
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

# Test 1: a digit-substituted pharmaceutical term is detected.
write_message "$TMP_DIR/v1agra.eml" "obfuscated viagra" \
  "Exclusive offer on v1agra available today."
scan_message "$TMP_DIR/v1agra.eml" >"$TMP_DIR/v1agra.out"
assert_symbol_present OBFUSCATED_SPAM "$TMP_DIR/v1agra.out"

# Test 2: the unobfuscated term is not flagged by this custom rule.
write_message "$TMP_DIR/cialis.eml" "plain cialis" \
  "This message contains the plain word cialis."
scan_message "$TMP_DIR/cialis.eml" >"$TMP_DIR/cialis.out"
assert_symbol_absent OBFUSCATED_SPAM "$TMP_DIR/cialis.out"

# Test 3: multiple substitutions in a gambling term are detected.
write_message "$TMP_DIR/casino.eml" "obfuscated casino" \
  "Claim a c@sin0 bonus now."
scan_message "$TMP_DIR/casino.eml" >"$TMP_DIR/casino.out"
assert_symbol_present OBFUSCATED_SPAM "$TMP_DIR/casino.out"

# Test 4: ordinary benign text remains unflagged.
write_message "$TMP_DIR/apple.eml" "benign apple" \
  "An apple a day makes a simple test message."
scan_message "$TMP_DIR/apple.eml" >"$TMP_DIR/apple.out"
assert_symbol_absent OBFUSCATED_SPAM "$TMP_DIR/apple.out"

printf 'obfuscated_text_test: PASS\n'
