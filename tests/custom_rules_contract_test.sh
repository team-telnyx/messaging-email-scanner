#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
MAP="$REPO_ROOT/config/local.d/maps.d/idn_homograph.map"
MULTIMAP="$REPO_ROOT/config/override.d/multimap.conf"
IDN_CONFIG="$REPO_ROOT/config/local.d/idn_homograph.conf"
TEXT_CONFIG="$REPO_ROOT/config/local.d/obfuscated_text.conf"
DISABLED_CONFIG="$REPO_ROOT/config/local.d/custom_rules_disabled.conf"

fail() {
  printf 'custom_rules_contract_test: FAIL: %s\n' "$*" >&2
  exit 1
}

assert_fixed() {
  local needle=$1
  local file=$2
  grep -Fq -- "$needle" "$file" || fail "missing '$needle' in $file"
}

assert_no_fixed() {
  local needle=$1
  local file=$2
  if grep -Fq -- "$needle" "$file"; then
    fail "unexpected '$needle' in $file"
  fi
}

assert_fixed 'score = 0.0;' "$IDN_CONFIG"
assert_fixed 'score = 0.0;' "$TEXT_CONFIG"
[[ $(grep -Fc 'score = 0.0;' "$MULTIMAP") -ge 2 ]] || \
  fail "OBFUSCATED_SPAM and IDN_HOMOGRAPH must both have zero multimap scores"
assert_fixed 'Scores set to 0.0 until shadow evaluation complete.' "$DISABLED_CONFIG"
assert_fixed 'Enable by setting scores > 0 after MSG-1791 launch gate evaluation.' "$DISABLED_CONFIG"

# Blanket punycode detection is forbidden: an xn-- prefix does not imply abuse.
assert_no_fixed '/xn--[a-z0-9]+/' "$MAP"

for brand in apple google microsoft paypal amazon facebook instagram; do
  assert_fixed "# ${brand}" "$MAP"
done
assert_fixed 'аррӏе' "$MAP"

printf 'custom_rules_contract_test: PASS\n'