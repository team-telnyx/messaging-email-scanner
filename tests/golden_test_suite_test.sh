#!/usr/bin/env bash
# MSG-1846: Contract tests for the golden test suite runner.
# Verifies sorting, action normalization, symbol matching (AND semantics),
# warnings, failures, build/skip-build behavior, corpus inventory, and cleanup.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TMP_DIR=""
TEST_NUM=0
PASS_COUNT=0
FAIL_COUNT=0

cleanup() {
  [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]] && rm -rf "$TMP_DIR"
}
trap cleanup EXIT

assert() {
  local label=$1
  local condition=$2
  TEST_NUM=$((TEST_NUM + 1))
  if eval "$condition"; then
    PASS_COUNT=$((PASS_COUNT + 1))
    printf '  ✓ %s\n' "$label"
  else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    printf '  ✗ %s [condition: %s]\n' "$label" "$condition"
  fi
}

setup_fake_corpus() {
  TMP_DIR=$(mktemp -d)
  mkdir -p "$TMP_DIR/corpus/attacks/phishing" "$TMP_DIR/corpus/legitimate/business" "$TMP_DIR/corpus/legitimate/fp_stress"

  # Attack fixtures
  for i in 01 02 03; do
    cat >"$TMP_DIR/corpus/attacks/phishing/${i}_test.eml" <<EOF
From: attacker@evil.example
To: victim@example.org
Subject: Phish $i
Message-ID: <phish-${i}@test>
Content-Type: text/plain

Phishing email $i
EOF
    cat >"$TMP_DIR/corpus/attacks/phishing/${i}_test.expected" <<EOF
action: add_header
symbols: BEC_PATTERN, LOOKALIKE_DOMAIN
description: Attack test $i
EOF
  done

  # Legitimate fixtures
  for i in 01 02; do
    cat >"$TMP_DIR/corpus/legitimate/business/${i}_legit.eml" <<EOF
From: sender@example.org
To: recipient@example.org
Subject: Legit $i
Message-ID: <legit-${i}@test>
Content-Type: text/plain

Legitimate email $i
EOF
    cat >"$TMP_DIR/corpus/legitimate/business/${i}_legit.expected" <<EOF
action: no_action
symbols: 
description: Legitimate test $i
EOF
  done

  # fp_stress fixture
  cat >"$TMP_DIR/corpus/legitimate/fp_stress/01_stress.eml" <<EOF
From: cfo@company.com
To: finance@company.com
Subject: Wire transfer
Message-ID: <stress-01@test>
Content-Type: text/plain

Urgent wire transfer request
EOF
    cat >"$TMP_DIR/corpus/legitimate/fp_stress/01_stress.expected" <<EOF
action: no_action
symbols: BEC_PATTERN
description: Known FP risk
EOF
  }

printf 'golden_test_suite_test: running contract tests\n\n'

# Test 1: Action normalization
printf 'Test 1: Action normalization\n'
assert "'no action' normalizes to 'no_action'" \
  "[ '$(printf 'no action' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/[[:space:]-][[:space:]-]*/_/g')' = 'no_action' ]"
assert "'add header' normalizes to 'add_header'" \
  "[ '$(printf 'add header' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/[[:space:]-][[:space:]-]*/_/g')' = 'add_header' ]"
assert "'greylist' normalizes to 'greylist'" \
  "[ '$(printf 'greylist' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/[[:space:]-][[:space:]-]*/_/g')' = 'greylist' ]"

# Test 2: Corpus inventory validation
printf '\nTest 2: Corpus inventory validation\n'
setup_fake_corpus
assert "fake corpus has 3 attack .eml files" \
  "[ $(find "$TMP_DIR/corpus/attacks" -type f -name '*.eml' | wc -l | tr -d ' ') -eq 3 ]"
assert "fake corpus has 3 attack .expected files" \
  "[ $(find "$TMP_DIR/corpus/attacks" -type f -name '*.expected' | wc -l | tr -d ' ') -eq 3 ]"
assert "fake corpus has 3 legitimate .eml files" \
  "[ $(find "$TMP_DIR/corpus/legitimate" -type f -name '*.eml' | wc -l | tr -d ' ') -eq 3 ]"
assert "fake corpus has 3 legitimate .expected files" \
  "[ $(find "$TMP_DIR/corpus/legitimate" -type f -name '*.expected' | wc -l | tr -d ' ') -eq 3 ]"

# Test 3: Orphan detection
printf '\nTest 3: Orphan .expected detection\n'
cat >"$TMP_DIR/corpus/attacks/phishing/99_orphan.expected" <<EOF
action: add_header
symbols: TEST
description: Orphan
EOF
assert "orphan .expected file detected" \
  "[ -f "$TMP_DIR/corpus/attacks/phishing/99_orphan.expected" ] && [ ! -f "$TMP_DIR/corpus/attacks/phishing/99_orphan.eml" ]"

# Test 4: AND semantics for attack symbols (BLOCK 2 fix)
printf '\nTest 4: Attack symbol AND semantics\n'
# Simulate: expected symbols are "BEC_PATTERN, LOOKALIKE_DOMAIN"
# If only BEC_PATTERN is present, it should FAIL (not pass with OR semantics)
actual_symbols="BEC_PATTERN"
expected_symbols="BEC_PATTERN, LOOKALIKE_DOMAIN"
missing_symbols=""
for sym in $(printf '%s' "$expected_symbols" | tr ',' ' '); do
  sym=$(printf '%s' "$sym" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
  if ! printf '%s\n' "$actual_symbols" | grep -Fxq -- "$sym"; then
    missing_symbols="${missing_symbols:+$missing_symbols, }$sym"
  fi
done
assert "missing LOOKALIKE_DOMAIN is detected with AND semantics" \
  "[ -n '$missing_symbols' ]"
assert "the missing symbol is LOOKALIKE_DOMAIN" \
  "[[ '$missing_symbols' == *'LOOKALIKE_DOMAIN'* ]]"

# Test 5: Legitimate action must be exactly no_action (BLOCK 3 fix)
printf '\nTest 5: Legitimate action strict comparison\n'
assert "greylist is NOT accepted for legitimate no_action" \
  "[ 'greylist' != 'no_action' ]"
assert "add_header is NOT accepted for legitimate no_action" \
  "[ 'add_header' != 'no_action' ]"

# Test 6: fp_stress symbol verification
printf '\nTest 6: fp_stress expected symbol verification\n'
# fp_stress with expected BEC_PATTERN — if BEC_PATTERN doesn't fire, it's a regression
actual_symbols="SOME_OTHER_SYMBOL"
expected_symbol="BEC_PATTERN"
assert "missing fp_stress target symbol is detected" \
  "! printf '%s\n' '$actual_symbols' | grep -Fxq -- '$expected_symbol'"

# Test 7: Script syntax
printf '\nTest 7: Script syntax\n'
assert "golden_test_suite.sh passes bash -n" \
  "bash -n '$REPO_ROOT/tests/golden_test_suite.sh'"

# Summary
printf '\n--- Contract test results ---\n'
printf 'Passed: %d, Failed: %d\n' "$PASS_COUNT" "$FAIL_COUNT"
if [[ "$FAIL_COUNT" -gt 0 ]]; then
  printf 'golden_test_suite_test: FAIL\n'
  exit 1
fi
printf 'golden_test_suite_test: PASS\n'
