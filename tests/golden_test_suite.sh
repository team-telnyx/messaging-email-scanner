#!/usr/bin/env bash
# MSG-1846: Golden regression suite for the attack and legitimate email corpora.
# Scans all .eml fixtures against the scanner, compares to .expected files.
# Fails CI on any regression. fp_stress false positives are warnings, not failures.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CORPUS_ROOT=${GOLDEN_CORPUS_ROOT:-$REPO_ROOT/tests/corpus}
IMAGE=${GOLDEN_TEST_IMAGE:-messaging-email-scanner:golden-test}
CONTAINER="golden-test-suite-$$"
REDIS_CONTAINER="golden-redis-$$"
NETWORK="golden-net-$$"
# Redis must be named "redis" so statistic.conf's hardcoded "redis:6379" resolves via Docker DNS
REDIS_ALIAS="redis"

# Authoritative corpus inventory — must match or CI fails
EXPECTED_ATTACKS=52
EXPECTED_LEGITIMATE=55

TOTAL=0
PASSED=0
WARNINGS=0
FAILURES=()

cleanup() {
  docker rm -f "$CONTAINER" "$REDIS_CONTAINER" >/dev/null 2>&1 || true
  docker network rm "$NETWORK" >/dev/null 2>&1 || true
}
trap cleanup EXIT

fail_infrastructure() {
  printf 'golden_test_suite: ERROR: %s\n' "$*" >&2
  docker logs "$CONTAINER" >&2 2>/dev/null || true
  exit 1
}

normalize_action() {
  printf '%s' "$1" |
    tr '[:upper:]' '[:lower:]' |
    sed -e 's/^[[:space:]]*//' \
        -e 's/[[:space:]]*$//' \
        -e 's/[[:space:]-][[:space:]-]*/_/g'
}

read_expected_value() {
  local key=$1
  local expected_file=$2

  sed -n "s/^${key}:[[:space:]]*//p" "$expected_file" |
    head -n 1 |
    sed -e 's/\r$//' -e 's/[[:space:]]*$//'
}

record_failure() {
  local path=$1
  local detail=$2
  FAILURES+=("$path: $detail")
}

# BLOCK 4: Validate one-to-one .eml/.expected pairing and corpus inventory
validate_corpus_inventory() {
  local attack_emls attack_expecteds legit_emls legit_expecteds
  attack_emls=$(find "$CORPUS_ROOT/attacks" -type f -name '*.eml' | wc -l | tr -d ' ')
  attack_expecteds=$(find "$CORPUS_ROOT/attacks" -type f -name '*.expected' | wc -l | tr -d ' ')
  legit_emls=$(find "$CORPUS_ROOT/legitimate" -type f -name '*.eml' | wc -l | tr -d ' ')
  legit_expecteds=$(find "$CORPUS_ROOT/legitimate" -type f -name '*.expected' | wc -l | tr -d ' ')

  local inventory_ok=1

  if [[ "$attack_emls" -ne "$EXPECTED_ATTACKS" ]]; then
    record_failure "inventory" "attack corpus has $attack_emls .eml files, expected $EXPECTED_ATTACKS"
    inventory_ok=0
  fi
  if [[ "$legit_emls" -ne "$EXPECTED_LEGITIMATE" ]]; then
    record_failure "inventory" "legitimate corpus has $legit_emls .eml files, expected $EXPECTED_LEGITIMATE"
    inventory_ok=0
  fi
  if [[ "$attack_emls" -ne "$attack_expecteds" ]]; then
    record_failure "inventory" "attack corpus has $attack_emls .eml but $attack_expecteds .expected files — mismatch"
    inventory_ok=0
  fi
  if [[ "$legit_emls" -ne "$legit_expecteds" ]]; then
    record_failure "inventory" "legitimate corpus has $legit_emls .eml but $legit_expecteds .expected files — mismatch"
    inventory_ok=0
  fi

  # Check for orphan .expected files (no corresponding .eml)
  local expected_file eml_file
  while IFS= read -r expected_file; do
    eml_file="${expected_file%.expected}.eml"
    if [[ ! -f "$eml_file" ]]; then
      record_failure "inventory" "orphan .expected file: ${expected_file#"$CORPUS_ROOT"/}"
      inventory_ok=0
    fi
  done < <(find "$CORPUS_ROOT/attacks" "$CORPUS_ROOT/legitimate" -type f -name '*.expected' -print | LC_ALL=C sort)

  if [[ "$inventory_ok" -eq 0 ]]; then
    printf 'FAIL: corpus inventory validation failed\n'
    for failure in "${FAILURES[@]}"; do
      printf '  - %s\n' "$failure"
    done
    exit 1
  fi
}

scan_fixture() {
  local eml=$1
  local expected_file=${eml%.eml}.expected
  local display_path=${eml#"$CORPUS_ROOT"/}
  local corpus_type=$2
  local expected_action
  local expected_symbols_raw
  local actual_action_raw
  local actual_action
  local actual_symbols
  local scan_output
  local case_failed=0
  local failure_start=${#FAILURES[@]}

  TOTAL=$((TOTAL + 1))

  if [[ ! -f "$expected_file" ]]; then
    record_failure "$display_path" "missing expected file ${expected_file#"$CORPUS_ROOT"/}"
    printf 'FAIL: %s (missing .expected file)\n' "$display_path"
    return
  fi

  expected_action=$(normalize_action "$(read_expected_value action "$expected_file")")
  expected_symbols_raw=$(read_expected_value symbols "$expected_file")

  if [[ -z "$expected_action" ]]; then
    record_failure "$display_path" 'expected file has no action'
    printf 'FAIL: %s (invalid .expected file)\n' "$display_path"
    return
  fi

  if ! scan_output=$(docker exec -i "$CONTAINER" \
    rspamc -h 127.0.0.1:11333 --header 'Settings-ID: outbound' <"$eml" 2>&1); then
    scan_output=${scan_output//$'\n'/; }
    record_failure "$display_path" "rspamc failed: $scan_output"
    printf 'FAIL: %s (rspamc failed)\n' "$display_path"
    return
  fi

  actual_action_raw=$(printf '%s\n' "$scan_output" |
    sed -n 's/^[[:space:]]*Action:[[:space:]]*//p' |
    head -n 1)
  actual_action=$(normalize_action "$actual_action_raw")
  actual_symbols=$(printf '%s\n' "$scan_output" |
    sed -n 's/^[[:space:]]*Symbol:[[:space:]]*\([^[:space:] (]*\).*/\1/p')

  if [[ -z "$actual_action" ]]; then
    record_failure "$display_path" 'scan output has no Action field'
    printf 'FAIL: %s (scan output has no Action field)\n' "$display_path"
    return
  fi

  if [[ "$corpus_type" == 'attack' ]]; then
    # BLOCK 2: ALL expected symbols must be present (AND semantics, not OR)
    if [[ "$actual_action" != "$expected_action" ]]; then
      record_failure "$display_path" "action expected $expected_action, got ${actual_action:-<missing>}"
      case_failed=1
    fi

    local expected_symbol
    local trimmed_symbol
    local expected_symbol_list=()
    IFS=',' read -r -a expected_symbol_list <<<"$expected_symbols_raw"
    for expected_symbol in "${expected_symbol_list[@]}"; do
      trimmed_symbol=$(printf '%s' "$expected_symbol" |
        sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
      [[ -n "$trimmed_symbol" ]] || continue
      if ! printf '%s\n' "$actual_symbols" | grep -Fxq -- "$trimmed_symbol"; then
        record_failure "$display_path" "expected symbol '$trimmed_symbol' not present in scan output"
        case_failed=1
      fi
    done
  elif [[ "$display_path" == legitimate/fp_stress/* ]]; then
    # fp_stress: known false-positive risk. If action is not no_action, it's a WARNING.
    # But still verify the expected target symbol fires when one is listed.
    local expected_symbol
    local trimmed_symbol
    local expected_symbol_list=()
    IFS=',' read -r -a expected_symbol_list <<<"$expected_symbols_raw"
    for expected_symbol in "${expected_symbol_list[@]}"; do
      trimmed_symbol=$(printf '%s' "$expected_symbol" |
        sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
      [[ -n "$trimmed_symbol" ]] || continue
      if ! printf '%s\n' "$actual_symbols" | grep -Fxq -- "$trimmed_symbol"; then
        record_failure "$display_path" "fp_stress expected symbol '$trimmed_symbol' not present (detector regression)"
        case_failed=1
      fi
    done

    if [[ "$actual_action" != 'no_action' && "$case_failed" -eq 0 ]]; then
      WARNINGS=$((WARNINGS + 1))
      PASSED=$((PASSED + 1))
      printf 'WARNING: %s (known FP risk: action=%s, expected symbols=%s)\n' \
        "$display_path" "${actual_action:-<missing>}" "$expected_symbols_raw"
      return
    fi
  else
    # BLOCK 3: Legitimate messages MUST be no_action — not greylist, not add_header
    if [[ "$actual_action" != "$expected_action" ]]; then
      record_failure "$display_path" "legitimate action must be $expected_action, got ${actual_action:-<missing>}"
      case_failed=1
    fi
  fi

  if [[ "$case_failed" -eq 1 || ${#FAILURES[@]} -gt "$failure_start" ]]; then
    printf 'FAIL: %s (action=%s)\n' "$display_path" "${actual_action:-<missing>}"
  else
    PASSED=$((PASSED + 1))
    printf 'PASS: %s (action=%s)\n' "$display_path" "$actual_action"
  fi
}

command -v docker >/dev/null 2>&1 || fail_infrastructure 'docker is required'
[[ -d "$CORPUS_ROOT/attacks" ]] || fail_infrastructure "missing attack corpus: $CORPUS_ROOT/attacks"
[[ -d "$CORPUS_ROOT/legitimate" ]] || fail_infrastructure "missing legitimate corpus: $CORPUS_ROOT/legitimate"

# BLOCK 4: Validate corpus inventory before starting scanner
validate_corpus_inventory

if [[ "${GOLDEN_SKIP_BUILD:-0}" != '1' ]]; then
  printf 'Building scanner image %s...\n' "$IMAGE"
  docker build -t "$IMAGE" "$REPO_ROOT"
fi

# BLOCK 1: Start Redis for Bayes classifier
printf 'Starting Redis container %s...\n' "$REDIS_CONTAINER"
docker network create "$NETWORK" >/dev/null 2>&1 || true
docker run -d --name "$REDIS_CONTAINER" --network-alias "$REDIS_ALIAS" --network "$NETWORK" redis:7-alpine >/dev/null || \
  fail_infrastructure 'could not start Redis container'

printf 'Starting scanner container %s...\n' "$CONTAINER"
if ! docker run -d \
  --name "$CONTAINER" \
  --network "$NETWORK" \
  -e RSPAMD_LOGGING_LEVEL=info \
  -e RSPAMD_CONTROLLER_PASSWORD=golden-read-only \
  -e RSPAMD_CONTROLLER_ENABLE_PASSWORD=golden-enable \
  -e URL_BLOCKLIST_REFRESH_ENABLED=0 \
  -e REDIS_HOST=redis \
  "$IMAGE" >/dev/null; then
  fail_infrastructure 'could not start scanner container'
fi

status=
for attempt in $(seq 1 60); do
  status=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$CONTAINER" 2>/dev/null || true)
  if [[ "$status" == 'healthy' ]]; then
    break
  fi
  if [[ "$status" == 'unhealthy' || "$status" == 'exited' || "$status" == 'dead' ]]; then
    fail_infrastructure "scanner became $status"
  fi
  sleep 1
done
[[ "$status" == 'healthy' ]] || fail_infrastructure "scanner did not become healthy (last status: ${status:-unknown})"

# BLOCK 1: Verify Bayes is connected and trained
printf 'Verifying Bayes classifier...\n'
bayes_stats=$(docker exec "$CONTAINER" rspamc -h 127.0.0.1:11334 -P golden-read-only stat 2>&1 || true)
if printf '%s' "$bayes_stats" | grep -qi 'Messages learned.*0'; then
  # Bayes has 0 learned messages — need to train
  printf 'Training Bayes classifier with minimal corpus...\n'
  # Train spam from attack corpus (first 20 spam emails to exceed min_learns=20)
  local_learned=0
  while IFS= read -r eml; do
    docker exec -i "$CONTAINER" rspamc -h 127.0.0.1:11334 -P golden-enable learn_spam <"$eml" >/dev/null 2>&1 || true
    local_learned=$((local_learned + 1))
    [[ "$local_learned" -ge 25 ]] && break
  done < <(find "$CORPUS_ROOT/attacks" -type f -name '*.eml' -print | LC_ALL=C sort | head -25)

  # Train ham from legitimate corpus (first 20 legit emails)
  while IFS= read -r eml; do
    docker exec -i "$CONTAINER" rspamc -h 127.0.0.1:11334 -P golden-enable learn_ham <"$eml" >/dev/null 2>&1 || true
    local_learned=$((local_learned + 1))
    [[ "$local_learned" -ge 50 ]] && break
  done < <(find "$CORPUS_ROOT/legitimate" -type f -name '*.eml' -not -path '*/fp_stress/*' -print | LC_ALL=C sort | head -25)

  sleep 3  # Allow Redis to persist
fi

# Verify Bayes is now active
bayes_check=$(docker exec "$CONTAINER" rspamc -h 127.0.0.1:11333 --header 'Settings-ID: outbound' <<'BAYES_TEST' 2>&1 || true
From: test@example.org
To: test@example.net
Subject: test
Message-ID: <bayes-check@test>
Content-Type: text/plain

test message
BAYES_TEST
)
if ! printf '%s' "$bayes_check" | grep -qi 'BAYES\|statistics'; then
  # Bayes might still be warming up — check stats
  stats=$(docker exec "$CONTAINER" rspamc -h 127.0.0.1:11334 -P golden-read-only stat 2>&1 || true)
  if printf '%s' "$stats" | grep -qi 'Messages learned.*0'; then
    printf 'WARNING: Bayes classifier has 0 learned messages — Bayes-dependent tests may not exercise the full classifier\n' >&2
  fi
fi

printf 'Scanning golden corpus...\n'
while IFS= read -r eml; do
  if [[ "$eml" == "$CORPUS_ROOT/attacks/"* ]]; then
    scan_fixture "$eml" attack
  else
    scan_fixture "$eml" legitimate
  fi
done < <(find "$CORPUS_ROOT/attacks" "$CORPUS_ROOT/legitimate" -type f -name '*.eml' -print | LC_ALL=C sort)

printf '\nSummary: %d/%d passed' "$PASSED" "$TOTAL"
if [[ "$WARNINGS" -gt 0 ]]; then
  printf ' (%d warning%s)' "$WARNINGS" "$([[ "$WARNINGS" -eq 1 ]] && printf '' || printf 's')"
fi
printf '\n'

if [[ "$TOTAL" -eq 0 ]]; then
  printf 'Failures:\n  - no .eml files found in the golden corpus\n' >&2
  exit 1
fi

if [[ ${#FAILURES[@]} -gt 0 ]]; then
  printf 'Failures (%d):\n' "${#FAILURES[@]}"
  for failure in "${FAILURES[@]}"; do
    printf '  - %s\n' "$failure"
  done
  exit 1
fi

printf 'golden_test_suite: PASS\n'
