#!/usr/bin/env bash
# MSG-1846: Golden regression suite for the attack and legitimate email corpora.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CORPUS_ROOT=${GOLDEN_CORPUS_ROOT:-$REPO_ROOT/tests/corpus}
IMAGE=${GOLDEN_TEST_IMAGE:-messaging-email-scanner:golden-test}
CONTAINER="golden-test-suite-$$"

TOTAL=0
PASSED=0
WARNINGS=0
FAILURES=()

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
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
  local matched_symbol=

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
      if printf '%s\n' "$actual_symbols" | grep -Fxq -- "$trimmed_symbol"; then
        matched_symbol=$trimmed_symbol
        break
      fi
    done

    if [[ -z "$matched_symbol" ]]; then
      record_failure "$display_path" "none of expected attack symbols present: $expected_symbols_raw"
      case_failed=1
    fi
  elif [[ "$display_path" == legitimate/fp_stress/* ]]; then
    if [[ "$actual_action" != 'no_action' ]]; then
      WARNINGS=$((WARNINGS + 1))
      PASSED=$((PASSED + 1))
      printf 'WARNING: %s (known FP risk: action=%s, expected symbols=%s)\n' \
        "$display_path" "${actual_action:-<missing>}" "$expected_symbols_raw"
      return
    fi
  else
    # A legitimate message may be accepted or temporarily greylisted, but an
    # add-header/rewrite/reject result is a false-positive regression.
    if [[ "$actual_action" != 'no_action' && "$actual_action" != 'greylist' ]]; then
      record_failure "$display_path" "legitimate action must be no_action or greylist, got ${actual_action:-<missing>} (expected $expected_action)"
      case_failed=1
    fi
  fi

  if [[ "$case_failed" -eq 1 || ${#FAILURES[@]} -gt "$failure_start" ]]; then
    printf 'FAIL: %s (action=%s)\n' "$display_path" "${actual_action:-<missing>}"
  else
    PASSED=$((PASSED + 1))
    if [[ -n "$matched_symbol" ]]; then
      printf 'PASS: %s (action=%s, matched=%s)\n' "$display_path" "$actual_action" "$matched_symbol"
    else
      printf 'PASS: %s (action=%s)\n' "$display_path" "$actual_action"
    fi
  fi
}

command -v docker >/dev/null 2>&1 || fail_infrastructure 'docker is required'
[[ -d "$CORPUS_ROOT/attacks" ]] || fail_infrastructure "missing attack corpus: $CORPUS_ROOT/attacks"
[[ -d "$CORPUS_ROOT/legitimate" ]] || fail_infrastructure "missing legitimate corpus: $CORPUS_ROOT/legitimate"

if [[ "${GOLDEN_SKIP_BUILD:-0}" != '1' ]]; then
  printf 'Building scanner image %s...\n' "$IMAGE"
  docker build -t "$IMAGE" "$REPO_ROOT"
fi

printf 'Starting scanner container %s...\n' "$CONTAINER"
if ! docker run -d \
  --name "$CONTAINER" \
  -e RSPAMD_LOGGING_LEVEL=info \
  -e RSPAMD_CONTROLLER_PASSWORD=golden-read-only \
  -e RSPAMD_CONTROLLER_ENABLE_PASSWORD=golden-enable \
  -e URL_BLOCKLIST_REFRESH_ENABLED=0 \
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
