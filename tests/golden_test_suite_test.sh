#!/usr/bin/env bash
# MSG-1846: Contract tests for the golden test suite runner.
# Drives the real golden_test_suite.sh through a fake Docker adapter so that
# production-code mutations are detected by the contract test.
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
    printf '  ✗ %s\n' "$label"
  fi
}

setup_fake_corpus() {
  TMP_DIR=$(mktemp -d)
  mkdir -p "$TMP_DIR/corpus/attacks/phishing" "$TMP_DIR/corpus/legitimate/business" "$TMP_DIR/corpus/legitimate/fp_stress"

  # 52 attack fixtures
  for i in $(seq -w 01 52); do
    printf 'From: attacker@evil.example\nTo: victim@example.org\nSubject: Attack %s\nMessage-ID: <attack-%s@test>\nContent-Type: text/plain\n\nAttack email %s\n' "$i" "$i" "$i" >"$TMP_DIR/corpus/attacks/phishing/${i}_attack.eml"
    printf 'action: add_header\nsymbols: BEC_PATTERN, LOOKALIKE_DOMAIN\ndescription: Attack %s\n' "$i" >"$TMP_DIR/corpus/attacks/phishing/${i}_attack.expected"
  done

  # 50 legitimate fixtures
  for i in $(seq -w 01 50); do
    printf 'From: sender@example.org\nTo: recipient@example.org\nSubject: Legit %s\nMessage-ID: <legit-%s@test>\nContent-Type: text/plain\n\nLegitimate %s\n' "$i" "$i" "$i" >"$TMP_DIR/corpus/legitimate/business/${i}_legit.eml"
    printf 'action: no_action\nsymbols: \ndescription: Legit %s\n' "$i" >"$TMP_DIR/corpus/legitimate/business/${i}_legit.expected"
  done

  # 5 fp_stress fixtures
  for i in $(seq -w 01 05); do
    printf 'From: cfo@company.com\nTo: finance@company.com\nSubject: Stress %s\nMessage-ID: <stress-%s@test>\nContent-Type: text/plain\n\nStress %s\n' "$i" "$i" "$i" >"$TMP_DIR/corpus/legitimate/fp_stress/${i}_stress.eml"
    printf 'action: no_action\nsymbols: BEC_PATTERN\ndescription: Known FP risk %s\n' "$i" >"$TMP_DIR/corpus/legitimate/fp_stress/${i}_stress.expected"
  done
}

# Create a fake docker that simulates scanner responses
create_fake_docker() {
  local fake_dir="$TMP_DIR/fake_bin"
  mkdir -p "$fake_dir"

  cat >"$fake_dir/docker" <<'DOCKER_EOF'
#!/usr/bin/env bash
set -euo pipefail
cmd="${1:-}"
shift || true

case "$cmd" in
  build) exit 0 ;;
  network) exit 0 ;;
  rm) exit 0 ;;
  logs) exit 0 ;;
  run)
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --name) shift 2 ;;
        --network-alias) shift 2 ;;
        --network) shift 2 ;;
        -e) shift 2 ;;
        *) shift ;;
      esac
    done
    echo "fake_container"
    ;;
  inspect)
    # Skip --format and container name
    echo "healthy"
    ;;
  exec)
    # Skip -i flag
    while [[ "${1:-}" == "-i" || "${1:-}" == "-P" ]]; do
      [[ "${1:-}" == "-P" ]] && { shift; shift; continue; }
      shift
    done
    container="${1:-}"; shift || true
    rspamc="${1:-}"; shift || true
    
    if [[ "$rspamc" != "rspamc" ]]; then exit 0; fi
    
    # Parse rspamc flags: -h HOST:PORT -P PASSWORD, then subcommand
    while [[ "${1:-}" == -* ]]; do
      case "$1" in
        -h) shift 2 ;;
        -P) shift 2 ;;
        --header) shift 2 ;;
        *) shift ;;
      esac
    done
    subcmd="${1:-}"; shift || true
    
    if [[ "$subcmd" == "stat" ]]; then
      echo "Messages learned: 50"
      echo "Total learns: 50"
      exit 0
    fi
    if [[ "$subcmd" == "learn_spam" || "$subcmd" == "learn_ham" ]]; then
      cat >/dev/null
      exit 0
    fi
    
    # Default: scan command (subcmd is empty — just flags + stdin)
    input=$(cat)
    if echo "$input" | grep -q "Attack"; then
      mode="${FAKE_SCAN_MODE:-all_pass}"
      if [[ "$mode" == "missing_symbol" ]]; then
        printf 'Results for file: stdin\nAction: add header\nScore: 10.50 / 15.00\nSymbol: BEC_PATTERN (7.00)\nSymbol: OCR_SKIPPED (0.00)\n'
      elif [[ "$mode" == "fp_stress_no_symbol" ]]; then
        printf 'Results for file: stdin\nAction: add header\nScore: 10.50 / 15.00\nSymbol: BEC_PATTERN (7.00)\nSymbol: OCR_SKIPPED (0.00)\n'
      else
        printf 'Results for file: stdin\nAction: add header\nScore: 10.50 / 15.00\nSymbol: BEC_PATTERN (7.00)\nSymbol: LOOKALIKE_DOMAIN (6.00)\nSymbol: OCR_SKIPPED (0.00)\n'
      fi
    elif echo "$input" | grep -q "Stress"; then
      mode="${FAKE_SCAN_MODE:-all_pass}"
      if [[ "$mode" == "fp_stress_no_symbol" ]]; then
        printf 'Results for file: stdin\nAction: add header\nScore: 10.50 / 15.00\nSymbol: SOME_OTHER (5.00)\nSymbol: OCR_SKIPPED (0.00)\n'
      else
        printf 'Results for file: stdin\nAction: add header\nScore: 10.50 / 15.00\nSymbol: BEC_PATTERN (7.00)\nSymbol: OCR_SKIPPED (0.00)\n'
      fi
    else
      mode="${FAKE_SCAN_MODE:-all_pass}"
      if [[ "$mode" == "legit_greylist" ]]; then
        printf 'Results for file: stdin\nAction: greylist\nScore: 4.50 / 15.00\nSymbol: OCR_SKIPPED (0.00)\n'
      else
        printf 'Results for file: stdin\nAction: no action\nScore: 3.50 / 15.00\nSymbol: OCR_SKIPPED (0.00)\n'
      fi
    fi
    exit 0
    ;;
esac
exit 0
DOCKER_EOF
  chmod +x "$fake_dir/docker"
  echo "$fake_dir"
}

printf 'golden_test_suite_test: running contract tests\n\n'

# Test 1: Script syntax
printf 'Test 1: Script syntax\n'
assert "golden_test_suite.sh passes bash -n" \
  "bash -n '$REPO_ROOT/tests/golden_test_suite.sh'"

# Test 2: AND semantics — missing LOOKALIKE_DOMAIN should fail
printf '\nTest 2: AND semantics (missing symbol detection)\n'
setup_fake_corpus
fake_bin=$(create_fake_docker)
export FAKE_SCAN_MODE=missing_symbol
export PATH="$fake_bin:$PATH"
export GOLDEN_CORPUS_ROOT="$TMP_DIR/corpus"
export GOLDEN_SKIP_BUILD=1

exit_code=0
bash "$REPO_ROOT/tests/golden_test_suite.sh" >"$TMP_DIR/output.txt" 2>&1 || exit_code=$?
assert "runner exits non-zero when expected symbol is missing" \
  "[ $exit_code -ne 0 ]"

# Test 3: Legitimate greylist should fail (strict no_action)
printf '\nTest 3: Legitimate greylist is not accepted\n'
export FAKE_SCAN_MODE=legit_greylist
exit_code=0
bash "$REPO_ROOT/tests/golden_test_suite.sh" >"$TMP_DIR/output.txt" 2>&1 || exit_code=$?
assert "runner exits non-zero when legitimate gets greylist" \
  "[ $exit_code -ne 0 ]"

# Test 4: Orphan .expected detection
printf '\nTest 4: Orphan .expected detection\n'
setup_fake_corpus
fake_bin=$(create_fake_docker)
export FAKE_SCAN_MODE=all_pass
export PATH="$fake_bin:$PATH"
export GOLDEN_CORPUS_ROOT="$TMP_DIR/corpus"
export GOLDEN_SKIP_BUILD=1

# Add orphan .expected
printf 'action: add_header\nsymbols: TEST\ndescription: Orphan\n' >"$TMP_DIR/corpus/attacks/phishing/99_orphan.expected"

exit_code=0
bash "$REPO_ROOT/tests/golden_test_suite.sh" >"$TMP_DIR/output.txt" 2>&1 || exit_code=$?
assert "runner exits non-zero with orphan .expected" \
  "[ $exit_code -ne 0 ]"
assert "output mentions orphan" \
  "grep -qi 'orphan' '$TMP_DIR/output.txt'"

# Test 5: Reduced corpus inventory
printf '\nTest 5: Reduced corpus inventory detection\n'
setup_fake_corpus
rm "$TMP_DIR/corpus/attacks/phishing/01_attack.eml"
exit_code=0
bash "$REPO_ROOT/tests/golden_test_suite.sh" >"$TMP_DIR/output.txt" 2>&1 || exit_code=$?
assert "runner exits non-zero with reduced corpus" \
  "[ $exit_code -ne 0 ]"

# Test 6: All pass (positive control)
printf '\nTest 6: All pass (positive control)\n'
setup_fake_corpus
fake_bin=$(create_fake_docker)
export FAKE_SCAN_MODE=all_pass
export PATH="$fake_bin:$PATH"
export GOLDEN_CORPUS_ROOT="$TMP_DIR/corpus"
export GOLDEN_SKIP_BUILD=1

exit_code=0
bash "$REPO_ROOT/tests/golden_test_suite.sh" >"$TMP_DIR/output.txt" 2>&1 || exit_code=$?
assert "runner exits zero when all pass" \
  "[ $exit_code -eq 0 ]"
assert "output shows PASS" \
  "grep -q 'PASS' '$TMP_DIR/output.txt'"

# Test 7: fp_stress missing target symbol
printf '\nTest 7: fp_stress target symbol detection\n'
setup_fake_corpus
fake_bin=$(create_fake_docker)
export FAKE_SCAN_MODE=fp_stress_no_symbol
export PATH="$fake_bin:$PATH"
export GOLDEN_CORPUS_ROOT="$TMP_DIR/corpus"
export GOLDEN_SKIP_BUILD=1

exit_code=0
bash "$REPO_ROOT/tests/golden_test_suite.sh" >"$TMP_DIR/output.txt" 2>&1 || exit_code=$?
assert "runner exits non-zero when fp_stress target symbol missing" \
  "[ $exit_code -ne 0 ]"

# Summary
printf '\n--- Contract test results ---\n'
printf 'Passed: %d, Failed: %d\n' "$PASS_COUNT" "$FAIL_COUNT"
if [[ "$FAIL_COUNT" -gt 0 ]]; then
  printf 'golden_test_suite_test: FAIL\n'
  exit 1
fi
printf 'golden_test_suite_test: PASS\n'
