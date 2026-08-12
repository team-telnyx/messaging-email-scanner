#!/usr/bin/env bash
# Contract tests for the golden corpus runner. Docker is faked so comparison,
# normalization, ordering, and false-positive semantics can be tested quickly.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SUITE="$REPO_ROOT/tests/golden_test_suite.sh"
TMP_DIR=$(mktemp -d "$REPO_ROOT/.golden-suite-unit.XXXXXX")

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

fail() {
  printf 'golden_test_suite_test: FAIL: %s\n' "$*" >&2
  exit 1
}

assert_contains() {
  local file=$1
  local expected=$2
  grep -Fq -- "$expected" "$file" || {
    sed 's/^/  /' "$file" >&2
    fail "expected output to contain: $expected"
  }
}

mkdir -p "$TMP_DIR/bin"
cat >"$TMP_DIR/bin/docker" <<'FAKE_DOCKER'
#!/usr/bin/env bash
set -euo pipefail
printf '%s' "$1" >>"$FAKE_DOCKER_LOG"
for arg in "${@:2}"; do
  printf ' <%s>' "$arg" >>"$FAKE_DOCKER_LOG"
done
printf '\n' >>"$FAKE_DOCKER_LOG"

case "$1" in
  build)
    ;;
  run)
    printf 'fake-container-id\n'
    ;;
  inspect)
    printf 'healthy\n'
    ;;
  exec)
    message=$(cat)
    case "$message" in
      *GOLDEN_ATTACK_A*)
        printf 'Results for file: stdin\nAction: add header\nSymbol: EXPECTED_B (4.00)\n'
        ;;
      *GOLDEN_ATTACK_Z*)
        printf 'Results for file: stdin\nAction: no action\nSymbol: EXPECTED_Z (1.00)\n'
        ;;
      *GOLDEN_LEGIT*)
        printf 'Results for file: stdin\nAction: greylist\nSymbol: LOW_SCORE (1.00)\n'
        ;;
      *GOLDEN_FP_STRESS*)
        printf 'Results for file: stdin\nAction: reject\nSymbol: BEC_PATTERN (6.00)\n'
        ;;
      *GOLDEN_FAILURE*)
        printf 'Results for file: stdin\nAction: no action\nSymbol: OTHER_SYMBOL (1.00)\n'
        ;;
      *)
        printf 'unknown fixture\n' >&2
        exit 2
        ;;
    esac
    ;;
  logs|rm)
    ;;
  *)
    printf 'unexpected docker command: %s\n' "$1" >&2
    exit 2
    ;;
esac
FAKE_DOCKER
chmod +x "$TMP_DIR/bin/docker"

make_fixture() {
  local corpus=$1
  local relative_path=$2
  local marker=$3
  local action=$4
  local symbols=$5
  mkdir -p "$(dirname "$corpus/$relative_path")"
  printf 'From: sender@example.test\nSubject: %s\n\nFixture\n' "$marker" >"$corpus/$relative_path.eml"
  printf 'action: %s\nsymbols: %s\ndescription: Contract test\n' \
    "$action" "$symbols" >"$corpus/$relative_path.expected"
}

# Passing scenario: action normalization, any expected attack symbol, greylist
# tolerance, deterministic sorting, and warning-only fp_stress behavior.
PASS_CORPUS="$TMP_DIR/pass-corpus"
make_fixture "$PASS_CORPUS" attacks/category/z_case GOLDEN_ATTACK_Z no_action EXPECTED_Z
make_fixture "$PASS_CORPUS" attacks/category/a_case GOLDEN_ATTACK_A add_header 'EXPECTED_A, EXPECTED_B'
make_fixture "$PASS_CORPUS" legitimate/business/clean GOLDEN_LEGIT no_action '# symbols that must NOT fire'
make_fixture "$PASS_CORPUS" legitimate/fp_stress/known_risk GOLDEN_FP_STRESS no_action BEC_PATTERN
: >"$TMP_DIR/docker-pass.log"
PATH="$TMP_DIR/bin:$PATH" \
FAKE_DOCKER_LOG="$TMP_DIR/docker-pass.log" \
GOLDEN_CORPUS_ROOT="$PASS_CORPUS" \
  bash "$SUITE" >"$TMP_DIR/pass.out" 2>&1 || {
    sed 's/^/  /' "$TMP_DIR/pass.out" >&2
    fail 'passing scenario exited non-zero'
  }
assert_contains "$TMP_DIR/pass.out" 'Summary: 4/4 passed'
assert_contains "$TMP_DIR/pass.out" 'WARNING'
assert_contains "$TMP_DIR/pass.out" 'known_risk.eml'
assert_contains "$TMP_DIR/docker-pass.log" 'build <-t> <messaging-email-scanner:golden-test>'
assert_contains "$TMP_DIR/docker-pass.log" 'run <-d>'
assert_contains "$TMP_DIR/docker-pass.log" '<URL_BLOCKLIST_REFRESH_ENABLED=0>'
assert_contains "$TMP_DIR/docker-pass.log" 'exec <-i>'
assert_contains "$TMP_DIR/docker-pass.log" '<rspamc> <-h> <127.0.0.1:11333> <--header> <Settings-ID: outbound>'
assert_contains "$TMP_DIR/docker-pass.log" 'rm <-f>'

scan_count=$(grep -c '^exec ' "$TMP_DIR/docker-pass.log")
[[ "$scan_count" -eq 4 ]] || fail 'expected exactly four scans in passing scenario'
# The fake Docker log cannot see stdin, so verify deterministic traversal from
# the suite output's per-case status lines.
actual_order=$(grep -E '^(PASS|WARNING):' "$TMP_DIR/pass.out" |
  sed 's/^[^:]*: //; s/ .*//' |
  tr '\n' ' ' |
  sed 's/[[:space:]]*$//')
expected_order='attacks/category/a_case.eml attacks/category/z_case.eml legitimate/business/clean.eml legitimate/fp_stress/known_risk.eml'
[[ "$actual_order" == "$expected_order" ]] || {
  printf 'actual order: %s\n' "$actual_order" >&2
  fail 'fixtures were not scanned in deterministic sorted order'
}

# Regression scenario: one attack can report both an action mismatch and a
# missing expected symbol, and must fail the suite.
FAIL_CORPUS="$TMP_DIR/fail-corpus"
mkdir -p "$FAIL_CORPUS/legitimate"
make_fixture "$FAIL_CORPUS" attacks/category/regression GOLDEN_FAILURE add_header EXPECTED_ATTACK_SYMBOL
: >"$TMP_DIR/docker-fail.log"
if PATH="$TMP_DIR/bin:$PATH" \
  FAKE_DOCKER_LOG="$TMP_DIR/docker-fail.log" \
  GOLDEN_CORPUS_ROOT="$FAIL_CORPUS" \
  GOLDEN_SKIP_BUILD=1 \
    bash "$SUITE" >"$TMP_DIR/fail.out" 2>&1; then
  sed 's/^/  /' "$TMP_DIR/fail.out" >&2
  fail 'regression scenario unexpectedly passed'
fi
assert_contains "$TMP_DIR/fail.out" 'Summary: 0/1 passed'
assert_contains "$TMP_DIR/fail.out" 'action expected add_header, got no_action'
assert_contains "$TMP_DIR/fail.out" 'none of expected attack symbols present: EXPECTED_ATTACK_SYMBOL'

printf 'golden_test_suite_test: PASS\n'
