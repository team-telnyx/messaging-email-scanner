#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
AUTOLEARN_CONFIG="$REPO_ROOT/config/local.d/bayes_autolearn.conf"
STATISTIC_CONFIG="$REPO_ROOT/config/override.d/statistic.conf"
CONTROLLER_CONFIG="$REPO_ROOT/config/override.d/worker-controller.inc"
HEALTH_CHECK="$REPO_ROOT/scripts/bayes_health_check.sh"
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

fail() {
  printf 'bayes_guard_test: FAIL: %s\n' "$*" >&2
  exit 1
}

assert_config_value() {
  local pattern=$1
  local file=$2
  grep -Eq "$pattern" "$file" || fail "missing config pattern '$pattern' in $file"
}

# Guarded autolearn must be loaded by the active statistic override. Keeping the
# thresholds in an unreferenced local.d file would provide no poisoning guard.
[[ -f "$AUTOLEARN_CONFIG" ]] || fail "missing $AUTOLEARN_CONFIG"
assert_config_value 'spam_threshold[[:space:]]*=[[:space:]]*15(\.0)?;' "$AUTOLEARN_CONFIG"
assert_config_value 'ham_threshold[[:space:]]*=[[:space:]]*-2(\.0)?;' "$AUTOLEARN_CONFIG"
assert_config_value 'min_tokens[[:space:]]*=[[:space:]]*10;' "$AUTOLEARN_CONFIG"
assert_config_value 'bayes_autolearn\.conf' "$STATISTIC_CONFIG"
if grep -Eq 'spam_threshold[[:space:]]*=[[:space:]]*8(\.0)?;|ham_threshold[[:space:]]*=[[:space:]]*-0\.5;' "$STATISTIC_CONFIG"; then
  fail "legacy permissive autolearn thresholds remain active"
fi

# Learning is a privileged controller operation. Production credentials remain
# injected as hashes; a checked-in fallback password must never be introduced.
assert_config_value 'password[[:space:]]*=[[:space:]]*"\$\{CONTROLLER_PASSWORD_HASH\}";' "$CONTROLLER_CONFIG"
assert_config_value 'enable_password[[:space:]]*=[[:space:]]*"\$\{CONTROLLER_ENABLE_PASSWORD_HASH\}";' "$CONTROLLER_CONFIG"
if grep -Eq 'changeme|password[[:space:]]*=[[:space:]]*"q1"' "$CONTROLLER_CONFIG"; then
  fail "controller contains a checked-in fallback password"
fi
assert_config_value 'secure_ip[[:space:]]*=[[:space:]]*\[[[:space:]]*\];' "$CONTROLLER_CONFIG"
if grep -Eq 'secure_ip[[:space:]]*=[[:space:]]*"|trusted_ips[[:space:]]*=' "$CONTROLLER_CONFIG"; then
  fail "controller grants password-less access via secure_ip/trusted_ips"
fi

[[ -x "$HEALTH_CHECK" ]] || fail "$HEALTH_CHECK is missing or not executable"
bash -n "$HEALTH_CHECK"

# Exercise monitoring without a live Rspamd service. The fake also proves that
# the script authenticates stats requests and normalizes an http:// endpoint.
cat >"$TMP_DIR/rspamc" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail

host=
password=
command=
while (($#)); do
  case "$1" in
    -h)
      host=${2:-}
      shift 2
      ;;
    -P)
      password=${2:-}
      shift 2
      ;;
    stat)
      command=stat
      shift
      ;;
    *)
      printf 'unexpected rspamc argument: %s\n' "$1" >&2
      exit 2
      ;;
  esac
done

[[ "$host" == "rspamd:11334" ]] || { printf 'unexpected host: %s\n' "$host" >&2; exit 2; }
[[ "$password" == "monitor-secret" ]] || { printf 'missing monitor password\n' >&2; exit 2; }
[[ "$command" == "stat" ]] || { printf 'missing stat command\n' >&2; exit 2; }
[[ "${FAKE_MALFORMED:-false}" != true ]] || { printf 'not rspamd statistics\n'; exit 0; }

spam=${FAKE_SPAM_COUNT:-1000}
ham=${FAKE_HAM_COUNT:-100}
printf 'Messages learned: %s\n' "$((spam + ham))"
printf 'Statfile: BAYES_SPAM type: spam; length: 0; learned: %s; users: 0\n' "$spam"
printf 'Statfile: BAYES_HAM type: ham; length: 0; learned: %s; users: 0\n' "$ham"
FAKE
chmod +x "$TMP_DIR/rspamc"

common_env=(
  PATH="$TMP_DIR:$PATH"
  RSPAMC_BIN=rspamc
  RSPAMD_URL=http://rspamd:11334
  RSPAMD_PASSWORD=monitor-secret
  BAYES_STATE_FILE="$TMP_DIR/bayes-health.state"
)

normal_output="$TMP_DIR/normal.log"
env "${common_env[@]}" "$HEALTH_CHECK" >"$normal_output"
grep -q 'Ham: 100, Spam: 1000' "$normal_output" || fail "normal counts were not reported"
grep -q 'Ham/spam ratio: 0.1000' "$normal_output" || fail "normal ratio was not reported"

poison_output="$TMP_DIR/poison.log"
set +e
env "${common_env[@]}" FAKE_HAM_COUNT=600 "$HEALTH_CHECK" >"$poison_output" 2>&1
poison_status=$?
set -e
[[ "$poison_status" -eq 1 ]] || fail "high ham/spam ratio did not fail the health check"
grep -q 'ALERT: ham/spam ratio' "$poison_output" || fail "high-ratio alert was not reported"

# A prior sample allows the script to calculate the learn-rate delta. Use a
# two-hour window so scheduler jitter cannot turn this boundary check flaky.
now=$(date +%s)
printf '%s %s %s\n' "$((now - 7200))" 700 100 >"$TMP_DIR/bayes-health.state"
rate_output="$TMP_DIR/rate.log"
set +e
env "${common_env[@]}" "$HEALTH_CHECK" >"$rate_output" 2>&1
rate_status=$?
set -e
[[ "$rate_status" -eq 1 ]] || fail "learn-rate spike did not fail the health check"
grep -q 'ALERT: learn rate' "$rate_output" || fail "learn-rate alert was not reported"

malformed_output="$TMP_DIR/malformed.log"
set +e
env "${common_env[@]}" FAKE_MALFORMED=true "$HEALTH_CHECK" >"$malformed_output" 2>&1
malformed_status=$?
set -e
[[ "$malformed_status" -ne 0 ]] || fail "malformed statistics were accepted"

# Opt-in live controller check. This performs one real learn_ham operation and
# is intentionally disabled for the fast, offline test path.
if [[ "${RUN_RSPAMD_INTEGRATION:-false}" == true ]]; then
  : "${BAYES_CONTROLLER_URL:?BAYES_CONTROLLER_URL is required for integration testing}"
  : "${BAYES_CONTROLLER_READ_PASSWORD:?BAYES_CONTROLLER_READ_PASSWORD is required for integration testing}"
  : "${BAYES_CONTROLLER_ENABLE_PASSWORD:?BAYES_CONTROLLER_ENABLE_PASSWORD is required for integration testing}"
  command -v curl >/dev/null 2>&1 || fail "curl is required for integration testing"

  controller_url=${BAYES_CONTROLLER_URL%/}
  integration_mime=$(printf 'From: guard-test@example.test\r\nTo: guard-test@example.test\r\nSubject: MSG-1795 controller auth integration\r\nMessage-ID: <msg1795-%s@example.test>\r\n\r\nThis legitimate message contains enough ordinary words to satisfy the Bayes minimum token requirement.\r\n' "$$")

  no_auth_code=$(printf '%s' "$integration_mime" | curl -sS -o "$TMP_DIR/no-auth.response" -w '%{http_code}' \
    --data-binary @- "$controller_url/learnham")
  [[ "$no_auth_code" == 401 || "$no_auth_code" == 403 ]] || fail "unauthenticated learn_ham returned HTTP $no_auth_code"

  read_auth_code=$(printf '%s' "$integration_mime" | curl -sS -o "$TMP_DIR/read-auth.response" -w '%{http_code}' \
    -H "Password: $BAYES_CONTROLLER_READ_PASSWORD" --data-binary @- "$controller_url/learnham")
  [[ "$read_auth_code" == 401 || "$read_auth_code" == 403 ]] || fail "read-only password authorized learn_ham (HTTP $read_auth_code)"

  enable_auth_code=$(printf '%s' "$integration_mime" | curl -sS -o "$TMP_DIR/enable-auth.response" -w '%{http_code}' \
    -H 'Learn-Type: bulk' -H "Password: $BAYES_CONTROLLER_ENABLE_PASSWORD" \
    --data-binary @- "$controller_url/learnham")
  [[ "$enable_auth_code" == 200 ]] || fail "enable password did not authorize learn_ham (HTTP $enable_auth_code)"
fi

printf 'bayes_guard_test: PASS\n'
