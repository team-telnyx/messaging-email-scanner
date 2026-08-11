#!/usr/bin/env bash
set -euo pipefail

# NOTE: Tenant-cohort rollout, rollback, and launch gates are operational
# concerns handled by the shadow evaluation framework (MSG-1791).

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CANARY="$REPO_ROOT/scripts/canary.sh"
SETTINGS_CONFIG="$REPO_ROOT/config/local.d/settings.conf"
DEAD_CONFIG="$REPO_ROOT/config/local.d/score_reject.conf"
DOCKERFILE="$REPO_ROOT/Dockerfile"
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

cat >"$TMP_DIR/rspamc" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail

fixture=${!#}
message=$(<"$fixture")
has_outbound_settings=false

for arg in "$@"; do
  if [[ "$arg" == "Settings-ID: outbound" ]]; then
    has_outbound_settings=true
    break
  fi
done

if [[ "$has_outbound_settings" != true ]]; then
  printf 'missing Settings-ID: outbound header\n' >&2
  exit 2
fi

case "$message" in
  *"Subject: Telnyx scanner spam canary"*)
    printf 'spam\n' >>"$RSPAMC_CALL_LOG"
    printf 'Action: reject\nScore: 1000.00 / 15.00\nSymbol: GTUBE\n'
    ;;
  *"Subject: Telnyx scanner medium-score canary"*)
    printf 'medium_score\n' >>"$RSPAMC_CALL_LOG"
    printf 'Action: add header\nScore: 8.00 / 15.00\nSymbol: MISSING_DATE\n'
    ;;
  *"Subject: Telnyx scanner clean canary"*)
    printf 'clean\n' >>"$RSPAMC_CALL_LOG"
    printf 'Action: no action\nScore: 0.00 / 15.00\n'
    ;;
  *)
    printf 'unexpected fixture\n' >&2
    exit 2
    ;;
esac
FAKE
chmod +x "$TMP_DIR/rspamc"

output="$TMP_DIR/output.log"
export RSPAMC_CALL_LOG="$TMP_DIR/rspamc-calls.log"
set +e
PATH="$TMP_DIR:$PATH" RSPAMC_BIN=rspamc "$CANARY" --mode score_reject >"$output" 2>&1
status=$?
set -e

if [[ "$status" -ne 0 ]]; then
  printf 'score_reject canary failed with exit %d\n' "$status" >&2
  cat "$output" >&2
  exit 1
fi

# Test 1: GTUBE scores above 15 and must be rejected.
grep -q '"canary":"spam".*"status":"pass".*"expected":"reject".*"actual_action":"reject"' "$output"
# Test 2: A score of about 8 remains accepted below the reject threshold.
grep -q '"canary":"medium_score".*"status":"pass".*"expected":"accept".*"actual_action":"add header"' "$output"
# Test 3: A clean message remains accepted.
grep -q '"canary":"clean".*"status":"pass".*"expected":"accept".*"actual_action":"no action"' "$output"
grep -q '"event":"rspamd_canary_summary","status":"pass","mode":"score_reject","passed":3,"failed":0' "$output"

printf 'spam\nmedium_score\nclean\n' >"$TMP_DIR/expected-calls.log"
cmp "$TMP_DIR/expected-calls.log" "$RSPAMC_CALL_LOG"

[[ ! -e "$DEAD_CONFIG" ]]
grep -q 'Scan modes (controlled by RSPAMD_SCAN_MODE env var in KumoMTA)' "$SETTINGS_CONFIG"
grep -q 'score_reject.*aggregate score >= 15.0' "$SETTINGS_CONFIG"
grep -Eq 'reject[[:space:]]*=[[:space:]]*15\.0;' "$SETTINGS_CONFIG"
grep -q 'RSPAMD_SCAN_MODE=score_reject' "$DOCKERFILE"

printf 'score_reject_test: PASS\n'
