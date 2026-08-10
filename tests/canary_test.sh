#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CANARY="$REPO_ROOT/scripts/canary.sh"
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

cat >"$TMP_DIR/rspamc" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
fixture=${!#}
message=$(cat "$fixture")
mode=${FAKE_RSPAMC_MODE:-pass}

case "$message" in
  *"Subject: Telnyx scanner clean canary"*)
    if [[ "$mode" == "clean-fail" ]]; then
      printf 'Action: add header\nSymbol: TEST_FAILURE\n'
    else
      printf 'Action: no action\n'
    fi
    ;;
  *"Subject: Telnyx scanner spam canary"*)
    if [[ "$mode" == "spam-fail" ]]; then
      printf 'Action: no action\n'
    else
      printf 'Action: reject\nSymbol: GTUBE\n'
    fi
    ;;
  *"Subject: Telnyx scanner phishing canary"*)
    if [[ "$mode" == "phishing-fail" ]]; then
      printf 'Action: add header\nSymbol: TEST_FAILURE\n'
    else
      printf 'Action: add header\nSymbol: OPENPHISH_CANARY\n'
    fi
    ;;
  *)
    printf 'unexpected fixture\n' >&2
    exit 2
    ;;
esac
FAKE
chmod +x "$TMP_DIR/rspamc"

run_canary() {
  local mode=$1
  local expected_status=$2
  local output_file="$TMP_DIR/output-$mode.log"

  set +e
  PATH="$TMP_DIR:$PATH" \
    RSPAMC_BIN=rspamc \
    RSPAMD_HOST=scanner.test \
    RSPAMD_PORT=11333 \
    FAKE_RSPAMC_MODE="$mode" \
    "$CANARY" >"$output_file" 2>&1
  local status=$?
  set -e

  if [[ "$status" -ne "$expected_status" ]]; then
    printf 'mode=%s: expected exit %s, got %s\n' "$mode" "$expected_status" "$status" >&2
    cat "$output_file" >&2
    exit 1
  fi

  grep -q '"event":"rspamd_canary","canary":"clean"' "$output_file"
  grep -q '"event":"rspamd_canary","canary":"spam"' "$output_file"
  grep -q '"event":"rspamd_canary","canary":"phishing"' "$output_file"
}

run_canary pass 0
grep -q '"event":"rspamd_canary_summary","status":"pass","passed":3,"failed":0' "$TMP_DIR/output-pass.log"

for mode in clean-fail spam-fail phishing-fail; do
  run_canary "$mode" 1
  grep -q '"event":"rspamd_canary_summary","status":"fail","passed":2,"failed":1' "$TMP_DIR/output-$mode.log"
done

printf 'canary_test: PASS\n'
