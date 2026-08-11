#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CANARY="$REPO_ROOT/scripts/canary.sh"
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

cat >"$TMP_DIR/rspamc" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail

case "${RSPAMD_SCAN_MODE:-}" in
  shadow|quarantine|deterministic_reject|score_reject) ;;
  *)
    printf 'unexpected RSPAMD_SCAN_MODE=%s\n' "${RSPAMD_SCAN_MODE:-missing}" >&2
    exit 2
    ;;
esac

fixture=${!#}
message=$(<"$fixture")
case "$message" in
  *"Subject: Telnyx scanner deterministic phishing canary"*)
    printf 'Action: add header\nScore: 10.80 / 15.00\nSymbol: PHISHED_OPENPHISH\n'
    ;;
  *"Subject: Telnyx scanner phishing canary"*)
    printf 'Action: add header\nScore: 7.00 / 15.00\nSymbol: OPENPHISH_CANARY\n'
    ;;
  *"Subject: Telnyx scanner spam canary"*)
    printf 'Action: reject\nScore: 1000.00 / 15.00\nSymbol: GTUBE\n'
    ;;
  *"Subject: Telnyx scanner medium-score canary"*)
    printf 'Action: add header\nScore: 8.00 / 15.00\nSymbol: MISSING_DATE\n'
    ;;
  *"Subject: Telnyx scanner clean canary"*)
    printf 'Action: no action\nScore: 0.00 / 15.00\n'
    ;;
  *)
    printf 'unexpected fixture\n' >&2
    exit 2
    ;;
esac
FAKE
chmod +x "$TMP_DIR/rspamc"

run_mode() {
  local mode=$1
  local expected_count=$2
  local output="$TMP_DIR/$mode.log"

  PATH="$TMP_DIR:$PATH" \
    RSPAMC_BIN=rspamc \
    OPENPHISH_TEST_URL=https://known-openphish.test/login \
    "$CANARY" --mode "$mode" >"$output"

  grep -q "\"event\":\"rspamd_canary_summary\",\"status\":\"pass\",\"mode\":\"$mode\",\"passed\":$expected_count,\"failed\":0" "$output"
}

run_mode shadow 3
run_mode quarantine 3
run_mode deterministic_reject 4
run_mode score_reject 3

grep -q '"canary":"deterministic_phishing".*"status":"pass".*"expected":"reject".*"actual_action":"add header".*PHISHED_OPENPHISH' "$TMP_DIR/deterministic_reject.log"

set +e
"$CANARY" --mode unsupported >"$TMP_DIR/unsupported.log" 2>&1
unsupported_status=$?
set -e
[[ "$unsupported_status" -eq 2 ]]
grep -q 'shadow|quarantine|deterministic_reject|score_reject' "$TMP_DIR/unsupported.log"

printf 'canary_modes_test: PASS\n'
