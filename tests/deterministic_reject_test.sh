#!/usr/bin/env bash
set -euo pipefail

# NOTE: CLAM_VIRUS testing requires ClamAV sidecar (MSG-1783)
# Only PHISHED_OPENPHISH is tested here as the deterministic symbol
# The live canary requires OPENPHISH_TEST_URL to name a URL currently present
# in the running OpenPhish feed; it submits that MIME through rspamc.

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CANARY="$REPO_ROOT/scripts/canary.sh"
SETTINGS_CONFIG="$REPO_ROOT/config/local.d/settings.conf"
DEAD_CONFIG="$REPO_ROOT/config/local.d/deterministic_reject.conf"
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

cat >"$TMP_DIR/rspamc" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail

if [[ "${RSPAMD_SCAN_MODE:-}" != "deterministic_reject" ]]; then
  printf 'RSPAMD_SCAN_MODE was not exported to rspamc\n' >&2
  exit 2
fi

settings_id_seen=false
previous=
for argument in "$@"; do
  if [[ "$previous" == "--header" && "$argument" == "Settings-ID: outbound" ]]; then
    settings_id_seen=true
  fi
  if [[ "$previous" == "--header" && "$argument" == Settings:* ]]; then
    printf 'inline Settings header used instead of Settings-ID: outbound\n' >&2
    exit 2
  fi
  previous=$argument
done
if [[ "$settings_id_seen" != true ]]; then
  printf 'Settings-ID: outbound header missing\n' >&2
  exit 2
fi

fixture=${!#}
message=$(<"$fixture")
case "$message" in
  *"Subject: Telnyx scanner deterministic phishing canary"*)
    printf 'Action: add header\nScore: 10.80 / 15.00\nSymbol: PHISHED_OPENPHISH\n'
    ;;
  *"Subject: Telnyx scanner spam canary"*)
    printf 'Action: reject\nScore: 1000.00 / 15.00\nSymbol: GTUBE\n'
    ;;
  *"Subject: Telnyx scanner clean canary"*)
    printf 'Action: no action\nScore: 0.00 / 15.00\n'
    ;;
  *"Subject: Telnyx scanner medium-score canary"*)
    printf 'Action: add header\nScore: %s / 15.00\nSymbol: MISSING_DATE\n' "${FAKE_RSPAMC_MEDIUM_SCORE:-8.00}"
    ;;
  *)
    printf 'unexpected fixture\n' >&2
    exit 2
    ;;
esac
FAKE
chmod +x "$TMP_DIR/rspamc"

output="$TMP_DIR/output.log"
PATH="$TMP_DIR:$PATH" RSPAMC_BIN=rspamc \
  OPENPHISH_TEST_URL=https://known-openphish.test/login \
  "$CANARY" --mode deterministic_reject >"$output"

# GTUBE remains a basic Rspamd reject-path check; it is not deterministic evidence.
grep -q '"canary":"spam".*"status":"pass".*"expected":"reject".*"actual_action":"reject"' "$output"
grep -q '"canary":"clean".*"status":"pass".*"expected":"accept".*"actual_action":"no action"' "$output"
grep -q '"canary":"medium_score".*"status":"pass".*"expected":"accept".*"actual_action":"add header"' "$output"
# This is the deterministic precondition: PHISHED_OPENPHISH is present at 10.8,
# where Rspamd says add-header; KumoMTA's map_action test proves this maps to reject.
grep -q '"canary":"deterministic_phishing".*"status":"pass".*"expected":"reject".*"actual_action":"add header".*PHISHED_OPENPHISH' "$output"
grep -q '"event":"rspamd_canary_summary","status":"pass","mode":"deterministic_reject","passed":4,"failed":0' "$output"

zero_score_output="$TMP_DIR/zero-score-output.log"
set +e
PATH="$TMP_DIR:$PATH" RSPAMC_BIN=rspamc FAKE_RSPAMC_MEDIUM_SCORE=0.00 \
  OPENPHISH_TEST_URL=https://known-openphish.test/login \
  "$CANARY" --mode deterministic_reject >"$zero_score_output"
zero_score_status=$?
set -e
if [[ "$zero_score_status" -ne 1 ]]; then
  printf 'expected zero-score canary to fail, got exit %s\n' "$zero_score_status" >&2
  exit 1
fi
grep -q '"canary":"medium_score".*"status":"fail"' "$zero_score_output"

[[ ! -e "$DEAD_CONFIG" ]]
grep -q 'Scan modes (controlled by RSPAMD_SCAN_MODE env var in KumoMTA)' "$SETTINGS_CONFIG"
grep -q 'deterministic_reject.*PHISHED_OPENPHISH' "$SETTINGS_CONFIG"
grep -Eq 'reject[[:space:]]*=[[:space:]]*15\.0;' "$SETTINGS_CONFIG"

printf 'deterministic_reject_test: PASS\n'
