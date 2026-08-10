#!/usr/bin/env bash
# MSG-1775: end-to-end synthetic checks for the outbound Rspamd policy.
# Runs inside the messaging-email-scanner image (rspamc is provided by Rspamd).
set -uo pipefail

RSPAMC_BIN=${RSPAMC_BIN:-rspamc}
RSPAMD_HOST=${RSPAMD_HOST:-messaging-email-scanner}
RSPAMD_PORT=${RSPAMD_PORT:-11333}
RSPAMD_TIMEOUT=${RSPAMD_TIMEOUT:-10}

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

passed=0
failed=0

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/[[:cntrl:]]/ /g'
}

log_result() {
  local canary=$1
  local status=$2
  local expected=$3
  local actual_action=$4
  local detail=$5

  printf '{"event":"rspamd_canary","canary":"%s","status":"%s","expected":"%s","actual_action":"%s","detail":"%s"}\n' \
    "$(json_escape "$canary")" \
    "$(json_escape "$status")" \
    "$(json_escape "$expected")" \
    "$(json_escape "$actual_action")" \
    "$(json_escape "$detail")"
}

scan_message() {
  local fixture=$1
  "$RSPAMC_BIN" \
    -h "$RSPAMD_HOST:$RSPAMD_PORT" \
    -t "$RSPAMD_TIMEOUT" \
    -u "telnyx-rspamd-canary" \
    -F "canary@msgtelnyx.com" \
    -r "canary@example.com" \
    --header "Settings-ID: outbound" \
    "$fixture" 2>&1
}

extract_action() {
  printf '%s\n' "$1" | sed -n 's/^Action:[[:space:]]*//p' | head -n 1
}

run_clean_canary() {
  local output action
  if ! output=$(scan_message "$TMP_DIR/clean.eml"); then
    log_result clean fail "no action" unavailable "rspamc request failed"
    return 1
  fi

  action=$(extract_action "$output")
  if [[ "$action" == "no action" ]]; then
    log_result clean pass "no action" "$action" "known-clean MIME accepted"
    return 0
  fi

  log_result clean fail "no action" "${action:-missing}" "unexpected scanner action"
  return 1
}

run_spam_canary() {
  local output action
  if ! output=$(scan_message "$TMP_DIR/spam.eml"); then
    log_result spam fail "reject or add header" unavailable "rspamc request failed"
    return 1
  fi

  action=$(extract_action "$output")
  if [[ "$action" == "reject" || "$action" == "add header" ]]; then
    log_result spam pass "reject or add header" "$action" "GTUBE detected"
    return 0
  fi

  log_result spam fail "reject or add header" "${action:-missing}" "GTUBE was not classified as spam"
  return 1
}

run_phishing_canary() {
  local output action
  if ! output=$(scan_message "$TMP_DIR/phishing.eml"); then
    log_result phishing fail "OPENPHISH_CANARY symbol" unavailable "rspamc request failed"
    return 1
  fi

  action=$(extract_action "$output")
  if printf '%s\n' "$output" | grep -Eq '(^|[^[:alnum:]_])OPENPHISH_CANARY([^[:alnum:]_]|$)'; then
    log_result phishing pass "OPENPHISH_CANARY symbol" "${action:-missing}" "deterministic phishing URL detected"
    return 0
  fi

  log_result phishing fail "OPENPHISH_CANARY symbol" "${action:-missing}" "expected symbol missing"
  return 1
}

cat >"$TMP_DIR/clean.eml" <<'EOF'
From: Telnyx Canary <canary@msgtelnyx.com>
To: Scanner Canary <canary@example.com>
Date: Mon, 10 Aug 2026 12:00:00 +0000
Message-ID: <clean-canary@msgtelnyx.com>
Subject: Telnyx scanner clean canary
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

This is a routine synthetic monitoring message for the Telnyx email scanner.
EOF

cat >"$TMP_DIR/spam.eml" <<'EOF'
From: Telnyx Canary <canary@msgtelnyx.com>
To: Scanner Canary <canary@example.com>
Date: Mon, 10 Aug 2026 12:00:00 +0000
Message-ID: <spam-canary@msgtelnyx.com>
Subject: Telnyx scanner spam canary
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X
EOF

cat >"$TMP_DIR/phishing.eml" <<'EOF'
From: Telnyx Canary <canary@msgtelnyx.com>
To: Scanner Canary <canary@example.com>
Date: Mon, 10 Aug 2026 12:00:00 +0000
Message-ID: <phishing-canary@msgtelnyx.com>
Subject: Telnyx scanner phishing canary
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8

<html><body><a href="https://scan-canary-phish.msgtelnyx.com/login">Verify your account</a></body></html>
EOF

for canary in clean spam phishing; do
  if "run_${canary}_canary"; then
    passed=$((passed + 1))
  else
    failed=$((failed + 1))
  fi
done

if ((failed == 0)); then
  printf '{"event":"rspamd_canary_summary","status":"pass","passed":%d,"failed":0}\n' "$passed"
  exit 0
fi

printf '{"event":"rspamd_canary_summary","status":"fail","passed":%d,"failed":%d}\n' "$passed" "$failed"
exit 1
