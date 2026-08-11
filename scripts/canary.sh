#!/usr/bin/env bash
# MSG-1775: end-to-end synthetic checks for the outbound Rspamd policy.
# MSG-1782/MSG-1785: shared rollout canaries for every KumoMTA scan mode.
# Runs inside the messaging-email-scanner image (rspamc is provided by Rspamd).
set -uo pipefail

RSPAMC_BIN=${RSPAMC_BIN:-rspamc}
RSPAMD_HOST=${RSPAMD_HOST:-messaging-email-scanner}
RSPAMD_PORT=${RSPAMD_PORT:-11333}
RSPAMD_TIMEOUT=${RSPAMD_TIMEOUT:-10}
RSPAMD_SCAN_MODE=${RSPAMD_SCAN_MODE:-baseline}
OPENPHISH_TEST_URL=${OPENPHISH_TEST_URL:-}
CANARY_MODE=$RSPAMD_SCAN_MODE
export RSPAMD_SCAN_MODE

usage() {
  printf 'Usage: %s [--mode shadow|quarantine|deterministic_reject|score_reject]\n' "${0##*/}"
}

while (($# > 0)); do
  case "$1" in
    --mode)
      if (($# < 2)); then
        printf '%s: --mode requires a value\n' "${0##*/}" >&2
        usage >&2
        exit 2
      fi
      CANARY_MODE=$2
      RSPAMD_SCAN_MODE=$CANARY_MODE
      export RSPAMD_SCAN_MODE
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf '%s: unknown argument: %s\n' "${0##*/}" "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

case "$CANARY_MODE" in
  baseline|shadow|quarantine|deterministic_reject|score_reject) ;;
  *)
    printf '%s: unsupported mode: %s\n' "${0##*/}" "$CANARY_MODE" >&2
    usage >&2
    exit 2
    ;;
esac

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
  local inline_settings=${2:-}
  local -a args=(
    -h "$RSPAMD_HOST:$RSPAMD_PORT"
    -t "$RSPAMD_TIMEOUT"
    -u "telnyx-rspamd-canary"
    -F "canary@msgtelnyx.com"
    -r "canary@example.com"
    --header "Settings-ID: outbound"
  )

  if [[ -n "$inline_settings" ]]; then
    args+=(--header "Settings: $inline_settings")
  fi

  "$RSPAMC_BIN" "${args[@]}" "$fixture" 2>&1
}

extract_action() {
  printf '%s\n' "$1" | sed -n 's/^Action:[[:space:]]*//p' | head -n 1
}

extract_score() {
  printf '%s\n' "$1" | sed -n 's/^Score:[[:space:]]*\([-+0-9.]*\).*/\1/p' | head -n 1
}

has_symbol() {
  local output=$1
  local symbol=$2
  printf '%s\n' "$output" | grep -Eq "(^|[^[:alnum:]_])${symbol}([^[:alnum:]_]|$)"
}

is_positive_score_below_reject() {
  [[ "$1" =~ ^((0[.][0-9]*[1-9][0-9]*)|([1-9]|1[0-4])([.][0-9]+)?)$ ]]
}

run_clean_canary() {
  local output action expected
  expected="no action"
  if [[ "$CANARY_MODE" != "baseline" ]]; then expected="accept"; fi

  if ! output=$(scan_message "$TMP_DIR/clean.eml"); then
    log_result clean fail "$expected" unavailable "rspamc request failed"
    return 1
  fi

  action=$(extract_action "$output")
  if [[ "$action" == "no action" ]]; then
    log_result clean pass "$expected" "$action" "known-clean MIME accepted"
    return 0
  fi

  log_result clean fail "$expected" "${action:-missing}" "unexpected scanner action"
  return 1
}

run_spam_canary() {
  local output action expected
  expected="reject or add header"
  if [[ "$CANARY_MODE" == "deterministic_reject" || "$CANARY_MODE" == "score_reject" ]]; then
    expected="reject"
  fi

  if ! output=$(scan_message "$TMP_DIR/spam.eml"); then
    log_result spam fail "$expected" unavailable "rspamc request failed"
    return 1
  fi

  action=$(extract_action "$output")
  if [[ "$expected" == "reject" && "$action" == "reject" ]]; then
    log_result spam pass "$expected" "$action" "GTUBE exercised the basic Rspamd reject path"
    return 0
  fi
  if [[ "$expected" == "reject or add header" && ("$action" == "reject" || "$action" == "add header") ]]; then
    log_result spam pass "$expected" "$action" "GTUBE detected"
    return 0
  fi

  log_result spam fail "$expected" "${action:-missing}" "GTUBE did not produce the expected action"
  return 1
}

run_medium_score_canary() {
  local output action score settings
  settings=""

  if [[ "$CANARY_MODE" == "score_reject" ]]; then
    # Keep this threshold canary deterministic without changing the deployed
    # outbound profile: the Settings override applies only to this rspamc call.
    settings='{"symbols":{"MISSING_DATE":8.0},"symbols_enabled":["MISSING_DATE"],"actions":{"reject":15.0,"add header":6.0,"greylist":null,"rewrite subject":null}}'
  fi

  if ! output=$(scan_message "$TMP_DIR/medium-score.eml" "$settings"); then
    log_result medium_score fail "accept" unavailable "rspamc request failed"
    return 1
  fi

  action=$(extract_action "$output")
  score=$(extract_score "$output")
  if [[ ("$action" == "no action" || "$action" == "add header") ]] && is_positive_score_below_reject "$score"; then
    log_result medium_score pass "accept" "$action" "moderate score ${score} remained below reject threshold"
    return 0
  fi

  log_result medium_score fail "accept" "${action:-missing}" "expected a non-reject action with score between 0 and 15, got ${score:-missing}"
  return 1
}

run_phishing_canary() {
  local output action
  if ! output=$(scan_message "$TMP_DIR/phishing.eml"); then
    log_result phishing fail "OPENPHISH_CANARY symbol" unavailable "rspamc request failed"
    return 1
  fi

  action=$(extract_action "$output")
  if has_symbol "$output" OPENPHISH_CANARY; then
    log_result phishing pass "OPENPHISH_CANARY symbol" "${action:-missing}" "stable scanner phishing canary detected"
    return 0
  fi

  log_result phishing fail "OPENPHISH_CANARY symbol" "${action:-missing}" "expected symbol missing"
  return 1
}

run_deterministic_phishing_canary() {
  local output action score

  if [[ -z "$OPENPHISH_TEST_URL" ]]; then
    log_result deterministic_phishing fail "reject" unavailable "OPENPHISH_TEST_URL must name a URL in the running OpenPhish feed"
    return 1
  fi

  if ! output=$(scan_message "$TMP_DIR/deterministic-phishing.eml"); then
    log_result deterministic_phishing fail "reject" unavailable "rspamc request failed"
    return 1
  fi

  action=$(extract_action "$output")
  score=$(extract_score "$output")
  if [[ "$action" == "add header" ]] && is_positive_score_below_reject "$score" && has_symbol "$output" PHISHED_OPENPHISH; then
    log_result deterministic_phishing pass "reject" "$action" "PHISHED_OPENPHISH at score ${score}; KumoMTA deterministic mapping must reject"
    return 0
  fi

  log_result deterministic_phishing fail "reject" "${action:-missing}" "expected PHISHED_OPENPHISH with add-header action below score 15, got score ${score:-missing}"
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

cat >"$TMP_DIR/medium-score.eml" <<'EOF'
From: Telnyx Canary <canary@msgtelnyx.com>
To: Scanner Canary <canary@example.com>
Message-ID: <medium-score-canary@msgtelnyx.com>
Subject: Telnyx scanner medium-score canary
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Synthetic moderate-score canary. The intentionally missing Date header activates
MISSING_DATE while remaining below the reject level.
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

cat >"$TMP_DIR/deterministic-phishing.eml" <<EOF
From: Telnyx Canary <canary@msgtelnyx.com>
To: Scanner Canary <canary@example.com>
Date: Mon, 10 Aug 2026 12:00:00 +0000
Message-ID: <deterministic-phishing-canary@msgtelnyx.com>
Subject: Telnyx scanner deterministic phishing canary
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8

<html><body><a href="$OPENPHISH_TEST_URL">Verify your account</a></body></html>
EOF

case "$CANARY_MODE" in
  baseline|shadow|quarantine)
    canaries=(clean spam phishing)
    ;;
  deterministic_reject)
    canaries=(spam clean medium_score deterministic_phishing)
    ;;
  score_reject)
    canaries=(spam medium_score clean)
    ;;
esac

for canary in "${canaries[@]}"; do
  if "run_${canary}_canary"; then
    passed=$((passed + 1))
  else
    failed=$((failed + 1))
  fi
done

if ((failed == 0)); then
  if [[ "$CANARY_MODE" == "baseline" ]]; then
    printf '{"event":"rspamd_canary_summary","status":"pass","passed":%d,"failed":0,"timestamp":"%s"}\n' "$passed" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  else
    printf '{"event":"rspamd_canary_summary","status":"pass","mode":"%s","passed":%d,"failed":0,"timestamp":"%s"}\n' "$CANARY_MODE" "$passed" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  fi
  exit 0
fi

if [[ "$CANARY_MODE" == "baseline" ]]; then
  printf '{"event":"rspamd_canary_summary","status":"fail","passed":%d,"failed":%d,"timestamp":"%s"}\n' "$passed" "$failed" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
else
  printf '{"event":"rspamd_canary_summary","status":"fail","mode":"%s","passed":%d,"failed":%d,"timestamp":"%s"}\n' "$CANARY_MODE" "$passed" "$failed" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
fi
exit 1
