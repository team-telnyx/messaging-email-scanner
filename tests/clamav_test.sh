#!/bin/bash
set -euo pipefail

# Test ClamAV integration
# Requires: Rspamd running with access to ClamAV on the scanner-net network.

RSPAMC_BIN=${RSPAMC_BIN:-rspamc}
RSPAMD_HOST=${RSPAMD_HOST:-localhost:11333}
SCAN_OUTPUT=

fail() {
  printf 'clamav_test: FAIL: %s\n' "$*" >&2
  exit 1
}

run_scan() {
  local label=$1
  local message=$2
  local status

  set +e
  SCAN_OUTPUT=$(printf '%s' "$message" | \
    "$RSPAMC_BIN" -h "$RSPAMD_HOST" --header "Settings-ID: outbound" 2>&1)
  status=$?
  set -e

  printf '%s\n' "$SCAN_OUTPUT"
  if ((status != 0)); then
    printf 'clamav_test: %s scan failed with rspamc exit status %d\n' \
      "$label" "$status" >&2
    return "$status"
  fi
}

# Test 1: EICAR test file (standard antivirus test)
EICAR='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
printf -v VIRUS_MESSAGE '%s\r\n' \
  'Subject: virus test' \
  'MIME-Version: 1.0' \
  'Content-Type: multipart/mixed; boundary="boundary"' \
  '' \
  '--boundary' \
  'Content-Type: text/plain' \
  '' \
  'clean text' \
  '--boundary' \
  'Content-Type: application/octet-stream' \
  'Content-Disposition: attachment; filename="eicar.com"' \
  '' \
  "$EICAR" \
  '--boundary--'

if ! run_scan 'EICAR attachment' "$VIRUS_MESSAGE"; then
  exit 1
fi
if ! grep -q 'CLAM_VIRUS' <<<"$SCAN_OUTPUT"; then
  fail 'EICAR attachment did not produce the CLAM_VIRUS symbol'
fi

# Test 2: Clean message — no CLAM_VIRUS
printf -v CLEAN_MESSAGE '%s\r\n' \
  'Subject: clean' \
  'Content-Type: text/plain; charset=US-ASCII' \
  '' \
  'Hello world'

if ! run_scan 'clean message' "$CLEAN_MESSAGE"; then
  exit 1
fi
if grep -q 'CLAM_VIRUS' <<<"$SCAN_OUTPUT"; then
  fail 'clean message unexpectedly produced the CLAM_VIRUS symbol'
fi

printf 'clamav_test: PASS\n'
