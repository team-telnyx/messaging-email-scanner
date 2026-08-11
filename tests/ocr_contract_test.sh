#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

fail() {
  printf 'ocr_contract_test: FAIL: %s\n' "$*" >&2
  exit 1
}

assert_pattern() {
  local pattern=$1
  local file=$2
  [[ -f "$file" ]] || fail "missing $file"
  grep -Eq "$pattern" "$file" || fail "missing pattern '$pattern' in $file"
}

DOCKERFILE="$REPO_ROOT/Dockerfile"
OCR_CONFIG="$REPO_ROOT/config/local.d/ocr.conf"
OCR_PLUGIN="$REPO_ROOT/config/plugins.d/ocr.lua"
OCR_LIBRARY="$REPO_ROOT/config/lualib/ocr_select.lua"
RSPAMD_LOCAL="$REPO_ROOT/config/rspamd.conf.local"

assert_pattern 'tesseract-ocr([[:space:]\\]|$)' "$DOCKERFILE"
assert_pattern 'tesseract-ocr-eng([[:space:]\\]|$)' "$DOCKERFILE"
assert_pattern 'config/plugins\.d' "$DOCKERFILE"
assert_pattern 'config/lualib' "$DOCKERFILE"
assert_pattern 'rspamd\.conf\.local' "$DOCKERFILE"

assert_pattern 'enabled[[:space:]]*=[[:space:]]*true' "$OCR_CONFIG"
assert_pattern 'min_size[[:space:]]*=[[:space:]]*10240' "$OCR_CONFIG"
assert_pattern 'max_images[[:space:]]*=[[:space:]]*3' "$OCR_CONFIG"
assert_pattern 'timeout[[:space:]]*=[[:space:]]*10' "$OCR_CONFIG"
assert_pattern 'score_threshold[[:space:]]*=[[:space:]]*3' "$OCR_CONFIG"
assert_pattern 'image_ratio_threshold[[:space:]]*=[[:space:]]*0\.8' "$OCR_CONFIG"
assert_pattern 'max_connections' "$OCR_CONFIG"
assert_pattern 'max_load' "$OCR_CONFIG"
assert_pattern 'feed_bayes[[:space:]]*=[[:space:]]*true' "$OCR_CONFIG"

assert_pattern "type[[:space:]]*=[[:space:]]*['\"]prefilter['\"]" "$OCR_PLUGIN"
assert_pattern 'task:get_metric_score' "$OCR_PLUGIN"
assert_pattern 'task:set_message' "$OCR_PLUGIN"
assert_pattern 'OCR_PROCESSED' "$OCR_PLUGIN"
assert_pattern 'OCR_SPAM_TEXT' "$OCR_PLUGIN"
assert_pattern 'settings\.timeout_bin' "$OCR_PLUGIN"
assert_pattern 'settings\.tesseract_bin' "$OCR_PLUGIN"
assert_pattern 'local\.d/ocr\.conf' "$RSPAMD_LOCAL"

OCR_LUA_PATH="$REPO_ROOT/config/lualib" lua "$REPO_ROOT/tests/ocr_logic_test.lua"
printf 'ocr_contract_test: PASS\n'
