#!/usr/bin/env bash
set -euo pipefail

# MSG-1797 live integration tests. Requires the custom scanner image running
# with its scanner port reachable by rspamc.
RSPAMC_BIN=${RSPAMC_BIN:-rspamc}
RSPAMD_HOST=${RSPAMD_HOST:-127.0.0.1:11333}
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

fail() {
  printf 'ocr_test: FAIL: %s\n' "$*" >&2
  exit 1
}

command -v "$RSPAMC_BIN" >/dev/null 2>&1 || fail "$RSPAMC_BIN is required"
command -v python3 >/dev/null 2>&1 || fail "python3 is required"
python3 "$REPO_ROOT/tests/generate_ocr_images.py" "$TMP_DIR"

[[ $(wc -c <"$TMP_DIR/small-logo.png") -lt 10240 ]] || fail "small logo fixture is not below min_size"
[[ $(wc -c <"$TMP_DIR/spam.png") -gt 10240 ]] || fail "spam fixture is not above min_size"
[[ $(wc -c <"$TMP_DIR/benign.png") -gt 10240 ]] || fail "benign fixture is not above min_size"

make_message() {
  local image=$1
  local subject=$2
  local body=$3
  local output=$4
  local filename
  filename=$(basename "$image")

  {
    printf 'From: ocr-test@example.test\r\n'
    printf 'To: recipient@example.test\r\n'
    printf 'Subject: %s\r\n' "$subject"
    printf 'MIME-Version: 1.0\r\n'
    printf 'Content-Type: multipart/mixed; boundary="msg1797-boundary"\r\n'
    printf '\r\n'
    printf '%s\r\n' '--msg1797-boundary'
    printf 'Content-Type: text/plain; charset=UTF-8\r\n'
    printf 'Content-Transfer-Encoding: 7bit\r\n'
    printf '\r\n%s\r\n' "$body"
    printf '%s\r\n' '--msg1797-boundary'
    printf 'Content-Type: image/png; name="%s"\r\n' "$filename"
    printf 'Content-Disposition: attachment; filename="%s"\r\n' "$filename"
    printf 'Content-Transfer-Encoding: base64\r\n'
    printf '\r\n'
    base64 <"$image"
    printf '\r\n%s\r\n' '--msg1797-boundary--'
  } >"$output"
}

make_empty_image_message() {
  local image=$1
  local subject=$2
  local output=$3
  local filename
  filename=$(basename "$image")

  {
    printf 'From: ocr-test@example.test\r\n'
    printf 'To: recipient@example.test\r\n'
    printf 'Subject: %s\r\n' "$subject"
    printf 'MIME-Version: 1.0\r\n'
    printf 'Content-Type: multipart/related; boundary="msg1797-empty-image"\r\n'
    printf '\r\n'
    printf '%s\r\n' '--msg1797-empty-image'
    printf 'Content-Type: text/html; charset=UTF-8\r\n'
    printf 'Content-Transfer-Encoding: 7bit\r\n'
    printf '\r\n'
    printf '<html><body><img src="cid:ocr-image" width="400" height="200"></body></html>\r\n'
    printf '%s\r\n' '--msg1797-empty-image'
    printf 'Content-Type: image/png; name="%s"\r\n' "$filename"
    printf 'Content-Disposition: inline; filename="%s"\r\n' "$filename"
    printf 'Content-ID: <ocr-image>\r\n'
    printf 'Content-Transfer-Encoding: base64\r\n'
    printf '\r\n'
    base64 <"$image"
    printf '\r\n%s\r\n' '--msg1797-empty-image--'
  } >"$output"
}

scan() {
  local message=$1
  local output=$2
  local status

  set +e
  "$RSPAMC_BIN" -h "$RSPAMD_HOST" --header "Settings-ID: outbound" "$message" >"$output" 2>&1
  status=$?
  set -e
  if ((status != 0)); then
    printf '%s\n' "$(<"$output")" >&2
    fail "rspamc failed with exit status $status"
  fi
}

score_from_output() {
  python3 - "$1" <<'PY'
import re
import sys
text = open(sys.argv[1], encoding="utf-8", errors="replace").read()
match = re.search(r"Score:\s*(-?[0-9]+(?:\.[0-9]+)?)", text)
if not match:
    raise SystemExit("could not parse rspamc score")
print(match.group(1))
PY
}

make_message "$TMP_DIR/spam.png" "Image offer" "Please see the attached offer." "$TMP_DIR/spam.eml"
make_message "$TMP_DIR/small-logo.png" "Small clean logo" \
  "This ordinary account notification contains a small brand logo and no promotional offer." \
  "$TMP_DIR/small.eml"
make_message "$TMP_DIR/benign.png" "Benign newsletter image" \
  "This ordinary quarterly newsletter contains a large editorial image." \
  "$TMP_DIR/benign.eml"
make_empty_image_message "$TMP_DIR/benign.png" "Empty HTML image" \
  "$TMP_DIR/empty-image.eml"

# Test 1: image-carried spam text is extracted and contributes score.
scan "$TMP_DIR/spam.eml" "$TMP_DIR/spam.out"
grep -q 'OCR_PROCESSED' "$TMP_DIR/spam.out" || fail "spam image was not OCR processed"
grep -q 'OCR_SPAM_TEXT' "$TMP_DIR/spam.out" || fail "spam OCR text did not produce OCR_SPAM_TEXT"

# Test 2: a clean logo under 10 KiB never invokes Tesseract.
scan "$TMP_DIR/small.eml" "$TMP_DIR/small.out"
grep -q 'OCR_SKIPPED' "$TMP_DIR/small.out" || fail "small logo did not report OCR_SKIPPED"
if grep -q 'OCR_PROCESSED\|OCR_SPAM_TEXT' "$TMP_DIR/small.out"; then
  fail "small logo unexpectedly ran OCR"
fi

# Test 3: a large benign image is OCR processed without spam evidence.
scan "$TMP_DIR/benign.eml" "$TMP_DIR/benign.out"
grep -q 'OCR_PROCESSED' "$TMP_DIR/benign.out" || fail "large benign image was not OCR processed"
if grep -q 'OCR_SPAM_TEXT' "$TMP_DIR/benign.out"; then
  fail "large benign image produced OCR_SPAM_TEXT"
fi

spam_score=$(score_from_output "$TMP_DIR/spam.out")
benign_score=$(score_from_output "$TMP_DIR/benign.out")
python3 - "$spam_score" "$benign_score" <<'PY'
import sys
spam, benign = map(float, sys.argv[1:])
if spam <= benign:
    raise SystemExit(f"spam score {spam} did not exceed benign score {benign}")
PY

# Test 4: Rspamd's built-in R_EMPTY_IMAGE signal remains available alongside
# OCR for a nearly empty HTML body containing a large inline image.
scan "$TMP_DIR/empty-image.eml" "$TMP_DIR/empty-image.out"
grep -q 'R_EMPTY_IMAGE' "$TMP_DIR/empty-image.out" || fail "R_EMPTY_IMAGE was not emitted"
grep -q 'OCR_PROCESSED' "$TMP_DIR/empty-image.out" || fail "empty HTML image was not OCR processed"

printf 'ocr_test: PASS (spam score=%s, benign score=%s)\n' "$spam_score" "$benign_score"
