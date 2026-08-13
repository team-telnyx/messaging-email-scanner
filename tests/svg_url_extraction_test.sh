#!/usr/bin/env bash
# MSG-1859: Docker integration coverage for URL extraction from SVG MIME parts.
# Real .com hosts make downstream URL-symbol assertions mutation-sensitive.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
IMAGE=${SVG_URL_TEST_IMAGE:-messaging-email-scanner:svg-test}
CONTAINER="svg-url-test-$$"
TMP_DIR=$(mktemp -d "$REPO_ROOT/.svg-url-test.XXXXXX")

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

fail() {
  printf 'svg_url_extraction_test: FAIL: %s\n' "$*" >&2
  docker logs "$CONTAINER" >&2 2>/dev/null || true
  exit 1
}

command -v docker >/dev/null 2>&1 || fail 'docker is required'

if [[ "${SVG_URL_SKIP_BUILD:-0}" != "1" ]]; then
  docker build -t "$IMAGE" "$REPO_ROOT"
fi

docker run -d \
  --name "$CONTAINER" \
  -e RSPAMD_LOGGING_LEVEL=info \
  -e RSPAMD_CONTROLLER_PASSWORD=local-read-only \
  -e RSPAMD_CONTROLLER_ENABLE_PASSWORD=local-enable \
  -e URL_BLOCKLIST_REFRESH_ENABLED=0 \
  "$IMAGE" >/dev/null

status=
for attempt in $(seq 1 60); do
  status=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$CONTAINER" 2>/dev/null || true)
  if [[ "$status" == "healthy" ]]; then
    break
  fi
  if [[ "$status" == "unhealthy" || "$status" == "exited" || "$status" == "dead" ]]; then
    fail "scanner became $status"
  fi
  sleep 1
done
[[ "$status" == "healthy" ]] || fail "scanner did not become healthy (last status: ${status:-unknown})"

scan() {
  local fixture=$1
  docker exec -i "$CONTAINER" rspamc -h 127.0.0.1:11333 \
    --header 'Settings-ID: outbound' <"$fixture"
}

assert_symbol() {
  local output=$1
  local symbol=$2
  local label=$3
  if ! grep -Eq "Symbol: ${symbol}([[:space:] (]|$)" "$output"; then
    sed 's/^/  /' "$output" >&2
    fail "$label: expected symbol $symbol"
  fi
}

assert_caught() {
  local output=$1
  local label=$2
  local action
  action=$(sed -n 's/^[[:space:]]*Action:[[:space:]]*//p' "$output" | head -n 1)
  case "$action" in
    "add header"|"rewrite subject"|reject) ;;
    *)
      sed 's/^/  /' "$output" >&2
      fail "$label: expected add header or higher action, got ${action:-<missing>}"
      ;;
  esac
}

write_related_message() {
  local output=$1
  local svg=$2
  local subject=$3
  local encoded
  encoded=$(printf '%s' "$svg" | base64)

  cat >"$output" <<EOF
From: Security Team <sender@example.org>
To: recipient@example.net
Date: Wed, 13 Aug 2026 12:00:00 +0000
Subject: $subject
Message-ID: <$(basename "$output")@svg-test>
MIME-Version: 1.0
Content-Type: multipart/related; boundary="svg-boundary"

--svg-boundary
Content-Type: text/html; charset=UTF-8

<html><body><p>Open the embedded account notice.</p><img src="cid:notice@svg-test" alt="Account notice"></body></html>
--svg-boundary
Content-Type: image/svg+xml
Content-Transfer-Encoding: base64
Content-ID: <notice@svg-test>
Content-Disposition: inline; filename="notice.svg"

$encoded
--svg-boundary--
EOF
}

write_related_message \
  "$TMP_DIR/foreign-object.eml" \
  '<svg xmlns="http://www.w3.org/2000/svg"><foreignObject data="https://micros0ft.security.evil.com/microsoft/verify"></foreignObject></svg>' \
  'Foreign object notice'
scan "$TMP_DIR/foreign-object.eml" >"$TMP_DIR/foreign-object.out" 2>&1
assert_symbol "$TMP_DIR/foreign-object.out" SVG_URL_EXTRACTION "foreignObject data"
assert_symbol "$TMP_DIR/foreign-object.out" PHISH_URL_HEURISTIC "foreignObject data"
assert_caught "$TMP_DIR/foreign-object.out" "foreignObject data"

write_related_message \
  "$TMP_DIR/image-href.eml" \
  '<svg xmlns="http://www.w3.org/2000/svg"><image href="https://micros0ft.evil.com/microsoft/notice.png"/></svg>' \
  'Image resource notice'
scan "$TMP_DIR/image-href.eml" >"$TMP_DIR/image-href.out" 2>&1
assert_symbol "$TMP_DIR/image-href.out" SVG_URL_EXTRACTION "image href"
assert_symbol "$TMP_DIR/image-href.out" LOOKALIKE_DOMAIN "image href"
assert_caught "$TMP_DIR/image-href.out" "image href"

write_related_message \
  "$TMP_DIR/use-href.eml" \
  '<svg xmlns="http://www.w3.org/2000/svg"><use href="https://paypa1.security.evil.com/paypal/sprite.svg#login"/></svg>' \
  'External SVG resource notice'
scan "$TMP_DIR/use-href.eml" >"$TMP_DIR/use-href.out" 2>&1
assert_symbol "$TMP_DIR/use-href.out" SVG_URL_EXTRACTION "use href"
assert_symbol "$TMP_DIR/use-href.out" PHISH_URL_HEURISTIC "use href"
assert_caught "$TMP_DIR/use-href.out" "use href"

# The same XML content under a non-SVG MIME type must remain out of scope.
cat >"$TMP_DIR/non-svg.eml" <<'EOF'
From: Security Team <sender@example.org>
To: recipient@example.net
Date: Wed, 13 Aug 2026 12:00:00 +0000
Subject: XML document
Message-ID: <non-svg@svg-test>
MIME-Version: 1.0
Content-Type: application/xml

<svg><foreignObject data="https://microsoft.security.evil.com/verify"/></svg>
EOF
scan "$TMP_DIR/non-svg.eml" >"$TMP_DIR/non-svg.out" 2>&1
if grep -Eq 'Symbol: SVG_URL_EXTRACTION([[:space:] (]|$)' "$TMP_DIR/non-svg.out"; then
  sed 's/^/  /' "$TMP_DIR/non-svg.out" >&2
  fail 'non-SVG MIME part must not trigger SVG_URL_EXTRACTION'
fi
if grep -Eq 'Symbol: PHISH_URL_HEURISTIC([[:space:] (]|$)' "$TMP_DIR/non-svg.out"; then
  sed 's/^/  /' "$TMP_DIR/non-svg.out" >&2
  fail 'non-SVG embedded attribute must not reach PHISH_URL_HEURISTIC'
fi

printf 'svg_url_extraction_test: PASS\n'
