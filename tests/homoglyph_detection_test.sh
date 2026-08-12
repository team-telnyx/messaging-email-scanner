#!/usr/bin/env bash
# MSG-1847: Integration test for homoglyph/lookalike domain detection
# Verifies that homoglyph domains fire LOOKALIKE_DOMAIN and legitimate domains don't
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
IMAGE=${HOMOGLYPH_TEST_IMAGE:-messaging-email-scanner:homoglyph-test}
CONTAINER="homoglyph-test-$$"
TMP_DIR=$(mktemp -d "$REPO_ROOT/.homoglyph-test.XXXXXX")

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

fail() {
  printf 'homoglyph_test: FAIL: %s\n' "$*" >&2
  docker logs "$CONTAINER" >&2 2>/dev/null || true
  exit 1
}

command -v docker >/dev/null 2>&1 || fail 'docker is required'

if [[ "${HOMOGLYPH_SKIP_BUILD:-0}" != "1" ]]; then
  docker build -t "$IMAGE" "$REPO_ROOT"
fi

docker run -d \
  --name "$CONTAINER" \
  -e RSPAMD_CONTROLLER_PASSWORD=seedpass \
  -e RSPAMD_CONTROLLER_ENABLE_PASSWORD=seedpass \
  -e URL_BLOCKLIST_REFRESH_ENABLED=0 \
  "$IMAGE" >/dev/null

for attempt in $(seq 1 30); do
  status=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$CONTAINER")
  if [[ "$status" == "healthy" ]]; then
    break
  fi
  if [[ "$status" == "unhealthy" || "$status" == "exited" || "$status" == "dead" ]]; then
    fail "scanner became $status"
  fi
  sleep 1
done

scan() {
  local fixture=$1
  docker exec -i "$CONTAINER" rspamc -h 127.0.0.1:11333 \
    --header 'Settings-ID: outbound' <"$fixture"
}

# Test 1: Homoglyph domain (micros0ft) should trigger LOOKALIKE_DOMAIN
cat >"$TMP_DIR/homoglyph.eml" <<'EOF'
From: sender@micros0ft-share.example
To: victim@example.net
Date: Tue, 12 Aug 2026 12:00:00 +0000
Subject: Shared document
Message-ID: <homoglyph1@test.example>
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8

<html><body>
<p><a href="https://micros0ft-share.example/view">Open document</a></p>
</body></html>
EOF

scan "$TMP_DIR/homoglyph.eml" >"$TMP_DIR/homoglyph.out" 2>&1
if ! grep -Eq 'LOOKALIKE_DOMAIN' "$TMP_DIR/homoglyph.out"; then
  sed 's/^/  /' "$TMP_DIR/homoglyph.out" >&2
  fail 'expected LOOKALIKE_DOMAIN for micros0ft homoglyph domain'
fi

# Test 2: Levenshtein lookalike (paypall.com) should trigger LOOKALIKE_DOMAIN
cat >"$TMP_DIR/levenshtein.eml" <<'EOF'
From: sender@paypall.example
To: victim@example.net
Date: Tue, 12 Aug 2026 12:00:00 +0000
Subject: Verify account
Message-ID: <levenshtein1@test.example>
MIME-Version: 1.0
Content-Type: text/plain

Please verify your account at https://paypall.example/verify
EOF

scan "$TMP_DIR/levenshtein.eml" >"$TMP_DIR/levenshtein.out" 2>&1
if ! grep -Eq 'LOOKALIKE_DOMAIN' "$TMP_DIR/levenshtein.out"; then
  sed 's/^/  /' "$TMP_DIR/levenshtein.out" >&2
  fail 'expected LOOKALIKE_DOMAIN for paypall.com (Levenshtein distance 1 from paypal)'
fi

# Test 3: Official brand subdomain (apps.apple.com) must NOT trigger LOOKALIKE_DOMAIN
cat >"$TMP_DIR/brand_subdomain.eml" <<'EOF'
From: sender@apple.example
To: victim@example.net
Date: Tue, 12 Aug 2026 12:00:00 +0000
Subject: App Store
Message-ID: <brandsub1@test.example>
MIME-Version: 1.0
Content-Type: text/plain

Download from https://apps.apple.example/us/app/id123456
EOF

scan "$TMP_DIR/brand_subdomain.eml" >"$TMP_DIR/brand_subdomain.out" 2>&1
if grep -Eq 'LOOKALIKE_DOMAIN' "$TMP_DIR/brand_subdomain.out"; then
  sed 's/^/  /' "$TMP_DIR/brand_subdomain.out" >&2
  fail 'apps.apple.com should NOT trigger LOOKALIKE_DOMAIN (legitimate brand subdomain)'
fi

# Test 4: Non-brand domain must NOT trigger
cat >"$TMP_DIR/clean.eml" <<'EOF'
From: sender@example.org
To: victim@example.net
Date: Tue, 12 Aug 2026 12:00:00 +0000
Subject: Hello
Message-ID: <clean1@test.example>
MIME-Version: 1.0
Content-Type: text/plain

Visit https://www.example.org/info for more details.
EOF

scan "$TMP_DIR/clean.eml" >"$TMP_DIR/clean.out" 2>&1
if grep -Eq 'LOOKALIKE_DOMAIN' "$TMP_DIR/clean.out"; then
  sed 's/^/  /' "$TMP_DIR/clean.out" >&2
  fail 'example.org should NOT trigger LOOKALIKE_DOMAIN'
fi

printf 'homoglyph_test: PASS\n'
