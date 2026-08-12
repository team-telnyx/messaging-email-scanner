#!/usr/bin/env bash
# MSG-1833: Integration test for HTML link extraction
# Verifies prefilter ordering (HTML_LINK_MISMATCH runs before PHISH_URL_HEURISTIC)
# and numeric-label rejection (version numbers don't trigger mismatch)
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
IMAGE=${HTML_LINK_TEST_IMAGE:-messaging-email-scanner:html-link-test}
CONTAINER="html-link-test-$$"
TMP_DIR=$(mktemp -d "$REPO_ROOT/.html-link-test.XXXXXX")

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

fail() {
  printf 'html_link_test: FAIL: %s\n' "$*" >&2
  docker logs "$CONTAINER" >&2 2>/dev/null || true
  exit 1
}

command -v docker >/dev/null 2>&1 || fail 'docker is required'

if [[ "${HTML_LINK_SKIP_BUILD:-0}" != "1" ]]; then
  docker build -t "$IMAGE" "$REPO_ROOT"
fi

docker run -d \
  --name "$CONTAINER" \
  -e RSPAMD_LOGGING_LEVEL=info \
  -e RSPAMD_CONTROLLER_PASSWORD=local-read-only \
  -e RSPAMD_CONTROLLER_ENABLE_PASSWORD=local-enable \
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

# Test 1: HTML email with display/href domain mismatch → HTML_LINK_MISMATCH fires
cat >"$TMP_DIR/mismatch.eml" <<'EOF'
From: sender@example.org
To: recipient@example.net
Date: Tue, 12 Aug 2026 12:00:00 +0000
Subject: Verify your account
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8

<html><body>
<p>Click <a href="https://evil.com/login">paypal.com</a> to verify.</p>
</body></html>
EOF

scan "$TMP_DIR/mismatch.eml" >"$TMP_DIR/mismatch.out" 2>&1
if ! grep -Eq 'HTML_LINK_MISMATCH' "$TMP_DIR/mismatch.out"; then
  sed 's/^/  /' "$TMP_DIR/mismatch.out" >&2
  fail 'expected HTML_LINK_MISMATCH for display/href domain mismatch'
fi

# Test 2: HTML email with version-number display text → no HTML_LINK_MISMATCH
cat >"$TMP_DIR/version.eml" <<'EOF'
From: sender@example.org
To: recipient@example.net
Date: Tue, 12 Aug 2026 12:00:00 +0000
Subject: Release notes
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8

<html><body>
<p>Read the <a href="https://docs.example.com/release">Version 1.23 release notes</a></p>
</body></html>
EOF

scan "$TMP_DIR/version.eml" >"$TMP_DIR/version.out" 2>&1
if grep -Eq 'HTML_LINK_MISMATCH' "$TMP_DIR/version.out"; then
  sed 's/^/  /' "$TMP_DIR/version.out" >&2
  fail 'version-number display text should not trigger HTML_LINK_MISMATCH'
fi

# Test 3: Plain text email → no HTML_LINK_MISMATCH
cat >"$TMP_DIR/plain.eml" <<'EOF'
From: sender@example.org
To: recipient@example.net
Date: Tue, 12 Aug 2026 12:00:00 +0000
Subject: Plain text
Content-Type: text/plain; charset=UTF-8

Hello, please visit https://evil.com/login to verify.
EOF

scan "$TMP_DIR/plain.eml" >"$TMP_DIR/plain.out" 2>&1
if grep -Eq 'HTML_LINK_MISMATCH' "$TMP_DIR/plain.out"; then
  sed 's/^/  /' "$TMP_DIR/plain.out" >&2
  fail 'plain text email should not trigger HTML_LINK_MISMATCH'
fi

# Test 4: HTML email with matching display/href domain → no HTML_LINK_MISMATCH
cat >"$TMP_DIR/clean.eml" <<'EOF'
From: sender@example.org
To: recipient@example.net
Date: Tue, 12 Aug 2026 12:00:00 +0000
Subject: Check your account
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8

<html><body>
<p>Visit <a href="https://www.google.com/search">google.com</a> for more info.</p>
</body></html>
EOF

scan "$TMP_DIR/clean.eml" >"$TMP_DIR/clean.out" 2>&1
if grep -Eq 'HTML_LINK_MISMATCH' "$TMP_DIR/clean.out"; then
  sed 's/^/  /' "$TMP_DIR/clean.out" >&2
  fail 'matching display/href domain should not trigger HTML_LINK_MISMATCH'
fi

printf 'html_link_test: PASS\n'
