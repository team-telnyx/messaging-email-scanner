#!/usr/bin/env bash
# MSG-1862: Integration test for external open redirects to suspicious domains.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
IMAGE=${OPEN_REDIRECT_TEST_IMAGE:-messaging-email-scanner:open-redirect-test}
CONTAINER="open-redirect-test-$$"
TMP_DIR=$(mktemp -d "$REPO_ROOT/.open-redirect-test.XXXXXX")
ATTACK_FIXTURE="$REPO_ROOT/tests/corpus/attacks/phishing_url/15_open_redirect.eml"

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

fail() {
  printf 'open_redirect_test: FAIL: %s\n' "$*" >&2
  docker logs "$CONTAINER" >&2 2>/dev/null || true
  exit 1
}

command -v docker >/dev/null 2>&1 || fail 'docker is required'
[[ -f "$ATTACK_FIXTURE" ]] || fail "missing attack fixture: $ATTACK_FIXTURE"

if [[ "${OPEN_REDIRECT_SKIP_BUILD:-0}" != "1" ]]; then
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

scan "$ATTACK_FIXTURE" >"$TMP_DIR/attack.out" 2>&1
if ! grep -Eq '^Symbol: OPEN_REDIRECT([[:space:] (]|$)' "$TMP_DIR/attack.out"; then
  sed 's/^/  /' "$TMP_DIR/attack.out" >&2
  fail 'expected OPEN_REDIRECT for LinkedIn slink to linkedin-secure.com'
fi
if ! grep -Eq '^Symbol: LOOKALIKE_DOMAIN([[:space:] (]|$)' "$TMP_DIR/attack.out"; then
  sed 's/^/  /' "$TMP_DIR/attack.out" >&2
  fail 'expected LOOKALIKE_DOMAIN for linkedin-secure.com redirect target'
fi
if ! grep -Eq '^Action: (add header|reject)$' "$TMP_DIR/attack.out"; then
  sed 's/^/  /' "$TMP_DIR/attack.out" >&2
  fail 'expected add header or reject action for suspicious open redirect'
fi

cat >"$TMP_DIR/same-domain.eml" <<'EOF'
From: sender@example.org
To: recipient@example.net
Date: Thu, 13 Aug 2026 12:00:00 +0000
Subject: Account link
Message-ID: <same-domain-open-redirect@test>
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8

<html><body><a href="https://same-domain.com/redirect?url=https://same-domain.com/path">Continue</a></body></html>
EOF
scan "$TMP_DIR/same-domain.eml" >"$TMP_DIR/same-domain.out" 2>&1
if grep -Eq '^Symbol: OPEN_REDIRECT([[:space:] (]|$)' "$TMP_DIR/same-domain.out"; then
  sed 's/^/  /' "$TMP_DIR/same-domain.out" >&2
  fail 'same-domain target must not trigger OPEN_REDIRECT'
fi

cat >"$TMP_DIR/relative.eml" <<'EOF'
From: sender@example.org
To: recipient@example.net
Date: Thu, 13 Aug 2026 12:00:00 +0000
Subject: Continue setup
Message-ID: <relative-open-redirect@test>
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8

<html><body><a href="https://legitimate.example/continue?next=/relative/path">Continue</a></body></html>
EOF
scan "$TMP_DIR/relative.eml" >"$TMP_DIR/relative.out" 2>&1
if grep -Eq '^Symbol: OPEN_REDIRECT([[:space:] (]|$)' "$TMP_DIR/relative.out"; then
  sed 's/^/  /' "$TMP_DIR/relative.out" >&2
  fail 'relative target must not trigger OPEN_REDIRECT'
fi

printf 'open_redirect_test: PASS\n'
