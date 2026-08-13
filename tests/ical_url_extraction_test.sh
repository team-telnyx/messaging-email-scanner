#!/usr/bin/env bash
# MSG-1860: Docker integration test for phishing URLs in iCalendar MIME parts.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
IMAGE=${ICAL_URL_TEST_IMAGE:-messaging-email-scanner:ical-test}
CONTAINER="ical-url-test-$$"
TMP_DIR=$(mktemp -d "$REPO_ROOT/.ical-url-test.XXXXXX")
FIXTURE="$REPO_ROOT/tests/corpus/attacks/phishing_url/16_calendar_invite_urls.eml"

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

fail() {
  printf 'ical_url_extraction_test: FAIL: %s\n' "$*" >&2
  docker logs "$CONTAINER" >&2 2>/dev/null || true
  exit 1
}

command -v docker >/dev/null 2>&1 || fail 'docker is required'
[[ -f "$FIXTURE" ]] || fail "missing fixture: $FIXTURE"

if [[ "${ICAL_URL_SKIP_BUILD:-0}" != "1" ]]; then
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

scan "$FIXTURE" >"$TMP_DIR/base64.out" 2>&1
for symbol in ICAL_URL_EXTRACTION PHISH_URL_HEURISTIC LOOKALIKE_DOMAIN; do
  if ! grep -Eq "Symbol: ${symbol}([[:space:] (]|$)" "$TMP_DIR/base64.out"; then
    sed 's/^/  /' "$TMP_DIR/base64.out" >&2
    fail "expected $symbol for base64 calendar fixture"
  fi
done

base64_action=$(sed -n 's/^[[:space:]]*Action:[[:space:]]*//p' "$TMP_DIR/base64.out" | head -n 1)
case "$base64_action" in
  "add header"|"rewrite subject"|quarantine|reject) ;;
  *)
    sed 's/^/  /' "$TMP_DIR/base64.out" >&2
    fail "expected add-header-or-higher action for base64 calendar fixture, got ${base64_action:-<missing>}"
    ;;
esac

# Quoted-printable calendar parts must also be decoded and inspected.
cat >"$TMP_DIR/quoted-printable.eml" <<'EOF'
From: Calendar Service <calendar@phishing.test>
To: employee@example.org
Date: Thu, 13 Aug 2026 12:00:00 +0000
Subject: Account Review
Message-ID: <msg-1860-calendar-qp@phishing.test>
MIME-Version: 1.0
Content-Type: text/calendar; method=REQUEST; charset=utf-8
Content-Transfer-Encoding: quoted-printable

BEGIN=3AVCALENDAR
VERSION=3A2.0
BEGIN=3AVEVENT
UID=3Amsg-1860-qp@phishing.test
SUMMARY=3AAccount Review
DESCRIPTION=3AOpen https=3A//paypal.evil.example/confirm
END=3AVEVENT
END=3AVCALENDAR
EOF

scan "$TMP_DIR/quoted-printable.eml" >"$TMP_DIR/quoted-printable.out" 2>&1
for symbol in ICAL_URL_EXTRACTION PHISH_URL_HEURISTIC; do
  if ! grep -Eq "Symbol: ${symbol}([[:space:] (]|$)" "$TMP_DIR/quoted-printable.out"; then
    sed 's/^/  /' "$TMP_DIR/quoted-printable.out" >&2
    fail "expected $symbol for quoted-printable calendar"
  fi
done

# A URL-free calendar remains informationally clean.
cat >"$TMP_DIR/clean.eml" <<'EOF'
From: Calendar Service <calendar@example.org>
To: employee@example.org
Date: Thu, 13 Aug 2026 12:00:00 +0000
Subject: Team Sync
Message-ID: <msg-1860-calendar-clean@example.org>
MIME-Version: 1.0
Content-Type: text/calendar; method=REQUEST; charset=utf-8
Content-Transfer-Encoding: 8bit

BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VEVENT
UID:msg-1860-clean@example.org
SUMMARY:Weekly team sync
DESCRIPTION:Discuss project status and next steps.
END:VEVENT
END:VCALENDAR
EOF

scan "$TMP_DIR/clean.eml" >"$TMP_DIR/clean.out" 2>&1
if grep -Eq 'Symbol: (ICAL_URL_EXTRACTION|PHISH_URL_HEURISTIC|LOOKALIKE_DOMAIN)([[:space:] (]|$)' "$TMP_DIR/clean.out"; then
  sed 's/^/  /' "$TMP_DIR/clean.out" >&2
  fail 'URL-free calendar should not trigger iCalendar or phishing URL symbols'
fi

printf 'ical_url_extraction_test: PASS\n'
