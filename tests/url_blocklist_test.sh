#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
IMAGE=${URL_BLOCKLIST_TEST_IMAGE:-messaging-email-scanner:url-blocklist-test}
CONTAINER="url-blocklist-test-$$"
# Keep bind-mounted fixtures under the repository so Docker Desktop/Colima can
# access them even when the host's private TMPDIR is not shared with the VM.
TMP_DIR=$(mktemp -d "$REPO_ROOT/.url-blocklist-test.XXXXXX")
OPENPHISH_URL="https://example.org/openphish-blocklist-test/login"
URLHAUS_URL="http://example.net/urlhaus-blocklist-test/payload.exe"
LEGITIMATE_URL="https://www.google.com/"

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

fail() {
  printf 'url_blocklist_test: FAIL: %s\n' "$*" >&2
  docker logs "$CONTAINER" >&2 2>/dev/null || true
  exit 1
}

write_message() {
  local path=$1
  local subject=$2
  local url=$3

  cat >"$path" <<EOF
From: sender@example.org
To: recipient@example.net
Date: Tue, 11 Aug 2026 12:00:00 +0000
Message-ID: <${subject// /-}@example.org>
Subject: $subject
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit

Please review $url for more information.
EOF
}

start_scanner() {
  local map_file=$1
  local status=
  local attempt

  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  docker run -d \
    --name "$CONTAINER" \
    --mount "type=bind,src=$map_file,dst=/etc/rspamd/local.d/maps.d/url_blocklist.map,readonly" \
    -e RSPAMD_LOGGING_LEVEL=info \
    -e RSPAMD_CONTROLLER_PASSWORD=local-read-only \
    -e RSPAMD_CONTROLLER_ENABLE_PASSWORD=local-enable \
    "$IMAGE" >/dev/null

  for attempt in $(seq 1 30); do
    status=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$CONTAINER")
    if [[ "$status" == "healthy" ]]; then
      return 0
    fi
    if [[ "$status" == "unhealthy" || "$status" == "exited" || "$status" == "dead" ]]; then
      fail "scanner became $status"
    fi
    sleep 1
  done

  fail "scanner did not become healthy (last status: ${status:-unknown})"
}

# Start scanner with a writable map directory (for hot-reload test)
start_scanner_writable() {
  local map_dir=$1
  local status=
  local attempt

  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  docker run -d \
    --name "$CONTAINER" \
    --mount "type=bind,src=$map_dir,dst=/etc/rspamd/local.d/maps.d" \
    -e RSPAMD_LOGGING_LEVEL=info \
    -e RSPAMD_CONTROLLER_PASSWORD=local-read-only \
    -e RSPAMD_CONTROLLER_ENABLE_PASSWORD=local-enable \
    -e URL_BLOCKLIST_REFRESH_ENABLED=0 \
    "$IMAGE" >/dev/null

  for attempt in $(seq 1 30); do
    status=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$CONTAINER")
    if [[ "$status" == "healthy" ]]; then
      return 0
    fi
    if [[ "$status" == "unhealthy" || "$status" == "exited" || "$status" == "dead" ]]; then
      fail "scanner became $status"
    fi
    sleep 1
  done

  fail "scanner did not become healthy (last status: ${status:-unknown})"
}

scan_message() {
  local fixture=$1
  docker exec -i "$CONTAINER" rspamc -h 127.0.0.1:11333 \
    --header 'Settings-ID: outbound' <"$fixture"
}

assert_symbol_present() {
  local output=$1
  if ! grep -Eq '(^|[^A-Z0-9_])PHISHED_URL_BLOCKLIST([^A-Z0-9_]|$)' "$output"; then
    sed 's/^/  /' "$output" >&2
    fail 'expected PHISHED_URL_BLOCKLIST in scan output'
  fi
}

assert_symbol_absent() {
  local output=$1
  if grep -Eq '(^|[^A-Z0-9_])PHISHED_URL_BLOCKLIST([^A-Z0-9_]|$)' "$output"; then
    sed 's/^/  /' "$output" >&2
    fail 'did not expect PHISHED_URL_BLOCKLIST in scan output'
  fi
}

command -v docker >/dev/null 2>&1 || fail 'docker is required'

if [[ "${URL_BLOCKLIST_SKIP_BUILD:-0}" != "1" ]]; then
  docker build -t "$IMAGE" "$REPO_ROOT"
fi

cat >"$TMP_DIR/openphish.txt" <<EOF
$OPENPHISH_URL
EOF
cat >"$TMP_DIR/urlhaus.csv" <<EOF
################################################################
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"1","2026-08-11 12:00:00","$URLHAUS_URL","online","2026-08-11 12:00:00","malware_download","test","https://urlhaus.abuse.ch/url/1/","test"
EOF
URL_BLOCKLIST_MAP="$TMP_DIR/url_blocklist.map" \
OPENPHISH_FEED_URL="file://$TMP_DIR/openphish.txt" \
URLHAUS_FEED_URL="file://$TMP_DIR/urlhaus.csv" \
RSPAMD_RELOAD=0 \
  "$REPO_ROOT/scripts/refresh_url_blocklist.sh" >"$TMP_DIR/refresh.out"

grep -Fxq "$OPENPHISH_URL" "$TMP_DIR/url_blocklist.map" || fail 'OpenPhish URL missing from refreshed map'
grep -Fxq "$URLHAUS_URL" "$TMP_DIR/url_blocklist.map" || fail 'URLhaus URL missing from refreshed map'
grep -q 'OpenPhish URLs: 1' "$TMP_DIR/refresh.out" || fail 'OpenPhish count missing from refresh log'
grep -q 'URLhaus URLs: 1' "$TMP_DIR/refresh.out" || fail 'URLhaus count missing from refresh log'

write_message "$TMP_DIR/openphish.eml" 'OpenPhish blocklist URL' "$OPENPHISH_URL"
write_message "$TMP_DIR/urlhaus.eml" 'URLhaus blocklist URL' "$URLHAUS_URL"
write_message "$TMP_DIR/legitimate.eml" 'legitimate URL' "$LEGITIMATE_URL"

start_scanner "$TMP_DIR/url_blocklist.map"

# Test 1: a URL sourced from OpenPhish emits the blocklist symbol.
scan_message "$TMP_DIR/openphish.eml" >"$TMP_DIR/openphish.out"
assert_symbol_present "$TMP_DIR/openphish.out"

# Test 2: a URL sourced from URLhaus emits the blocklist symbol.
scan_message "$TMP_DIR/urlhaus.eml" >"$TMP_DIR/urlhaus.out"
assert_symbol_present "$TMP_DIR/urlhaus.out"

# Test 3: a legitimate URL does not emit the blocklist symbol.
scan_message "$TMP_DIR/legitimate.eml" >"$TMP_DIR/legitimate.out"
assert_symbol_absent "$TMP_DIR/legitimate.out"

# Test 4: an empty blocklist does not create false positives.
mkdir -p "$TMP_DIR/maps"
: >"$TMP_DIR/maps/url_blocklist.map"
start_scanner_writable "$TMP_DIR/maps"
scan_message "$TMP_DIR/openphish.eml" >"$TMP_DIR/empty.out"
assert_symbol_absent "$TMP_DIR/empty.out"

# Test 5: hot-reload — run refresh inside the running container (from Test 4),
# poll for the symbol, and verify the container/PID is unchanged.
# The container from Test 4 has a writable map directory with an empty map.
# Copy the refresh script and feed files into the container
docker cp "$REPO_ROOT/scripts/refresh_url_blocklist.sh" "$CONTAINER:/tmp/refresh_url_blocklist.sh"
docker cp "$TMP_DIR/openphish.txt" "$CONTAINER:/tmp/openphish.txt"
docker cp "$TMP_DIR/urlhaus.csv" "$CONTAINER:/tmp/urlhaus.csv"

# Record container identity before refresh
container_id_before=$(docker inspect --format '{{.Id}}' "$CONTAINER")
pid_before=$(docker inspect --format '{{.State.Pid}}' "$CONTAINER")
restart_count_before=$(docker inspect --format '{{.RestartCount}}' "$CONTAINER")

# Verify the blocklist symbol is absent with empty map
scan_message "$TMP_DIR/openphish.eml" >"$TMP_DIR/prereload.out"
assert_symbol_absent "$TMP_DIR/prereload.out"

# Run the refresh script inside the running container against the writable map
docker exec "$CONTAINER" sh -c \
  'OPENPHISH_FEED_URL=file:///tmp/openphish.txt URLHAUS_FEED_URL=file:///tmp/urlhaus.csv URL_BLOCKLIST_MAP=/etc/rspamd/local.d/maps.d/url_blocklist.map RSPAMD_RELOAD=0 /tmp/refresh_url_blocklist.sh'

# Poll for the symbol (Rspamd watcher may take a few seconds)
hot_reload_ok=0
for attempt in $(seq 1 15); do
  scan_message "$TMP_DIR/openphish.eml" >"$TMP_DIR/hotreload.out"
  if grep -Eq 'PHISHED_URL_BLOCKLIST' "$TMP_DIR/hotreload.out"; then
    hot_reload_ok=1
    break
  fi
  sleep 1
done

if [[ "$hot_reload_ok" != "1" ]]; then
  sed 's/^/  /' "$TMP_DIR/hotreload.out" >&2
  fail 'hot-reload: PHISHED_URL_BLOCKLIST not detected after refresh in running container'
fi

# Verify container identity is unchanged (no restart)
container_id_after=$(docker inspect --format '{{.Id}}' "$CONTAINER")
pid_after=$(docker inspect --format '{{.State.Pid}}' "$CONTAINER")
restart_count_after=$(docker inspect --format '{{.RestartCount}}' "$CONTAINER")

if [[ "$container_id_before" != "$container_id_after" ]]; then
  fail 'hot-reload: container ID changed (container was recreated)'
fi
if [[ "$pid_before" != "$pid_after" ]]; then
  fail 'hot-reload: Rspamd PID changed (container was restarted)'
fi
if [[ "$restart_count_before" != "$restart_count_after" ]]; then
  fail 'hot-reload: restart count changed (container restarted)'
fi

# Test 6: entrypoint refresh loop — verify the background scheduler in entrypoint.sh
# populates the blocklist automatically without manual script invocation.
# Start a new scanner with a short refresh interval and mounted feeds.
CONTAINER2="url-blocklist-test-loop-$$"
TMP_DIR2=$(mktemp -d "$REPO_ROOT/.url-blocklist-test2.XXXXXX")
cleanup2() {
  docker rm -f "$CONTAINER2" >/dev/null 2>&1 || true
  rm -rf "$TMP_DIR2"
}
trap 'cleanup; cleanup2' EXIT

# Prepare feed files and empty map in the writable map dir
mkdir -p "$TMP_DIR2/maps"
: >"$TMP_DIR2/maps/url_blocklist.map"
cat >"$TMP_DIR2/openphish.txt" <<EOF
$OPENPHISH_URL
EOF
cat >"$TMP_DIR2/urlhaus.csv" <<EOF
################################################################
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"1","2026-08-11 12:00:00","$URLHAUS_URL","online","2026-08-11 12:00:00","malware_download","test","https://urlhaus.abuse.ch/url/1/","test"
EOF

# Start scanner with the entrypoint refresh loop enabled and a 2-second interval
docker rm -f "$CONTAINER2" >/dev/null 2>&1 || true
docker run -d \
  --name "$CONTAINER2" \
  --mount "type=bind,src=$TMP_DIR2/maps,dst=/etc/rspamd/local.d/maps.d" \
  --mount "type=bind,src=$TMP_DIR2/openphish.txt,dst=/tmp/openphish.txt,readonly" \
  --mount "type=bind,src=$TMP_DIR2/urlhaus.csv,dst=/tmp/urlhaus.csv,readonly" \
  -e RSPAMD_LOGGING_LEVEL=info \
  -e RSPAMD_CONTROLLER_PASSWORD=local-read-only \
  -e RSPAMD_CONTROLLER_ENABLE_PASSWORD=local-enable \
  -e URL_BLOCKLIST_REFRESH_ENABLED=1 \
  -e URL_BLOCKLIST_REFRESH_INTERVAL=2 \
  -e OPENPHISH_FEED_URL=file:///tmp/openphish.txt \
  -e URLHAUS_FEED_URL=file:///tmp/urlhaus.csv \
  "$IMAGE" >/dev/null

# Wait for scanner to be healthy
for attempt in $(seq 1 30); do
  status=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$CONTAINER2")
  if [[ "$status" == "healthy" ]]; then
    break
  fi
  if [[ "$status" == "unhealthy" || "$status" == "exited" || "$status" == "dead" ]]; then
    fail "loop scanner became $status"
  fi
  sleep 1
done

# Poll for the symbol (the entrypoint loop should refresh after 2 seconds)
loop_ok=0
for attempt in $(seq 1 15); do
  docker exec -i "$CONTAINER2" rspamc -h 127.0.0.1:11333 \
    --header 'Settings-ID: outbound' <"$TMP_DIR/openphish.eml" >"$TMP_DIR2/loop.out"
  if grep -Eq 'PHISHED_URL_BLOCKLIST' "$TMP_DIR2/loop.out"; then
    loop_ok=1
    break
  fi
  sleep 1
done

if [[ "$loop_ok" != "1" ]]; then
  docker logs "$CONTAINER2" >&2 2>/dev/null || true
  sed 's/^/  /' "$TMP_DIR2/loop.out" >&2
  fail 'entrypoint loop: PHISHED_URL_BLOCKLIST not detected after scheduled refresh'
fi

printf 'url_blocklist_test: PASS\n'
