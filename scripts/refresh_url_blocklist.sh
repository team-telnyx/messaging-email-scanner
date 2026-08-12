#!/usr/bin/env bash
set -euo pipefail

OPENPHISH_FEED_URL=${OPENPHISH_FEED_URL:-https://openphish.com/feed.txt}
URLHAUS_FEED_URL=${URLHAUS_FEED_URL:-https://urlhaus.abuse.ch/downloads/csv_recent/}
URL_BLOCKLIST_MAP=${URL_BLOCKLIST_MAP:-/etc/rspamd/local.d/maps.d/url_blocklist.map}
RSPAMD_HOST=${RSPAMD_HOST:-127.0.0.1:11334}
RSPAMD_PWD=${RSPAMD_PWD:-${RSPAMD_CONTROLLER_ENABLE_PASSWORD:-}}
RSPAMD_RELOAD=${RSPAMD_RELOAD:-1}
CURL_BIN=${CURL_BIN:-curl}
RSPAMADM_BIN=${RSPAMADM_BIN:-rspamadm}

log() {
  printf 'refresh_url_blocklist: %s\n' "$*"
}

fail() {
  printf 'refresh_url_blocklist: ERROR: %s\n' "$*" >&2
  exit 1
}

command -v "$CURL_BIN" >/dev/null 2>&1 || fail "$CURL_BIN is required"

map_dir=$(dirname "$URL_BLOCKLIST_MAP")
mkdir -p "$map_dir"
[[ -w "$map_dir" ]] || fail "map directory is not writable: $map_dir"

work_dir=$(mktemp -d "$map_dir/.url-blocklist-refresh.XXXXXX")
cleanup() {
  rm -rf "$work_dir"
}
trap cleanup EXIT

log "downloading OpenPhish feed"
"$CURL_BIN" --fail --silent --show-error --location \
  --retry 3 --retry-delay 2 \
  --output "$work_dir/openphish.txt" "$OPENPHISH_FEED_URL"

log "downloading URLhaus feed"
"$CURL_BIN" --fail --silent --show-error --location \
  --retry 3 --retry-delay 2 \
  --output "$work_dir/urlhaus.csv" "$URLHAUS_FEED_URL"

# Keep only URL records. CR stripping handles the URLhaus CSV's CRLF line endings.
awk '/^https?:\/\// { sub(/\r$/, ""); print }' \
  "$work_dir/openphish.txt" >"$work_dir/openphish.urls"
awk -F'"' '$6 ~ /^https?:\/\// { sub(/\r$/, "", $6); print $6 }' \
  "$work_dir/urlhaus.csv" >"$work_dir/urlhaus.urls"

openphish_count=$(wc -l <"$work_dir/openphish.urls" | tr -d '[:space:]')
urlhaus_count=$(wc -l <"$work_dir/urlhaus.urls" | tr -d '[:space:]')

# Do not replace a healthy map with an empty or malformed upstream response.
((openphish_count > 0)) || fail "OpenPhish feed contained no URLs"
((urlhaus_count > 0)) || fail "URLhaus feed contained no URLs"

LC_ALL=C sort -u "$work_dir/openphish.urls" "$work_dir/urlhaus.urls" \
  >"$work_dir/url_blocklist.map"
total_count=$(wc -l <"$work_dir/url_blocklist.map" | tr -d '[:space:]')

chmod 0644 "$work_dir/url_blocklist.map"
mv -f "$work_dir/url_blocklist.map" "$URL_BLOCKLIST_MAP"

log "OpenPhish URLs: $openphish_count"
log "URLhaus URLs: $urlhaus_count"
log "Combined unique URLs: $total_count"
log "updated $URL_BLOCKLIST_MAP"

if [[ "$RSPAMD_RELOAD" == "1" ]]; then
  # Local file maps are watched and reload automatically after the atomic rename.
  # Ask the local main process to refresh worker dynamic data when its control
  # socket is available; otherwise the normal map watcher performs the refresh.
  if command -v "$RSPAMADM_BIN" >/dev/null 2>&1 && \
    [[ -S /var/lib/rspamd/rspamd.sock ]]; then
    "$RSPAMADM_BIN" control reload >/dev/null
    log "requested Rspamd worker data reload"
  elif command -v rspamc >/dev/null 2>&1 && [[ -n "$RSPAMD_PWD" ]]; then
    # rspamc 3.10 has no map-reload command. Probe the authenticated controller
    # so a bad endpoint/password is visible while Rspamd's map watcher reloads.
    rspamc -h "$RSPAMD_HOST" -P "$RSPAMD_PWD" stat >/dev/null
    log "controller reachable; local map watcher will reload the changed file"
  else
    log "map changed; local map watcher will reload it"
  fi
elif [[ "$RSPAMD_RELOAD" != "0" ]]; then
  fail "RSPAMD_RELOAD must be 0 or 1"
fi
