#!/bin/sh
# Entrypoint for messaging-email-scanner
# Generates hashed controller passwords from environment variables
# and starts Rspamd with the injected values.
# Fails closed if credentials are missing — no healthy scanner with unusable controller.

set -eu

# Fail closed — both credentials must be present
if [ -z "${RSPAMD_CONTROLLER_PASSWORD:-}" ]; then
  echo "ERROR: RSPAMD_CONTROLLER_PASSWORD is required" >&2
  exit 1
fi
if [ -z "${RSPAMD_CONTROLLER_ENABLE_PASSWORD:-}" ]; then
  echo "ERROR: RSPAMD_CONTROLLER_ENABLE_PASSWORD is required" >&2
  exit 1
fi

# Generate password hashes using rspamadm pw -e -p
CONTROLLER_PASSWORD_HASH=$(rspamadm pw -e -p "${RSPAMD_CONTROLLER_PASSWORD}")
CONTROLLER_ENABLE_PASSWORD_HASH=$(rspamadm pw -e -p "${RSPAMD_CONTROLLER_ENABLE_PASSWORD}")

# Initial URL blocklist population (MSG-1829)
# The same switch disables both startup population and the recurring refresh
# loop so offline tests can run against the repository-owned empty map.
if [ -x /scripts/refresh_url_blocklist.sh ] && [ "${URL_BLOCKLIST_REFRESH_ENABLED:-1}" = "1" ]; then
  echo "Populating URL blocklist from OpenPhish + URLhaus..."
  RSPAMD_RELOAD=0 /scripts/refresh_url_blocklist.sh || \
    echo "WARNING: initial URL blocklist refresh failed; blocklist will be empty until next scheduled refresh"
fi

# Start background URL blocklist refresh loop (MSG-1829)
# OpenPhish updates hourly, URLhaus updates daily. Refresh hourly to stay current.
URL_BLOCKLIST_REFRESH_INTERVAL=${URL_BLOCKLIST_REFRESH_INTERVAL:-3600}
if [ -x /scripts/refresh_url_blocklist.sh ] && [ "${URL_BLOCKLIST_REFRESH_ENABLED:-1}" = "1" ]; then
  (
    while true; do
      sleep "$URL_BLOCKLIST_REFRESH_INTERVAL"
      echo "Refreshing URL blocklist..."
      /scripts/refresh_url_blocklist.sh || \
        echo "WARNING: URL blocklist refresh failed; using stale data"
    done
  ) &
  echo "Started URL blocklist refresh loop (interval: ${URL_BLOCKLIST_REFRESH_INTERVAL}s)"
fi

# Start Rspamd with injected password hashes and logging level
exec rspamd -f \
  --var=CONTROLLER_PASSWORD_HASH="${CONTROLLER_PASSWORD_HASH}" \
  --var=CONTROLLER_ENABLE_PASSWORD_HASH="${CONTROLLER_ENABLE_PASSWORD_HASH}" \
  --var=RSPAMD_LOGGING_LEVEL="${RSPAMD_LOGGING_LEVEL:-info}"
