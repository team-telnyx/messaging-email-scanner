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

# Start Rspamd with injected password hashes and logging level
exec rspamd -f \
  --var=CONTROLLER_PASSWORD_HASH="${CONTROLLER_PASSWORD_HASH}" \
  --var=CONTROLLER_ENABLE_PASSWORD_HASH="${CONTROLLER_ENABLE_PASSWORD_HASH}" \
  --var=RSPAMD_LOGGING_LEVEL="${RSPAMD_LOGGING_LEVEL:-info}"
