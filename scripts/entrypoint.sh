#!/bin/sh
# Entrypoint for messaging-email-scanner
# Generates hashed controller passwords from environment variables
# and starts Rspamd with the injected values

set -eu

# Generate password hashes from plaintext env vars
CONTROLLER_PASSWORD_HASH=""
CONTROLLER_ENABLE_PASSWORD_HASH=""

if [ -n "${RSPAMD_CONTROLLER_PASSWORD:-}" ]; then
  CONTROLLER_PASSWORD_HASH=$(rspamadm pw -e "${RSPAMD_CONTROLLER_PASSWORD}")
fi

if [ -n "${RSPAMD_CONTROLLER_ENABLE_PASSWORD:-}" ]; then
  CONTROLLER_ENABLE_PASSWORD_HASH=$(rspamadm pw -e "${RSPAMD_CONTROLLER_ENABLE_PASSWORD}")
fi

# Start Rspamd with injected password hashes
exec rspamd -f \
  --var=CONTROLLER_PASSWORD_HASH="${CONTROLLER_PASSWORD_HASH}" \
  --var=CONTROLLER_ENABLE_PASSWORD_HASH="${CONTROLLER_ENABLE_PASSWORD_HASH}" \
  --var=RSPAMD_LOGGING_LEVEL="${RSPAMD_LOGGING_LEVEL:-info}"
