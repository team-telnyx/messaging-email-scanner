#!/bin/bash
set -euo pipefail

# MSG-1795: Bayes classifier snapshot and rollback.
# Bayes state is stored in Redis. Run this script where redis-cli is available
# and the Redis data directory is mounted for rollback.

SNAPSHOT_DIR="${BAYES_SNAPSHOT_DIR:-/tmp/bayes-snapshots}"
REDIS_URL="${REDIS_URL:-redis://redis:6379}"
REDIS_DATA_DIR="${REDIS_DATA_DIR:-/data}"
REDIS_CLI_BIN="${REDIS_CLI_BIN:-redis-cli}"
TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)

usage() {
  printf 'Usage: %s [--restore <snapshot.rdb>]\n' "${0##*/}" >&2
}

restore_snapshot() {
  local snapshot_file=$1

  if [[ ! -r "$snapshot_file" ]]; then
    printf 'ERROR: snapshot is not readable: %s\n' "$snapshot_file" >&2
    exit 2
  fi
  if [[ ! -d "$REDIS_DATA_DIR" ]]; then
    printf 'ERROR: Redis data directory is not accessible: %s\n' "$REDIS_DATA_DIR" >&2
    exit 2
  fi

  echo "Restoring Bayes from $snapshot_file..."
  # Disable AOF before flushing to prevent the FLUSHDB from being persisted
  "$REDIS_CLI_BIN" -u "$REDIS_URL" CONFIG SET appendonly no
  "$REDIS_CLI_BIN" -u "$REDIS_URL" FLUSHDB
  "$REDIS_CLI_BIN" -u "$REDIS_URL" SHUTDOWN NOSAVE
  
  # Remove stale AOF files and directory so RDB takes precedence on restart
  rm -f "${REDIS_DATA_DIR}/appendonly.aof" "${REDIS_DATA_DIR}/appendonly.aof."* 2>/dev/null || true
  rm -rf "${REDIS_DATA_DIR}/appendonlydir" 2>/dev/null || true
  
  # Copy the RDB snapshot
  cp "$snapshot_file" "${REDIS_DATA_DIR:-/data}/dump.rdb"
  echo "Restored. Restart Redis with --appendonly no to load the RDB."
  echo "After restart, re-enable AOF: redis-cli CONFIG SET appendonly yes"
  echo "This ensures Redis loads the RDB first, then creates a fresh AOF from it."
}

create_snapshot() {
  local snapshot_file="$SNAPSHOT_DIR/bayes-$TIMESTAMP.rdb"

  mkdir -p "$SNAPSHOT_DIR"

  # Force Redis to persist the current Bayes state before copying its RDB.
  "$REDIS_CLI_BIN" -u "$REDIS_URL" SAVE

  # Prefer the local data-directory copy requested by the operations runbook.
  # When the Redis filesystem is not mounted, redis-cli --rdb can stream the
  # same state from a remote Redis instance into the snapshot directory.
  if ! cp "$REDIS_DATA_DIR/dump.rdb" "$snapshot_file" 2>/dev/null; then
    printf 'Note: Redis RDB copy requires access to Redis data directory; streaming snapshot instead\n' >&2
    "$REDIS_CLI_BIN" -u "$REDIS_URL" --rdb "$snapshot_file"
  fi
  if [[ ! -s "$snapshot_file" ]]; then
    printf 'ERROR: Redis snapshot was not created: %s\n' "$snapshot_file" >&2
    exit 2
  fi

  printf 'Bayes snapshot saved: %s\n' "$snapshot_file"

  # Retention: keep last 10 snapshots.
  ls -t "$SNAPSHOT_DIR"/bayes-*.rdb 2>/dev/null | tail -n +11 | xargs rm -f 2>/dev/null || true
}

case "${1:-}" in
  "")
    create_snapshot
    ;;
  --restore)
    if [[ $# -ne 2 ]]; then
      usage
      exit 2
    fi
    restore_snapshot "$2"
    ;;
  *)
    usage
    exit 2
    ;;
esac
