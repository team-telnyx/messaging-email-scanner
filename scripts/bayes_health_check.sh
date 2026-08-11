#!/bin/bash
set -euo pipefail

# MSG-1795: Bayes classifier poisoning monitor.
# Returns 0 when healthy, 1 when a poisoning threshold is exceeded, and 2 when
# statistics cannot be collected or parsed.

RSPAMC_BIN="${RSPAMC_BIN:-rspamc}"
RSPAMD_URL="${RSPAMD_URL:-rspamd:11334}"
RSPAMD_PASSWORD="${RSPAMD_PASSWORD:-${RSPAMD_CONTROLLER_PASSWORD:-}}"
MAX_HAM_SPAM_RATIO="${MAX_HAM_SPAM_RATIO:-0.5}"
MAX_LEARNS_PER_HOUR="${MAX_LEARNS_PER_HOUR:-100}"
BAYES_STATE_FILE="${BAYES_STATE_FILE:-/tmp/rspamd-bayes-health.state}"

case "$RSPAMD_URL" in
  http://*) RSPAMD_ENDPOINT=${RSPAMD_URL#http://} ;;
  https://*)
    printf 'ERROR: rspamc does not accept an https:// endpoint: %s\n' "$RSPAMD_URL" >&2
    exit 2
    ;;
  *) RSPAMD_ENDPOINT=$RSPAMD_URL ;;
esac
RSPAMD_ENDPOINT=${RSPAMD_ENDPOINT%/}

if [[ -z "$RSPAMD_ENDPOINT" || "$RSPAMD_ENDPOINT" == */* || "$RSPAMD_ENDPOINT" =~ [[:space:]] ]]; then
  printf 'ERROR: RSPAMD_URL must be a host or host:port, optionally prefixed with http://\n' >&2
  exit 2
fi
if [[ -z "$RSPAMD_PASSWORD" ]]; then
  printf 'ERROR: RSPAMD_PASSWORD or RSPAMD_CONTROLLER_PASSWORD is required\n' >&2
  exit 2
fi
if [[ ! "$MAX_HAM_SPAM_RATIO" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
  printf 'ERROR: MAX_HAM_SPAM_RATIO must be a non-negative number\n' >&2
  exit 2
fi
if [[ ! "$MAX_LEARNS_PER_HOUR" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
  printf 'ERROR: MAX_LEARNS_PER_HOUR must be a non-negative number\n' >&2
  exit 2
fi

printf '=== Bayes Statistics ===\n'
if ! STAT_OUTPUT=$("$RSPAMC_BIN" -h "$RSPAMD_ENDPOINT" -P "$RSPAMD_PASSWORD" stat 2>&1); then
  printf 'ERROR: rspamc stat failed: %s\n' "$STAT_OUTPUT" >&2
  exit 2
fi
printf '%s\n' "$STAT_OUTPUT"

extract_learned_count() {
  local symbol=$1
  awk -v expected="$symbol" '
    $1 == "Statfile:" && $2 == expected {
      for (i = 1; i <= NF; i++) {
        if ($i == "learned:") {
          value = $(i + 1)
          gsub(/[^0-9]/, "", value)
          if (value != "") {
            print value
            found = 1
            exit
          }
        }
      }
    }
    END { if (!found) exit 1 }
  ' <<<"$STAT_OUTPUT"
}

if ! SPAM_COUNT=$(extract_learned_count BAYES_SPAM); then
  printf 'ERROR: could not parse BAYES_SPAM learned count\n' >&2
  exit 2
fi
if ! HAM_COUNT=$(extract_learned_count BAYES_HAM); then
  printf 'ERROR: could not parse BAYES_HAM learned count\n' >&2
  exit 2
fi
if [[ ! "$SPAM_COUNT" =~ ^[0-9]+$ || ! "$HAM_COUNT" =~ ^[0-9]+$ ]]; then
  printf 'ERROR: Bayes learned counts must be non-negative integers\n' >&2
  exit 2
fi

printf 'Ham: %s, Spam: %s\n' "$HAM_COUNT" "$SPAM_COUNT"
status=0
if ((SPAM_COUNT == 0)); then
  if ((HAM_COUNT == 0)); then
    printf 'Ham/spam ratio: n/a (classifier has not learned any messages)\n'
  else
    printf 'Ham/spam ratio: infinite\n'
    printf 'ALERT: ham learns exist while spam learns are zero\n' >&2
    status=1
  fi
else
  ratio=$(awk -v ham="$HAM_COUNT" -v spam="$SPAM_COUNT" 'BEGIN { printf "%.4f", ham / spam }')
  printf 'Ham/spam ratio: %s\n' "$ratio"
  if awk -v ratio="$ratio" -v maximum="$MAX_HAM_SPAM_RATIO" 'BEGIN { exit !(ratio > maximum) }'; then
    printf 'ALERT: ham/spam ratio %s exceeds %s\n' "$ratio" "$MAX_HAM_SPAM_RATIO" >&2
    status=1
  fi
fi

# Rspamd exposes cumulative counters rather than a recent-rate metric. Compare
# with the previous sample when state is available; the first run establishes
# the baseline. Persist spam and ham separately so counter resets are visible.
now=$(date +%s)
if [[ -r "$BAYES_STATE_FILE" ]]; then
  previous_epoch=
  previous_spam=
  previous_ham=
  extra=
  IFS=' ' read -r previous_epoch previous_spam previous_ham extra <"$BAYES_STATE_FILE" || true
  if [[ "$previous_epoch" =~ ^[0-9]+$ && "$previous_spam" =~ ^[0-9]+$ && "$previous_ham" =~ ^[0-9]+$ && -z "$extra" ]]; then
    elapsed=$((now - previous_epoch))
    previous_total=$((previous_spam + previous_ham))
    current_total=$((SPAM_COUNT + HAM_COUNT))
    if ((elapsed > 0 && current_total >= previous_total)); then
      learned_delta=$((current_total - previous_total))
      learn_rate=$(awk -v delta="$learned_delta" -v seconds="$elapsed" 'BEGIN { printf "%.2f", delta * 3600 / seconds }')
      printf 'Learn rate: %s/hour (%s learns in %s seconds)\n' "$learn_rate" "$learned_delta" "$elapsed"
      if awk -v rate="$learn_rate" -v maximum="$MAX_LEARNS_PER_HOUR" 'BEGIN { exit !(rate > maximum) }'; then
        printf 'ALERT: learn rate %s/hour exceeds %s/hour\n' "$learn_rate" "$MAX_LEARNS_PER_HOUR" >&2
        status=1
      fi
    elif ((elapsed > 0)); then
      printf 'NOTICE: learned counters decreased; classifier state may have reset\n'
    fi
  else
    printf 'NOTICE: ignoring malformed state file %s\n' "$BAYES_STATE_FILE" >&2
  fi
fi

state_dir=${BAYES_STATE_FILE%/*}
[[ "$state_dir" != "$BAYES_STATE_FILE" ]] || state_dir=.
if ! mkdir -p "$state_dir"; then
  printf 'ERROR: could not create state directory %s\n' "$state_dir" >&2
  exit 2
fi
state_tmp=$(mktemp "$state_dir/.bayes-health.XXXXXX")
trap 'rm -f "$state_tmp"' EXIT
printf '%s %s %s\n' "$now" "$SPAM_COUNT" "$HAM_COUNT" >"$state_tmp"
chmod 600 "$state_tmp"
mv "$state_tmp" "$BAYES_STATE_FILE"
trap - EXIT

if ((status == 0)); then
  printf '=== Health Check Complete: healthy ===\n'
else
  printf '=== Health Check Complete: alert ===\n'
fi
exit "$status"
