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
MAX_CLASS_DISTRIBUTION_DRIFT="${MAX_CLASS_DISTRIBUTION_DRIFT:-0.10}"
MAX_SINGLE_ACCOUNT_SHARE="${MAX_SINGLE_ACCOUNT_SHARE:-0.20}"
BAYES_STATE_FILE="${BAYES_STATE_FILE:-/tmp/rspamd-bayes-health.state}"
BAYES_DISTRIBUTION_BASELINE_FILE="${BAYES_DISTRIBUTION_BASELINE_FILE:-${BAYES_STATE_FILE}.distribution-baseline}"
BAYES_AUDIT_QUERY_CMD="${BAYES_AUDIT_QUERY_CMD:-}"

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
for fraction_setting in MAX_CLASS_DISTRIBUTION_DRIFT MAX_SINGLE_ACCOUNT_SHARE; do
  fraction_value=${!fraction_setting}
  if [[ ! "$fraction_value" =~ ^[0-9]+([.][0-9]+)?$ ]] ||
    ! awk -v value="$fraction_value" 'BEGIN { exit !(value >= 0 && value <= 1) }'; then
    printf 'ERROR: %s must be a number between 0 and 1\n' "$fraction_setting" >&2
    exit 2
  fi
done

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

# Detect classifier drift against a fixed baseline rather than merely checking
# the current ham/spam ratio. The first non-empty sample establishes the
# baseline; delete or deliberately replace the file only after recalibration.
TOTAL_COUNT=$((SPAM_COUNT + HAM_COUNT))
if ((TOTAL_COUNT == 0)); then
  printf 'Classifier distribution: n/a (classifier has not learned any messages)\n'
else
  current_spam_share=$(awk -v spam="$SPAM_COUNT" -v total="$TOTAL_COUNT" 'BEGIN { printf "%.6f", spam / total }')
  current_ham_share=$(awk -v ham="$HAM_COUNT" -v total="$TOTAL_COUNT" 'BEGIN { printf "%.6f", ham / total }')
  printf 'Classifier distribution: BAYES_SPAM=%s BAYES_HAM=%s\n' "$current_spam_share" "$current_ham_share"

  if [[ -r "$BAYES_DISTRIBUTION_BASELINE_FILE" ]]; then
    baseline_spam_share=
    baseline_ham_share=
    baseline_extra=
    IFS=' ' read -r baseline_spam_share baseline_ham_share baseline_extra <"$BAYES_DISTRIBUTION_BASELINE_FILE" || true
    if [[ ! "$baseline_spam_share" =~ ^[0-9]+([.][0-9]+)?$ ||
      ! "$baseline_ham_share" =~ ^[0-9]+([.][0-9]+)?$ || -n "$baseline_extra" ]] ||
      ! awk -v spam="$baseline_spam_share" -v ham="$baseline_ham_share" \
        'BEGIN { exit !(spam >= 0 && spam <= 1 && ham >= 0 && ham <= 1) }'; then
      printf 'ERROR: malformed classifier distribution baseline: %s\n' "$BAYES_DISTRIBUTION_BASELINE_FILE" >&2
      exit 2
    fi

    distribution_drift=$(awk -v current="$current_spam_share" -v baseline="$baseline_spam_share" \
      'BEGIN { difference = current - baseline; if (difference < 0) difference = -difference; printf "%.6f", difference }')
    printf 'Classifier distribution drift: %s (baseline BAYES_SPAM=%s)\n' "$distribution_drift" "$baseline_spam_share"
    if awk -v drift="$distribution_drift" -v maximum="$MAX_CLASS_DISTRIBUTION_DRIFT" \
      'BEGIN { exit !(drift > maximum) }'; then
      printf 'ALERT: classifier distribution drift %s exceeds %s\n' \
        "$distribution_drift" "$MAX_CLASS_DISTRIBUTION_DRIFT" >&2
      status=1
    fi
  else
    baseline_dir=${BAYES_DISTRIBUTION_BASELINE_FILE%/*}
    [[ "$baseline_dir" != "$BAYES_DISTRIBUTION_BASELINE_FILE" ]] || baseline_dir=.
    if ! mkdir -p "$baseline_dir"; then
      printf 'ERROR: could not create baseline directory %s\n' "$baseline_dir" >&2
      exit 2
    fi
    baseline_tmp=$(mktemp "$baseline_dir/.bayes-distribution.XXXXXX")
    trap 'rm -f "$baseline_tmp"' EXIT
    printf '%s %s\n' "$current_spam_share" "$current_ham_share" >"$baseline_tmp"
    chmod 600 "$baseline_tmp"
    mv "$baseline_tmp" "$BAYES_DISTRIBUTION_BASELINE_FILE"
    trap - EXIT
    printf 'Classifier distribution baseline established: %s\n' "$BAYES_DISTRIBUTION_BASELINE_FILE"
  fi
fi

# Account identity lives in MSG-1779's appeals audit log, outside Rspamd. When
# the log backend is available, BAYES_AUDIT_QUERY_CMD must emit one
# "<account_id> <learn_count>" row per account for the monitoring window.
if [[ -n "$BAYES_AUDIT_QUERY_CMD" ]]; then
  printf '=== Per-account Learn Counts ===\n'
  if ! AUDIT_OUTPUT=$(sh -c "$BAYES_AUDIT_QUERY_CMD" 2>&1); then
    printf 'ERROR: Bayes audit-log query failed: %s\n' "$AUDIT_OUTPUT" >&2
    exit 2
  fi
  if ! audit_summary=$(awk '
    NF == 0 || $1 ~ /^#/ { next }
    NF != 2 || $1 ~ /[|]/ || $2 !~ /^[0-9]+$/ { invalid = 1; next }
    { learns[$1] += $2; total += $2 }
    END {
      if (invalid) exit 1
      max_account = "-"
      max_learns = 0
      for (account in learns) {
        if (learns[account] > max_learns) {
          max_account = account
          max_learns = learns[account]
        }
      }
      printf "%d %s %d\n", total, max_account, max_learns
    }
  ' <<<"$AUDIT_OUTPUT"); then
    printf 'ERROR: audit query output must contain "<account_id> <learn_count>" rows\n' >&2
    exit 2
  fi

  audit_total=
  top_account=
  top_account_learns=
  audit_extra=
  IFS=' ' read -r audit_total top_account top_account_learns audit_extra <<<"$audit_summary"
  if [[ ! "$audit_total" =~ ^[0-9]+$ || ! "$top_account_learns" =~ ^[0-9]+$ || -n "$audit_extra" ]]; then
    printf 'ERROR: could not parse per-account learn summary\n' >&2
    exit 2
  fi
  if ((audit_total == 0)); then
    printf 'Per-account learn share: n/a (no audited learns in query window)\n'
  else
    top_account_share=$(awk -v account="$top_account_learns" -v total="$audit_total" \
      'BEGIN { printf "%.4f", account / total }')
    printf 'Top account: %s (%s/%s learns, share=%s)\n' \
      "$top_account" "$top_account_learns" "$audit_total" "$top_account_share"
    if awk -v share="$top_account_share" -v maximum="$MAX_SINGLE_ACCOUNT_SHARE" \
      'BEGIN { exit !(share > maximum) }'; then
      printf 'ALERT: account %s contributes %s of learns, exceeding %s\n' \
        "$top_account" "$top_account_share" "$MAX_SINGLE_ACCOUNT_SHARE" >&2
      status=1
    fi
  fi
else
  printf 'NOTICE: per-account learn counts unavailable; full per-tenant monitoring requires MSG-1779 audit-log analysis (future enhancement)\n'
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
