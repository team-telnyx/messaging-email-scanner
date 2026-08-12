#!/bin/bash
# Seed Bayes classifier with SpamAssassin public corpus + PhishTank URLs
# Downloads, extracts, and trains Rspamd's Bayes classifier via rspamc
# Also creates a pre-seed snapshot for rollback
#
# Must run INSIDE the messaging-email-scanner container (has rspamc + curl + tar + bzip2)
# Usage: docker exec messaging-email-scanner-rspamd-1 /scripts/seed-bayes.sh
#
# Requires: RSPAMD_CONTROLLER_ENABLE_PASSWORD env var (injected by entrypoint)

set -euo pipefail

RSPAMD_HOST="${RSPAMD_HOST:-127.0.0.1}"
RSPAMD_PORT="${RSPAMD_PORT:-11334}"
RSPAMD_PWD="${RSPAMD_CONTROLLER_ENABLE_PASSWORD:-${1:-}}"
CORPUS_DIR="$(mktemp -d /tmp/sa-corpus.XXXXXX)"
SNAPSHOT_DIR="${BAYES_SNAPSHOT_DIR:-/tmp/bayes-snapshots}"

if [ -z "$RSPAMD_PWD" ]; then
  echo "ERROR: RSPAMD_CONTROLLER_ENABLE_PASSWORD or password argument required" >&2
  exit 1
fi

cleanup() {
  rm -rf "$CORPUS_DIR"
}
trap cleanup EXIT

echo "=== Seeding Bayes classifier with SpamAssassin public corpus + PhishTank ==="
echo "Corpus dir: $CORPUS_DIR"

# --- Step 0: Pre-seed snapshot ---
echo ""
echo "--- Step 0: Pre-seed snapshot ---"
mkdir -p "$SNAPSHOT_DIR"
if command -v redis-cli >/dev/null 2>&1; then
  REDIS_URL="${REDIS_URL:-redis://redis:6379}"
  PRE_SEED_SNAPSHOT="$SNAPSHOT_DIR/bayes-pre-seed-$(date -u +%Y%m%dT%H%M%SZ).rdb"
  redis-cli -u "$REDIS_URL" SAVE 2>/dev/null || true
  cp "${REDIS_DATA_DIR:-/data}/dump.rdb" "$PRE_SEED_SNAPSHOT" 2>/dev/null || \
    echo "Note: Could not copy RDB (may not have Redis data dir access)"
  echo "Pre-seed snapshot: $PRE_SEED_SNAPSHOT"
else
  echo "Skip: redis-cli not available for pre-seed snapshot"
fi

# --- Step 1: Download SpamAssassin corpus ---
echo ""
echo "--- Step 1: Download SpamAssassin corpus ---"
declare -A ARCHIVES=(
  ["easy_ham"]="https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2"
  ["hard_ham"]="https://spamassassin.apache.org/old/publiccorpus/20030228_hard_ham.tar.bz2"
  ["easy_ham_2"]="https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham_2.tar.bz2"
  ["spam"]="https://spamassassin.apache.org/old/publiccorpus/20030228_spam.tar.bz2"
  ["spam_2"]="https://spamassassin.apache.org/old/publiccorpus/20050311_spam_2.tar.bz2"
)

for name in "${!ARCHIVES[@]}"; do
  url="${ARCHIVES[$name]}"
  archive="$CORPUS_DIR/$name.tar.bz2"
  echo "Downloading $name..."
  curl -sSf -o "$archive" "$url"
  tar xjf "$archive" -C "$CORPUS_DIR"
done

# --- Step 2: Download PhishTank phishing URLs ---
echo ""
echo "--- Step 2: Download PhishTank phishing URLs ---"
PHISHTANK_FILE="$CORPUS_DIR/phishtank_urls.txt"
# PhishTank research feed (public, free, updated hourly)
# Download the CSV of verified phishing URLs
if curl -sSf -o "$CORPUS_DIR/phishtank.csv" \
  "https://data.phishtank.com/data/online-valid.csv" 2>/dev/null; then
  # Extract URLs (first column, skip header)
  tail -n +2 "$CORPUS_DIR/phishtank.csv" | cut -d',' -f1 | tr -d '"' > "$PHISHTANK_FILE"
  PHISH_COUNT=$(wc -l < "$PHISHTANK_FILE" || echo "0")
  echo "PhishTank URLs: $PHISH_COUNT"
else
  echo "Skip: Could not download PhishTank data (may be temporarily unavailable)"
  PHISH_COUNT=0
fi

# --- Step 3: Get baseline ---
BEFORE=$(rspamc -h "$RSPAMD_HOST:$RSPAMD_PORT" -P "$RSPAMD_PWD" stat 2>/dev/null | grep -oP 'Messages learned: \K\d+' || echo "")
if ! [[ "$BEFORE" =~ ^[0-9]+$ ]]; then
  echo "ERROR: Could not parse baseline 'Messages learned' count" >&2
  exit 1
fi
echo ""
echo "Baseline messages learned: $BEFORE"

# --- Step 4: Train spam ---
echo ""
echo "--- Step 4: Training spam from SpamAssassin corpus ---"
SPAM_TRAINED=0
for dir in spam spam_2; do
  if [ -d "$CORPUS_DIR/$dir" ]; then
    for f in "$CORPUS_DIR/$dir"/*; do
      [ -f "$f" ] || continue
      case "$(basename "$f")" in
        cmds|.*|README*) continue ;;
      esac
      rspamc -h "$RSPAMD_HOST:$RSPAMD_PORT" -P "$RSPAMD_PWD" learn_spam "$f" >/dev/null 2>&1 || true
      SPAM_TRAINED=$((SPAM_TRAINED + 1))
    done
  fi
done
echo "Spam files processed: $SPAM_TRAINED"

# --- Step 5: Train ham ---
echo ""
echo "--- Step 5: Training ham from SpamAssassin corpus ---"
HAM_TRAINED=0
for dir in easy_ham hard_ham easy_ham_2; do
  if [ -d "$CORPUS_DIR/$dir" ]; then
    for f in "$CORPUS_DIR/$dir"/*; do
      [ -f "$f" ] || continue
      case "$(basename "$f")" in
        cmds|.*|README*) continue ;;
      esac
      rspamc -h "$RSPAMD_HOST:$RSPAMD_PORT" -P "$RSPAMD_PWD" learn_ham "$f" >/dev/null 2>&1 || true
      HAM_TRAINED=$((HAM_TRAINED + 1))
    done
  fi
done
echo "Ham files processed: $HAM_TRAINED"

# --- Step 6: Train phishing URLs ---
echo ""
echo "--- Step 6: Training phishing URLs as spam ---"
PHISH_TRAINED=0
if [ -f "$PHISHTANK_FILE" ] && [ "$PHISH_COUNT" -gt 0 ]; then
  # Create synthetic emails containing phishing URLs for Bayes training
  while IFS= read -r url; do
    [ -z "$url" ] && continue
    # Create a minimal email with the phishing URL
    printf "Subject: Click here\r\n\r\n%s\r\n" "$url" | \
      rspamc -h "$RSPAMD_HOST:$RSPAMD_PORT" -P "$RSPAMD_PWD" learn_spam - >/dev/null 2>&1 || true
    PHISH_TRAINED=$((PHISH_TRAINED + 1))
  done < "$PHISHTANK_FILE"
  echo "Phishing URLs trained: $PHISH_TRAINED"
else
  echo "Skip: No PhishTank URLs available"
fi

# --- Step 7: Verify results ---
AFTER=$(rspamc -h "$RSPAMD_HOST:$RSPAMD_PORT" -P "$RSPAMD_PWD" stat 2>/dev/null | grep -oP 'Messages learned: \K\d+' || echo "")
if ! [[ "$AFTER" =~ ^[0-9]+$ ]]; then
  echo "ERROR: Could not parse post-seed 'Messages learned' count" >&2
  exit 1
fi
DELTA=$((AFTER - BEFORE))

echo ""
echo "=== Training results ==="
echo "Before: $BEFORE learned"
echo "After: $AFTER learned"
echo "Delta: $DELTA new learnings"
echo "  SpamAssassin spam: $SPAM_TRAINED"
echo "  SpamAssassin ham:  $HAM_TRAINED"
echo "  PhishTank URLs:    $PHISH_TRAINED"
echo ""
rspamc -h "$RSPAMD_HOST:$RSPAMD_PORT" -P "$RSPAMD_PWD" stat 2>/dev/null | grep -E "BAYES_SPAM|BAYES_HAM"

# Fail if no new learnings
if [ "$DELTA" -lt 100 ]; then
  echo "ERROR: Expected at least 100 new learnings, got $DELTA" >&2
  exit 1
fi

# --- Step 8: Post-seed snapshot ---
echo ""
echo "--- Step 8: Post-seed snapshot ---"
POST_SEED_SNAPSHOT="$SNAPSHOT_DIR/bayes-post-seed-$(date -u +%Y%m%dT%H%M%SZ).rdb"
if command -v redis-cli >/dev/null 2>&1; then
  redis-cli -u "$REDIS_URL" SAVE 2>/dev/null || true
  cp "${REDIS_DATA_DIR:-/data}/dump.rdb" "$POST_SEED_SNAPSHOT" 2>/dev/null || \
    echo "Note: Could not copy RDB"
  echo "Post-seed snapshot: $POST_SEED_SNAPSHOT"
  echo ""
  echo "To rollback: bash /scripts/bayes_snapshot.sh --restore $PRE_SEED_SNAPSHOT"
fi

# Retention: keep last 10 snapshots
ls -t "$SNAPSHOT_DIR"/bayes-*.rdb 2>/dev/null | tail -n +11 | xargs rm -f 2>/dev/null || true

echo ""
echo "=== Bayes seeding complete ==="
echo ""
echo "Next steps:"
echo "  1. Review stats: rspamc -h $RSPAMD_HOST:$RSPAMD_PORT -P *** stat"
echo "  2. Run health check: bash /scripts/bayes_health_check.sh"
echo "  3. Monitor shadow mode data in scan_decisions table"
echo "  4. Before active mode: run launch gate evaluation (MSG-1791)"
