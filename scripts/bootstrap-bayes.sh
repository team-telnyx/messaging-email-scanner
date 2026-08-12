#!/bin/bash
# bootstrap-bayes.sh — One-command Bayes classifier bootstrap
#
# Downloads all available free training sources, trains Rspamd's Bayes
# classifier, and saves pre/post snapshots for rollback.
#
# Training sources:
#   Spam  : SpamAssassin 2002+2003 corpus, OpenPhish URLs, URLhaus URLs
#   Ham   : SpamAssassin 2002+2003 corpus, Enron corporate email corpus
#
# Must run INSIDE the messaging-email-scanner container:
#   docker exec messaging-email-scanner-rspamd-1 /scripts/bootstrap-bayes.sh
#
# Requires: RSPAMD_CONTROLLER_ENABLE_PASSWORD env var
# Optional: RSPAMD_HOST (default 127.0.0.1), RSPAMD_PORT (default 11334)
# Optional: ENRON_SAMPLE_SIZE (default 10000 — number of Enron emails to sample)
# Optional: PHISH_URL_LIMIT (default 5000 — max phishing URLs to train)
# Optional: URLHAUS_LIMIT (default 10000 — max URLhaus URLs to train)
#
# Usage:
#   docker exec rspamd-container /scripts/bootstrap-bayes.sh [password]
#
# Environment overrides:
#   ENRON_SAMPLE_SIZE=50000 PHISH_URL_LIMIT=10000 docker exec rspamd-container /scripts/bootstrap-bayes.sh

set -euo pipefail

RSPAMD_HOST="${RSPAMD_HOST:-127.0.0.1}"
RSPAMD_PORT="${RSPAMD_PORT:-11334}"
RSPAMD_PWD="${RSPAMD_CONTROLLER_ENABLE_PASSWORD:-${1:-}}"
CORPUS_DIR="$(mktemp -d /tmp/bayes-corpus.XXXXXX)"
SNAPSHOT_DIR="${BAYES_SNAPSHOT_DIR:-/tmp/bayes-snapshots}"
ENRON_SAMPLE_SIZE="${ENRON_SAMPLE_SIZE:-10000}"
PHISH_URL_LIMIT="${PHISH_URL_LIMIT:-5000}"
URLHAUS_LIMIT="${URLHAUS_LIMIT:-10000}"

# Colors (if terminal supports it)
if [ -t 1 ]; then
  GREEN='\033[0;32m'
  YELLOW='\033[1;33m'
  CYAN='\033[0;36m'
  RED='\033[0;31m'
  NC='\033[0m'
else
  GREEN=''
  YELLOW=''
  CYAN=''
  RED=''
  NC=''
fi

if [ -z "$RSPAMD_PWD" ]; then
  echo -e "${RED}ERROR: RSPAMD_CONTROLLER_ENABLE_PASSWORD or password argument required${NC}" >&2
  exit 1
fi

cleanup() {
  rm -rf "$CORPUS_DIR"
}
trap cleanup EXIT

log()  { echo -e "${CYAN}[$(date -u +%H:%M:%S)]${NC} $*"; }
ok()   { echo -e "${GREEN}[$(date -u +%H:%M:%S)] ✓${NC} $*"; }
warn() { echo -e "${YELLOW}[$(date -u +%H:%M:%S)] !${NC} $*"; }
err()  { echo -e "${RED}[$(date -u +%H:%M:%S)] ✗${NC} $*" >&2; }

echo ""
echo "============================================================"
echo "  Bayes Classifier Bootstrap"
echo "  Sources: SpamAssassin + Enron + OpenPhish + URLhaus"
echo "============================================================"
echo ""

# ============================================================================
# Step 0: Pre-seed snapshot
# ============================================================================
log "Step 0: Pre-seed snapshot"
mkdir -p "$SNAPSHOT_DIR"
if command -v redis-cli >/dev/null 2>&1; then
  REDIS_URL="${REDIS_URL:-redis://redis:6379}"
  PRE_SEED="$SNAPSHOT_DIR/bayes-pre-bootstrap-$(date -u +%Y%m%dT%H%M%SZ).rdb"
  redis-cli -u "$REDIS_URL" SAVE 2>/dev/null || true
  cp "${REDIS_DATA_DIR:-/data}/dump.rdb" "$PRE_SEED" 2>/dev/null || \
    warn "Could not copy RDB (may not have Redis data dir access)"
  ok "Pre-seed snapshot: $PRE_SEED"
else
  warn "redis-cli not available — skipping pre-seed snapshot"
fi

# Get baseline
BEFORE=$(rspamc -h "$RSPAMD_HOST:$RSPAMD_PORT" -P "$RSPAMD_PWD" stat 2>/dev/null \
  | grep -oP 'Messages learned: \K\d+' || echo "0")
log "Baseline: $BEFORE messages learned"

# Counters
SPAM_TRAINED=0
HAM_TRAINED=0
PHISH_TRAINED=0
URLHAUS_TRAINED=0
ENRON_TRAINED=0

# ============================================================================
# Step 1: Download SpamAssassin 2002 corpus
# ============================================================================
log "Step 1: Download SpamAssassin 2002 corpus"

declare -A SA_2002=(
  ["sa2002_spam"]="https://spamassassin.apache.org/old/publiccorpus/20021010_spam.tar.bz2"
  ["sa2002_easy_ham"]="https://spamassassin.apache.org/old/publiccorpus/20021010_easy_ham.tar.bz2"
  ["sa2002_hard_ham"]="https://spamassassin.apache.org/old/publiccorpus/20021010_hard_ham.tar.bz2"
)

for name in "${!SA_2002[@]}"; do
  url="${SA_2002[$name]}"
  archive="$CORPUS_DIR/${name}.tar.bz2"
  if curl -sSf -o "$archive" "$url" 2>/dev/null; then
    tar xjf "$archive" -C "$CORPUS_DIR" 2>/dev/null
    ok "Downloaded $name"
  else
    warn "Skip $name (unavailable)"
  fi
done

# ============================================================================
# Step 2: Download SpamAssassin 2003 corpus
# ============================================================================
log "Step 2: Download SpamAssassin 2003 corpus"

declare -A SA_2003=(
  ["sa2003_spam"]="https://spamassassin.apache.org/old/publiccorpus/20030228_spam.tar.bz2"
  ["sa2003_spam_2"]="https://spamassassin.apache.org/old/publiccorpus/20050311_spam_2.tar.bz2"
  ["sa2003_easy_ham"]="https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2"
  ["sa2003_easy_ham_2"]="https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham_2.tar.bz2"
  ["sa2003_hard_ham"]="https://spamassassin.apache.org/old/publiccorpus/20030228_hard_ham.tar.bz2"
)

for name in "${!SA_2003[@]}"; do
  url="${SA_2003[$name]}"
  archive="$CORPUS_DIR/${name}.tar.bz2"
  if curl -sSf -o "$archive" "$url" 2>/dev/null; then
    tar xjf "$archive" -C "$CORPUS_DIR" 2>/dev/null
    ok "Downloaded $name"
  else
    warn "Skip $name (unavailable)"
  fi
done

# ============================================================================
# Step 3: Download Enron corporate email corpus (ham goldmine)
# ============================================================================
log "Step 3: Download Enron corpus (legitimate corporate email — ham)"

ENRON_ARCHIVE="$CORPUS_DIR/enron_mail.tar.gz"
if curl -sSf -o "$ENRON_ARCHIVE" "https://www.cs.cmu.edu/~enron/enron_mail_20150507.tar.gz" 2>/dev/null; then
  tar xzf "$ENRON_ARCHIVE" -C "$CORPUS_DIR" 2>/dev/null
  ok "Downloaded Enron corpus (443MB)"

  # Count available Enron emails
  ENRON_DIR=$(find "$CORPUS_DIR" -maxdepth 1 -type d -name "maildir" -o -name "enron_mail" | head -1)
  if [ -z "$ENRON_DIR" ]; then
    # The tar extracts to a directory — find it
    ENRON_DIR=$(find "$CORPUS_DIR" -maxdepth 2 -type d -name "_sent" -printf '%h\n' 2>/dev/null | head -1)
    [ -n "$ENRON_DIR" ] && ENRON_DIR=$(dirname "$ENRON_DIR")
  fi

  if [ -n "$ENRON_DIR" ]; then
    ENRON_TOTAL=$(find "$ENRON_DIR" -type f | wc -l)
    ok "Enron emails available: $ENRON_TOTAL (sampling $ENRON_SAMPLE_SIZE)"
  else
    warn "Enron corpus extracted but could not locate mail directory"
    ENRON_TOTAL=0
  fi
else
  warn "Skip Enron corpus (download failed)"
  ENRON_TOTAL=0
fi

# ============================================================================
# Step 4: Download phishing URLs (OpenPhish + URLhaus)
# ============================================================================
log "Step 4: Download phishing/malware URL feeds"

# OpenPhish — free phishing URL feed
OPENPHISH_FILE="$CORPUS_DIR/openphish_urls.txt"
if curl -sSf -L -o "$OPENPHISH_FILE" "https://openphish.com/feed.txt" 2>/dev/null; then
  OPENPHISH_COUNT=$(wc -l < "$OPENPHISH_FILE")
  ok "OpenPhish URLs: $OPENPHISH_COUNT"
else
  warn "Skip OpenPhish (unavailable)"
  OPENPHISH_COUNT=0
fi

# URLhaus — malware URL feed from abuse.ch
URLHAUS_FILE="$CORPUS_DIR/urlhaus_urls.txt"
if curl -sSf -L -o "$CORPUS_DIR/urlhaus.csv" "https://urlhaus.abuse.ch/downloads/csv_recent/" 2>/dev/null; then
  # Extract URLs (field 3, between quotes)
  grep -v '^#' "$CORPUS_DIR/urlhaus.csv" | awk -F'"' '{print $6}' > "$URLHAUS_FILE"
  URLHAUS_COUNT=$(wc -l < "$URLHAUS_FILE")
  ok "URLhaus URLs: $URLHAUS_COUNT"
else
  warn "Skip URLhaus (unavailable)"
  URLHAUS_COUNT=0
fi

# ============================================================================
# Step 5: Train spam from SpamAssassin corpus
# ============================================================================
log "Step 5: Training spam from SpamAssassin corpus"

for dir in \
  "$CORPUS_DIR/spam" "$CORPUS_DIR/spam_2" \
  "$CORPUS_DIR/sa2002_spam" "$CORPUS_DIR/sa2003_spam" "$CORPUS_DIR/sa2003_spam_2"; do
  if [ -d "$dir" ]; then
    for f in "$dir"/*; do
      [ -f "$f" ] || continue
      case "$(basename "$f")" in cmds|.*|README*) continue ;; esac
      rspamc -h "$RSPAMD_HOST:$RSPAMD_PORT" -P "$RSPAMD_PWD" learn_spam "$f" >/dev/null 2>&1 || true
      SPAM_TRAINED=$((SPAM_TRAINED + 1))
    done
  fi
done
ok "SpamAssassin spam processed: $SPAM_TRAINED"

# ============================================================================
# Step 6: Train ham from SpamAssassin corpus
# ============================================================================
log "Step 6: Training ham from SpamAssassin corpus"

for dir in \
  "$CORPUS_DIR/easy_ham" "$CORPUS_DIR/easy_ham_2" "$CORPUS_DIR/hard_ham" \
  "$CORPUS_DIR/sa2002_easy_ham" "$CORPUS_DIR/sa2002_hard_ham" \
  "$CORPUS_DIR/sa2003_easy_ham" "$CORPUS_DIR/sa2003_easy_ham_2" "$CORPUS_DIR/sa2003_hard_ham"; do
  if [ -d "$dir" ]; then
    for f in "$dir"/*; do
      [ -f "$f" ] || continue
      case "$(basename "$f")" in cmds|.*|README*) continue ;; esac
      rspamc -h "$RSPAMD_HOST:$RSPAMD_PORT" -P "$RSPAMD_PWD" learn_ham "$f" >/dev/null 2>&1 || true
      HAM_TRAINED=$((HAM_TRAINED + 1))
    done
  fi
done
ok "SpamAssassin ham processed: $HAM_TRAINED"

# ============================================================================
# Step 7: Train ham from Enron corpus (sampled)
# ============================================================================
log "Step 7: Training ham from Enron corpus (sampling $ENRON_SAMPLE_SIZE)"

if [ "$ENRON_TOTAL" -gt 0 ] && [ -n "$ENRON_DIR" ]; then
  # Sample a random subset to avoid overwhelming the classifier
  find "$ENRON_DIR" -type f | shuf | head -"$ENRON_SAMPLE_SIZE" | while IFS= read -r f; do
    # Skip non-email files
    [ -f "$f" ] || continue
    case "$(basename "$f")" in .*) continue ;; esac

    # Enron emails are individual files — train as ham
    rspamc -h "$RSPAMD_HOST:$RSPAMD_PORT" -P "$RSPAMD_PWD" learn_ham "$f" >/dev/null 2>&1 || true
    ENRON_TRAINED=$((ENRON_TRAINED + 1))

    if [ $((ENRON_TRAINED % 1000)) -eq 0 ] && [ $ENRON_TRAINED -gt 0 ]; then
      log "  Enron progress: $ENRON_TRAINED / $ENRON_SAMPLE_SIZE"
    fi
  done
  ok "Enron ham trained: $ENRON_TRAINED"
else
  warn "Skip Enron training (no corpus available)"
fi

# ============================================================================
# Step 8: Train phishing URLs as spam
# ============================================================================
log "Step 8: Training phishing/malware URLs as spam"

# Combine and limit phishing URLs
COMBINED_URLS="$CORPUS_DIR/combined_urls.txt"
if [ "$OPENPHISH_COUNT" -gt 0 ]; then
  head -"$PHISH_URL_LIMIT" "$OPENPHISH_FILE" >> "$COMBINED_URLS" 2>/dev/null || true
fi
if [ "$URLHAUS_COUNT" -gt 0 ]; then
  head -"$URLHAUS_LIMIT" "$URLHAUS_FILE" >> "$COMBINED_URLS" 2>/dev/null || true
fi

TOTAL_URLS=$(wc -l < "$COMBINED_URLS" 2>/dev/null || echo "0")
log "Training $TOTAL_URLS phishing/malware URLs as spam..."

if [ "$TOTAL_URLS" -gt 0 ]; then
  while IFS= read -r url; do
    [ -z "$url" ] && continue

    # Create a realistic phishing email with enough tokens for Bayes
    # (min_tokens=10 in the autolearn config requires a body with substance)
    printf "Subject: Urgent - Account Verification Required\r\nFrom: security@notice.com\r\nTo: user@example.com\r\nDate: Mon, 01 Jan 2024 00:00:00 +0000\r\n\r\nDear Customer,\r\n\r\nWe have detected unusual activity on your account and need you to verify your identity immediately. Your account security is our top priority and we must ensure that only authorized users have access.\r\n\r\nPlease click the link below to complete the verification process:\r\n\r\n%s\r\n\r\nIf you do not complete verification within 24 hours, your account will be temporarily suspended to protect your information. This is an automated security check and cannot be opted out.\r\n\r\nThank you for your prompt attention to this matter.\r\nSecurity Team\r\n" "$url" > "$CORPUS_DIR/training_email.eml"

    if rspamc -h "$RSPAMD_HOST:$RSPAMD_PORT" -P "$RSPAMD_PWD" learn_spam "$CORPUS_DIR/training_email.eml" >/dev/null 2>&1; then
      PHISH_TRAINED=$((PHISH_TRAINED + 1))
    fi

    if [ $((PHISH_TRAINED % 1000)) -eq 0 ] && [ $PHISH_TRAINED -gt 0 ]; then
      log "  URL progress: $PHISH_TRAINED / $TOTAL_URLS"
    fi
  done < "$COMBINED_URLS"
  ok "Phishing/malware URLs trained: $PHISH_TRAINED"
else
  warn "Skip URL training (no URLs available)"
fi

# ============================================================================
# Step 9: Verify results
# ============================================================================
log "Step 9: Verifying training results"

AFTER=$(rspamc -h "$RSPAMD_HOST:$RSPAMD_PORT" -P "$RSPAMD_PWD" stat 2>/dev/null \
  | grep -oP 'Messages learned: \K\d+' || echo "0")
DELTA=$((AFTER - BEFORE))

echo ""
echo "============================================================"
echo "  Training Results"
echo "============================================================"
echo "  Before:            $BEFORE learned"
echo "  After:             $AFTER learned"
echo "  New learnings:     $DELTA"
echo ""
echo "  SpamAssassin spam: $SPAM_TRAINED"
echo "  SpamAssassin ham:  $HAM_TRAINED"
echo "  Enron ham:         $ENRON_TRAINED"
echo "  Phishing URLs:     $PHISH_TRAINED"
echo "============================================================"
echo ""
rspamc -h "$RSPAMD_HOST:$RSPAMD_PORT" -P "$RSPAMD_PWD" stat 2>/dev/null | grep -E "BAYES_SPAM|BAYES_HAM|Total learns"

# Fail if too few new learnings
if [ "$DELTA" -lt 100 ]; then
  err "Expected at least 100 new learnings, got $DELTA"
  exit 1
fi

# ============================================================================
# Step 10: Post-seed snapshot
# ============================================================================
log "Step 10: Post-seed snapshot"

if command -v redis-cli >/dev/null 2>&1; then
  POST_SEED="$SNAPSHOT_DIR/bayes-post-bootstrap-$(date -u +%Y%m%dT%H%M%SZ).rdb"
  redis-cli -u "$REDIS_URL" SAVE 2>/dev/null || true
  cp "${REDIS_DATA_DIR:-/data}/dump.rdb" "$POST_SEED" 2>/dev/null || \
    warn "Could not copy RDB"
  ok "Post-seed snapshot: $POST_SEED"

  # Retention: keep last 10 snapshots
  ls -t "$SNAPSHOT_DIR"/bayes-*.rdb 2>/dev/null | tail -n +11 | xargs rm -f 2>/dev/null || true

  echo ""
  echo "To rollback: bash /scripts/bayes_snapshot.sh --restore $PRE_SEED"
fi

echo ""
echo "============================================================"
ok "Bayes bootstrap complete!"
echo "============================================================"
echo ""
echo "Next steps:"
echo "  1. Review stats:    rspamc -h $RSPAMD_HOST:$RSPAMD_PORT -P *** stat"
echo "  2. Health check:    bash /scripts/bayes_health_check.sh"
echo "  3. Monitor shadow:  query scan_decisions table for production data"
echo "  4. Launch gate:    run MSG-1791 evaluation before active mode"
echo ""
