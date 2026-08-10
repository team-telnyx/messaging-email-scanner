#!/bin/bash
# Seed Bayes classifier with SpamAssassin public corpus
# Downloads, extracts, and trains Rspamd's Bayes classifier via rspamc
#
# Must run INSIDE the messaging-email-scanner container (has rspamc + curl + tar)
# Usage: docker exec messaging-email-scanner-rspamd-1 sh /scripts/seed-bayes.sh
#
# Requires: RSPAMD_CONTROLLER_ENABLE_PASSWORD env var (injected by entrypoint)

set -eu

RSPAMD_HOST="${RSPAMD_HOST:-127.0.0.1}"
RSPAMD_PORT="${RSPAMD_PORT:-11334}"
RSPAMD_PWD="${RSPAMD_CONTROLLER_ENABLE_PASSWORD:-${1:-}}"
CORPUS_DIR="$(mktemp -d /tmp/sa-corpus.XXXXXX)"

if [ -z "$RSPAMD_PWD" ]; then
  echo "ERROR: RSPAMD_CONTROLLER_ENABLE_PASSWORD or password argument required" >&2
  exit 1
fi

cleanup() {
  rm -rf "$CORPUS_DIR"
}
trap cleanup EXIT

echo "=== Seeding Bayes classifier with SpamAssassin public corpus ==="
echo "Corpus dir: $CORPUS_DIR"

# Download and verify archives
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

# Get baseline counts
BEFORE=$(rspamc -h "$RSPAMD_HOST:$RSPAMD_PORT" -P "$RSPAMD_PWD" stat 2>/dev/null | grep "learned" | grep -oP '\d+' || echo "0")
echo "Baseline messages learned: $BEFORE"

# Train spam — exclude cmds and other non-message artifacts
echo "Training spam..."
SPAM_TRAINED=0
for dir in spam spam_2; do
  if [ -d "$CORPUS_DIR/$dir" ]; then
    for f in "$CORPUS_DIR/$dir"/*; do
      # Skip non-email files (cmds, dotfiles)
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

# Train ham — exclude cmds, include easy_ham, hard_ham, easy_ham_2
echo "Training ham..."
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

# Verify delta
AFTER=$(rspamc -h "$RSPAMD_HOST:$RSPAMD_PORT" -P "$RSPAMD_PWD" stat 2>/dev/null | grep "learned" | grep -oP '\d+' || echo "0")
DELTA=$((AFTER - BEFORE))
echo ""
echo "=== Training results ==="
echo "Before: $BEFORE learned"
echo "After: $AFTER learned"
echo "Delta: $DELTA new learnings"
echo "Spam processed: $SPAM_TRAINED"
echo "Ham processed: $HAM_TRAINED"

rspamc -h "$RSPAMD_HOST:$RSPAMD_PORT" -P "$RSPAMD_PWD" stat 2>/dev/null | grep -E "BAYES_SPAM|BAYES_HAM"

# Fail if no new learnings
if [ "$DELTA" -lt 100 ]; then
  echo "ERROR: Expected at least 100 new learnings, got $DELTA" >&2
  exit 1
fi

echo ""
echo "=== Bayes seeding complete ==="
