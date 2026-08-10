#!/bin/bash
# Seed Bayes classifier with SpamAssassin public corpus
# Downloads, extracts, and trains Rspamd's Bayes classifier via rspamc
#
# Usage: ./scripts/seed-bayes.sh [RSPAMD_HOST] [RSPAMD_PORT] [PASSWORD]
# Defaults: 127.0.0.1 11334 q1

set -eu

RSPAMD_HOST="${1:-127.0.0.1}"
RSPAMD_PORT="${2:-11334}"
RSPAMD_PWD="${3:-q1}"
CORPUS_DIR="${CORPUS_DIR:-/tmp/sa-corpus}"

echo "=== Seeding Bayes classifier with SpamAssassin public corpus ==="

# Download corpus
mkdir -p "$CORPUS_DIR"
cd "$CORPUS_DIR"

for name_url in \
  "ham|https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2" \
  "ham2|https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham_2.tar.bz2" \
  "spam|https://spamassassin.apache.org/old/publiccorpus/20030228_spam.tar.bz2" \
  "spam2|https://spamassassin.apache.org/old/publiccorpus/20050311_spam_2.tar.bz2"; do

  name="${name_url%%|*}"
  url="${name_url##*|}"
  archive="$CORPUS_DIR/$name.tar.bz2"

  if [ ! -f "$archive" ]; then
    echo "Downloading $name..."
    curl -sL -o "$archive" "$url"
  fi

  echo "Extracting $name..."
  tar xjf "$archive" -C "$CORPUS_DIR"
done

# Count files
HAM_COUNT=$(ls "$CORPUS_DIR/easy_ham/" 2>/dev/null | wc -l)
HAM2_COUNT=$(ls "$CORPUS_DIR/easy_ham_2/" 2>/dev/null | wc -l)
SPAM_COUNT=$(ls "$CORPUS_DIR/spam/" 2>/dev/null | wc -l)
SPAM2_COUNT=$(ls "$CORPUS_DIR/spam_2/" 2>/dev/null | wc -l)
echo "Ham: $HAM_COUNT + $HAM2_COUNT files"
echo "Spam: $SPAM_COUNT + $SPAM2_COUNT files"

# Train spam
echo "Training spam..."
for dir in spam spam_2; do
  if [ -d "$CORPUS_DIR/$dir" ]; then
    for f in "$CORPUS_DIR/$dir"/*; do
      rspamc -h "$RSPAMD_HOST:$RSPAMD_PORT" -P "$RSPAMD_PWD" learn_spam "$f" 2>/dev/null
    done
  fi
done
echo "Spam training complete"

# Train ham
echo "Training ham..."
for dir in easy_ham easy_ham_2; do
  if [ -d "$CORPUS_DIR/$dir" ]; then
    for f in "$CORPUS_DIR/$dir"/*; do
      rspamc -h "$RSPAMD_HOST:$RSPAMD_PORT" -P "$RSPAMD_PWD" learn_ham "$f" 2>/dev/null
    done
  fi
done
echo "Ham training complete"

# Verify
echo ""
echo "=== Training results ==="
rspamc -h "$RSPAMD_HOST:$RSPAMD_PORT" -P "$RSPAMD_PWD" stat 2>&1 | grep -E "learned|BAYES"

echo ""
echo "=== Bayes seeding complete ==="
