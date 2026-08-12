#!/bin/bash
# convert-hf-datasets.sh — Convert HuggingFace email datasets to .eml files
#
# Runs on the HOST (requires python3 + curl). Produces tar archives of .eml files
# that bootstrap-bayes.sh can extract and train on inside the scanner container.
#
# Datasets:
#   Gunjand07/email-spam-dataset  (2026-02, 83K records, CSV: label,text)
#   yxzwayne/email-spam-10k      (2024-07, 11K records, JSON: text,is_spam)
#   zefang-liu/phishing-email    (2024-01, 18K records, CSV: Email Text,Email Type)
#
# Usage: bash scripts/convert-hf-datasets.sh [output_dir]
# Default output: /tmp/hf-email-corpus/

set -euo pipefail

OUTPUT_DIR="${1:-/tmp/hf-email-corpus}"
mkdir -p "$OUTPUT_DIR"

log() { echo "[$(date -u +%H:%M:%S)] $*"; }

log "Converting HuggingFace datasets to .eml files..."

# ============================================================================
# Dataset 1: Gunjand07/email-spam-dataset (CSV: label,text)
# ============================================================================
log "Downloading Gunjand07/email-spam-dataset (133MB)..."
curl -sSf -L -o "$OUTPUT_DIR/gunjand.csv" \
  'https://huggingface.co/datasets/Gunjand07/email-spam-dataset/resolve/main/combined_data.csv'

mkdir -p "$OUTPUT_DIR/gunjand_spam" "$OUTPUT_DIR/gunjand_ham"

log "Converting Gunjand07 to .eml files..."
python3 << 'PYEOF'
import csv, sys, os
csv.field_size_limit(sys.maxsize)
output = os.environ.get("OUTPUT_DIR", "/tmp/hf-email-corpus")
spam_dir = f"{output}/gunjand_spam"
ham_dir = f"{output}/gunjand_ham"
spam_count = 0
ham_count = 0
with open(f"{output}/gunjand.csv", newline="") as f:
    reader = csv.DictReader(f)
    for row in reader:
        label = row.get("label", "").strip()
        text = row.get("text", "").strip()
        if not text or len(text) < 20:
            continue
        # Construct a minimal email
        if "Subject:" in text:
            email = text
        else:
            email = f"Subject: {text[:80]}\r\n\r\n{text}"
        # Ensure proper line endings
        email = email.replace("\n", "\r\n").replace("\r\r\n", "\r\n")
        if label == "1":
            with open(f"{spam_dir}/{spam_count:06d}.eml", "w") as out:
                out.write(email)
            spam_count += 1
        elif label == "0":
            with open(f"{ham_dir}/{ham_count:06d}.eml", "w") as out:
                out.write(email)
            ham_count += 1
print(f"Gunjand07: {spam_count} spam, {ham_count} ham")
PYEOF

# ============================================================================
# Dataset 2: yxzwayne/email-spam-10k (JSON: text,is_spam)
# ============================================================================
log "Downloading yxzwayne/email-spam-10k (14MB)..."
curl -sSf -L -o "$OUTPUT_DIR/yxzwayne.json" \
  'https://huggingface.co/datasets/yxzwayne/email-spam-10k/resolve/main/email-spam-10k.json'

mkdir -p "$OUTPUT_DIR/yxzwayne_spam" "$OUTPUT_DIR/yxzwayne_ham"

log "Converting yxzwayne to .eml files..."
python3 << 'PYEOF'
import json, os
output = os.environ.get("OUTPUT_DIR", "/tmp/hf-email-corpus")
spam_dir = f"{output}/yxzwayne_spam"
ham_dir = f"{output}/yxzwayne_ham"
spam_count = 0
ham_count = 0
with open(f"{output}/yxzwayne.json") as f:
    data = json.load(f)
for item in data:
    text = item.get("text", "").strip()
    is_spam = str(item.get("is_spam", "")).strip()
    if not text or len(text) < 20:
        continue
    # The text already starts with "Subject:" in most cases
    email = text.replace("\n", "\r\n").replace("\r\r\n", "\r\n")
    if is_spam in ["1", "True", "true"]:
        with open(f"{spam_dir}/{spam_count:06d}.eml", "w") as out:
            out.write(email)
        spam_count += 1
    elif is_spam in ["0", "False", "false"]:
        with open(f"{ham_dir}/{ham_count:06d}.eml", "w") as out:
            out.write(email)
        ham_count += 1
print(f"yxzwayne: {spam_count} spam, {ham_count} ham")
PYEOF

# ============================================================================
# Dataset 3: zefang-liu/phishing-email-dataset (CSV: Email Text,Email Type)
# ============================================================================
log "Downloading zefang-liu/phishing-email-dataset (50MB)..."
curl -sSf -L -o "$OUTPUT_DIR/zefang.csv" \
  'https://huggingface.co/datasets/zefang-liu/phishing-email-dataset/resolve/main/Phishing_Email.csv'

mkdir -p "$OUTPUT_DIR/zefang_phish" "$OUTPUT_DIR/zefang_safe"

log "Converting zefang to .eml files..."
python3 << 'PYEOF'
import csv, sys, os
csv.field_size_limit(sys.maxsize)
output = os.environ.get("OUTPUT_DIR", "/tmp/hf-email-corpus")
phish_dir = f"{output}/zefang_phish"
safe_dir = f"{output}/zefang_safe"
phish_count = 0
safe_count = 0
with open(f"{output}/zefang.csv", newline="") as f:
    reader = csv.DictReader(f)
    for row in reader:
        text = row.get("Email Text", "").strip()
        etype = row.get("Email Type", "").strip()
        if not text or len(text) < 20:
            continue
        if "Subject:" in text:
            email = text
        else:
            email = f"Subject: {text[:80]}\r\n\r\n{text}"
        email = email.replace("\n", "\r\n").replace("\r\r\n", "\r\n")
        if etype == "Phishing Email":
            with open(f"{phish_dir}/{phish_count:06d}.eml", "w") as out:
                out.write(email)
            phish_count += 1
        elif etype == "Safe Email":
            with open(f"{safe_dir}/{safe_count:06d}.eml", "w") as out:
                out.write(email)
            safe_count += 1
print(f"zefang: {phish_count} phishing, {safe_count} safe")
PYEOF

# ============================================================================
# Create tar archives for easy transfer to container
# ============================================================================
log "Creating tar archives..."
cd "$OUTPUT_DIR"

tar cf gunjand_spam.tar gunjand_spam/ 2>/dev/null && gzip gunjand_spam.tar
tar cf gunjand_ham.tar gunjand_ham/ 2>/dev/null && gzip gunjand_ham.tar
tar cf yxzwayne_spam.tar yxzwayne_spam/ 2>/dev/null && gzip yxzwayne_spam.tar
tar cf yxzwayne_ham.tar yxzwayne_ham/ 2>/dev/null && gzip yxzwayne_ham.tar
tar cf zefang_phish.tar zefang_phish/ 2>/dev/null && gzip zefang_phish.tar
tar cf zefang_safe.tar zefang_safe/ 2>/dev/null && gzip zefang_safe.tar

# Clean up raw CSV/JSON and extracted dirs (keep tars)
rm -f gunjand.csv yxzwayne.json zefang.csv
rm -rf gunjand_spam gunjand_ham yxzwayne_spam yxzwayne_ham zefang_phish zefang_safe

log "Done! Tar archives in $OUTPUT_DIR:"
ls -lh "$OUTPUT_DIR"/*.tar.gz 2>/dev/null || echo "  (none)"

echo ""
echo "To train: copy tars to scanner container and extract:"
echo "  for f in $OUTPUT_DIR/*.tar.gz; do docker cp \"\$f\" rspamd:/tmp/; done"
echo "  docker exec rspamd bash -c 'cd /tmp && for f in *.tar.gz; do tar xzf \"\$f\"; done'"
echo "  # Then run rspamc learn_spam/learn_ham on the extracted dirs"
