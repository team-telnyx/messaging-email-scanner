#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CONFIG="$REPO_ROOT/config/local.d/trusted_sender.conf"
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT
RSPAMC_BIN=${RSPAMC_BIN:-rspamc}

cat >"$TMP_DIR/rspamc" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
settings_id=outbound
fixture=${!#}
previous=
for argument in "$@"; do
  if [[ "$previous" == "--header" && "$argument" == Settings-ID:* ]]; then
    settings_id=${argument#Settings-ID: }
  fi
  previous=$argument
done
message=$(<"$fixture")

if [[ "$message" == *"Subject: trusted sender malware canary"* ]]; then
  printf 'Action: reject\nScore: 1000.00 / 20.00\nSymbol: CLAM_VIRUS\n'
elif [[ "$message" == *"Subject: trusted sender score canary"* && "$settings_id" == "trusted" ]]; then
  printf 'Action: add header\nScore: 17.00 / 20.00\nSymbol: CANARY_SCORE_17\n'
elif [[ "$message" == *"Subject: trusted sender score canary"* ]]; then
  printf 'Action: reject\nScore: 17.00 / 15.00\nSymbol: CANARY_SCORE_17\n'
else
  printf 'unexpected fixture\n' >&2
  exit 2
fi
FAKE
chmod +x "$TMP_DIR/rspamc"

cat >"$TMP_DIR/score-17.eml" <<'EOF'
From: canary@msgtelnyx.com
To: canary@example.com
Subject: trusted sender score canary

Synthetic score-threshold canary.
EOF

cat >"$TMP_DIR/malware.eml" <<'EOF'
From: canary@msgtelnyx.com
To: canary@example.com
Subject: trusted sender malware canary

Synthetic CLAM_VIRUS canary.
EOF

scan_action() {
  local settings_id=$1
  local fixture=$2
  "$RSPAMC_BIN" --header "Settings-ID: $settings_id" "$fixture" |
    sed -n 's/^Action:[[:space:]]*//p' |
    head -n 1
}

PATH="$TMP_DIR:$PATH"
RSPAMC_BIN="$TMP_DIR/rspamc"

normal_action=$(scan_action outbound "$TMP_DIR/score-17.eml")
trusted_action=$(scan_action trusted "$TMP_DIR/score-17.eml")
malware_action=$(scan_action trusted "$TMP_DIR/malware.eml")

[[ "$normal_action" == "reject" ]]
[[ "$trusted_action" == "add header" ]]
[[ "$malware_action" == "reject" ]]

[[ -f "$CONFIG" ]]
grep -Eq 'id[[:space:]]*=[[:space:]]*"trusted";' "$CONFIG"
grep -Eq 'priority[[:space:]]*=[[:space:]]*higher;' "$CONFIG"
grep -Eq 'reject[[:space:]]*=[[:space:]]*20\.0;' "$CONFIG"
grep -Eq '"add header"[[:space:]]*=[[:space:]]*10\.0;' "$CONFIG"
grep -Eq 'greylist[[:space:]]*=[[:space:]]*null;' "$CONFIG"
grep -Eq '"rewrite subject"[[:space:]]*=[[:space:]]*null;' "$CONFIG"
grep -q 'trusted_sender.conf' "$REPO_ROOT/config/local.d/settings.conf"

echo 'trusted_sender_test: PASS'
