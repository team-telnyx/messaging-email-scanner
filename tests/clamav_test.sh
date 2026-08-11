#!/bin/bash
set -euo pipefail

# Test ClamAV integration
# Requires: ClamAV running on port 3310, Rspamd running

# Test 1: EICAR test file (standard antivirus test)
# Create a message with EICAR attachment
EICAR='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
echo -e "Subject: virus test\r\n\r\n$EICAR" | rspamc -h localhost:11333 --header "Settings-ID: outbound"

# Expected: CLAM_VIRUS symbol present, action should include rejection

# Test 2: Clean message — no CLAM_VIRUS
echo -e "Subject: clean\r\n\r\nHello world" | rspamc -h localhost:11333 --header "Settings-ID: outbound"

# Expected: no CLAM_VIRUS symbol
