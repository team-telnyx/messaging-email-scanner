# messaging-email-scanner

Rspamd-based outbound content scanner for Telnyx Email.

## Overview

Rspamd deployed as a separate service alongside the email-api stack. Scans
outbound email content (spam, phishing, malware) at the KumoMTA
`http_message_generated` hook — after final per-recipient MIME construction,
before DKIM signing and queue insertion.

## Architecture

```
KumoMTA (http_message_generated)
    │
    │  POST /checkv2 (raw MIME + headers)
    ▼
Rspamd Scanner (port 11333, private)
    ├── Bayes classifier (Redis backend)
    ├── OpenPhish feed (phishing URLs)
    ├── Obfuscated spam text map (regexp multimap)
    ├── IDN homograph map (regexp multimap)
    ├── Lookalike domain map (multimap)
    ├── IP URL map (multimap)
    ├── MIME type checks (bad extensions)
    ├── Heuristics (content, headers, URLs)
    └── ClamAV sidecar (Phase 2, port 3310)

Rspamd Controller (port 11334, ops-only, authenticated)
    ├── Learn spam/ham endpoints
    ├── Metrics/history
    └── Configuration management

Unbound DNS (port 53, internal)
    └── Local recursive resolver for RBL/SURBL
```

## Ports

| Port | Service | Access |
|------|---------|--------|
| 11333 | Rspamd scanner | KumoMTA pods only (NetworkPolicy) |
| 11334 | Rspamd controller | Ops only (authenticated) |
| 6379 | Redis | Internal only |
| 53 | Unbound DNS | Internal only |
| 3310 | ClamAV (Phase 2) | Internal only |

No ports published externally.

## Development

```bash
# Local Docker Compose for dev/testing
docker compose -f docker-compose.yml up -d

# Health check
curl -s http://localhost:11333/ping
# Expected: pong

# Scan a message
curl -s -X POST http://localhost:11333/checkv2 \
  -H "Content-Type: message/rfc822" \
  --data-binary @test.eml | jq .

# Run clean, GTUBE-spam, and deterministic phishing canaries
RSPAMD_HOST=127.0.0.1 scripts/canary.sh

# Exercise custom text and IDN homograph rules against the live scanner
tests/obfuscated_text_test.sh
tests/idn_homograph_test.sh
```

See [`docs/custom-rules.md`](docs/custom-rules.md) for the detected patterns,
scoring policy, and instructions for extending the maps.

## Synthetic canaries

`/scripts/canary.sh` runs three `rspamc` checks and exits non-zero if any
expectation fails:

- known-clean MIME must return `no action`
- the standard GTUBE message must return `reject` or `add header`
- the controlled phishing URL must emit `PHISHED_OPENPHISH`

Every result and the final summary are emitted as one-line JSON for log-based
alerts. The deployment CronJob runs this script every five minutes.

## Design Document

See: `email/docs/antispam-integration-proposal.md` in the PM monorepo.

## Related

- PoC work: MSG-1746 (Docker Compose scanner, In Review)
- Design doc: MSG-1771 through MSG-1801 (Linear project: Email Anti-Spam Integration)
