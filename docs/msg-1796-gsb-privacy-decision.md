# MSG-1796: Google Safe Browsing — Privacy & Quota Decision

> **Status:** DECISION REQUIRED<br>
> **Author:** Barry Reynolds · 🤖 Hermes (AI)<br>
> **Date:** 2026-08-09<br>
> **Related:** MSG-1784 (Add GSB API for phishing URL detection)

## Executive Summary

**Recommendation: Do NOT use Google Safe Browsing API. Use Google Web Risk API instead.**

GSB's terms explicitly restrict it to **non-commercial use only** ("not for sale or revenue generating purposes"). Telnyx Email is a commercial product — we charge customers for sending email. Using GSB would violate their terms of service.

Google's own guidance directs commercial users to **Web Risk** (Google Cloud's paid equivalent).

---

## 1. Data Minimization Assessment

### What gets sent to Google

| API | Data sent | Privacy concern |
|---|---|---|
| GSB Lookup API | Full URL (e.g., `https://evil.com/login`) | URLs may contain path segments with tokens, IDs, or PII |
| Web Risk Lookup API | Full URL (same as GSB) | Same concern, but governed by Google Cloud's enterprise DPA |
| Web Risk Update API | URL hash prefixes (not full URLs) | Minimal exposure — only hash prefixes sent for confirmation |

**Mitigation:** Use the **Update API** (Web Risk), not the Lookup API. The Update API sends only hash prefixes to Google, never full URLs. URLs are hashed locally first; only matching hash prefixes are sent for threat confirmation.

### What stays private

- Email message body — never sent to Google
- Sender/recipient addresses — never sent to Google
- Only URL hash prefixes from the message body are sent (Update API)

### Risk assessment

| Signal | GSB Lookup | Web Risk Update API |
|---|---|---|
| Full URL exposed | Yes | No (hash prefix only) |
| Path/query params exposed | Yes | No |
| Governed by enterprise DPA | No | Yes (Google Cloud) |
| Commercial use permitted | No | Yes |
| Cost | Free | Free for Update API, paid for confirmation |

---

## 2. Terms of Service Review

### Google Safe Browsing API (v4)

> "The Safe Browsing API is for **non-commercial use only** (meaning 'not for sale or revenue generating purposes'). If you need a solution for commercial purposes, please refer to **Web Risk**."

**Verdict: ❌ Not usable for Telnyx Email.** We charge customers for email sending. Content scanning is a feature of a paid product. This is clearly commercial use.

Additional requirements that would constrain our product:
- Must display "Advisory provided by Google" attribution in user-facing warnings
- Must include user protection notice about false positives/negatives
- Must use qualifying language ("suspected", "potentially") in warnings
- Cannot show warnings using stale data (cache must be valid at time of warning)

### Google Web Risk API (Google Cloud)

- Commercial use permitted
- Governed by Google Cloud Platform terms (enterprise-grade, with DPA)
- Same threat data as GSB (shared infrastructure)
- Standard Google Cloud IAM, audit logging, and data processing agreements

**Verdict: ✅ Suitable for Telnyx Email.**

---

## 3. Key Management Plan

### API key storage

- Store Web Risk API key in **Vault** (like other Google Cloud credentials)
- Key name: `GOOGLE_WEB_RISK_API_KEY`
- Access: `messaging-email-scanner` service only
- Rotation: quarterly via Vault lifecycle

### Access control

- Key restricted to `webrisk.threatMatches.search` and `webrisk.threatLists.computeDiff` scopes
- Google Cloud project with IAM restricted to scanner service account
- No human access to API key (automated only)

---

## 4. Cache/Quota Model

### Web Risk pricing

| API | Call type | 0-100K/month | 100K-10M/month | 10M+/month |
|---|---|---|---|---|
| Lookup API | `uris.search` | Free | $0.50/1K calls | Contact sales |
| Update API | `threatLists.computeDiff` | Free | Free | Free |
| Update API | `hashes.search` (confirmation) | $50/1K calls | Contact sales | Contact sales |

### Recommended: Update API only

The Update API keeps a local copy of threat hash prefixes. Only when a URL hash matches a local prefix do we send the hash prefix for confirmation — drastically fewer API calls.

**Cost model (Update API):**

| Component | Cost |
|---|---|
| `threatLists.computeDiff` (local DB update) | **Free** (unlimited) |
| `hashes.search` (threat confirmation) | $50/1K calls |
| Estimated confirmations/month | ~1K (only suspicious URLs match local hash) |
| **Estimated monthly cost** | **~$50** |

### Caching strategy

1. **Local hash database** — Downloaded via `threatLists.computeDiff` (free, unlimited). Contains URL hash prefixes. Checked locally before any API call.
2. **Hash confirmation cache** — TTL 30 min (per Google's max cache age). Prevents re-querying the same hash within the cache window.
3. **Negative cache** — Non-matching URLs cached for 5 min (configurable). Prevents redundant local hash lookups for the same URL in a scan batch.

---

## 5. Decision

| Option | Commercial? | Privacy | Cost | Recommendation |
|---|---|---|---|---|
| GSB Lookup API | ❌ No | Full URLs sent | Free | **Do not use** |
| GSB Update API | ❌ No | Hash prefixes | Free | **Do not use** |
| Web Risk Lookup API | ✅ Yes | Full URLs sent | Free 100K, then $0.50/1K | Backup option |
| Web Risk Update API | ✅ Yes | Hash prefixes only | ~$50/month | **✅ Use this** |
| OpenPhish (already integrated) | ✅ Yes | No external calls | Free | **Already in use** |
| PhishTank (optional) | ✅ Yes | API key, full URLs | Free | Consider later |

### Proceed decision: ✅ **PROCEED with Web Risk Update API**

- Commercial use permitted
- Hash-prefix only (minimal data exposure)
- ~$50/month estimated cost
- Same threat intelligence as GSB
- Governed by Google Cloud enterprise terms

### Implementation note

Update MSG-1784 to reference **Google Web Risk Update API** instead of Google Safe Browsing API. The Rspamd Lua integration will use Web Risk's `hashes.search` endpoint, not GSB's `threatMatches.find`.

---

## 6. Privacy safeguards for implementation

1. **Hash before send** — URLs are SHA-256 hashed locally. Only the first 4-32 bytes of the hash are sent to Google for prefix matching. Full URLs never leave our infrastructure.
2. **No message content** — Only URL hashes from message bodies are checked. Message text, headers, and metadata are never sent to Google.
3. **No sender/recipient data** — No email addresses, account IDs, or tenant identifiers are sent to Google.
4. **Cache TTL compliance** — Cached results expire per Google's specified cache duration. No warnings shown from stale data.
5. **Audit logging** — All Web Risk API calls logged with timestamp, hash prefix, and response. No full URLs in logs.
