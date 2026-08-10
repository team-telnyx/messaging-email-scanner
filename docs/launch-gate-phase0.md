# Phase 0 → Phase 1 Launch Gate Decision

**Date:** _(to be filled when report is reviewed)_
**Decision:** PENDING

## Launch Gates

| Gate | Requirement | Actual | Pass? |
|---|---|---|---|
| Canary success | All clean/spam/phishing canaries passing | _(from shadow_eval.py)_ | ⬜ |
| Scan coverage | >99% of Kumo receptions scanned | _(from shadow_eval.py)_ | ⬜ |
| Scan latency p99 | <200ms | _(from shadow_eval.py)_ | ⬜ |
| Sample size | ≥10,000 scan decisions | _(from shadow_eval.py)_ | ⬜ |
| Observation period | ≥7 days of shadow-mode data | _(from shadow_eval.py)_ | ⬜ |

## Summary Metrics

- **Total scans:** _(from report)_
- **Successful scans:** _(from report)_
- **Failed scans:** _(from report)_
- **Action breakdown:** _(from report)_
- **Canary results:** _(from report)_

## Detection Quality

- **Detection rate (no action vs reject/add header):** _(from report)_
- **False positive rate (from appeals):** _(to be measured in Phase 1)_
- **Score distribution:** _(from report)_

## Decision

### Pre-conditions met
- [ ] All launch gates pass
- [ ] Canary monitoring operational (MSG-1775)
- [ ] Scanner deployed and stable (MSG-1771)
- [ ] Bayes seeded (MSG-1772)
- [ ] Scan hook wired (MSG-1773)
- [ ] Typed transport working (MSG-1774)
- [ ] EDR enrichment live (MSG-1776)
- [ ] Admission controls live (MSG-1790)
- [ ] Canaries + monitoring live (MSG-1775)
- [ ] Exact-MIME durability (MSG-1789)
- [ ] Quarantine state machine ready (MSG-1777)
- [ ] Scan-decision record ready (MSG-1778)

### Approval

- **Reviewer:** _(name)_
- **Date:** _(date)_
- **Decision:** APPROVED / DELAYED

### If approved
1. Change `RSPAMD_SCAN_MODE` from `shadow` to `quarantine`
2. Configure `RSPAMD_MIME_STORAGE_URL` for evidence storage
3. Monitor quarantine queue depth for 24h
4. Verify `message.quarantined` webhooks fire correctly
5. Begin appeals triage workflow

### If delayed
1. Document which gates failed
2. Set remediation timeline
3. Re-run `shadow_eval.py` after fixes
