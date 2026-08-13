# MSG-1848 score tuning results

## Decision

Raise `BAYES_SPAM` from the Rspamd 3.10 default weight of **5.1** to
**11.5**, and raise built-in `MIME_BAD_ATTACHMENT` from its effective corpus
score of **1.6** to **2.6** (declared weight **6.5**). Keep `BAYES_HAM` at
**-3.0**, the custom deterministic symbol scores unchanged, and the outbound
action boundary unchanged at **6.0** for `add header` and **15.0** for
`reject`.

The selected Bayes value is the smallest half-point weight that catches all
three previously evading corpus messages where `BAYES_SPAM` is usable positive
evidence. The tightest new catch is the IDN-homoglyph fixture at **6.06**, just
above the 6.0 action boundary. The attachment adjustment brings the only macro
fixture from **5.10** to **6.10**. Raising the other custom symbols
cannot recover additional evasions because none of those symbols fire on the
remaining eight messages.

## Corpus distribution

Scans use the golden suite's reproducible classifier setup: 25 attack fixtures
learned as spam, 25 non-stress legitimate fixtures learned as ham, followed by
a fresh scan of all 107 committed messages under `Settings-ID: outbound`.

| Corpus/result | Before | After |
|---|---:|---:|
| Attacks caught (`add_header` or `reject`) | 40/52 (76.9%) | 44/52 (84.6%) |
| Attacks at `no_action` | 12/52 (23.1%) | 8/52 (15.4%) |
| Attacks at `add_header` | 37/52 | 33/52 |
| Attacks at `reject` | 3/52 | 11/52 |
| Standard legitimate false positives | 0/50 | 0/50 |
| `fp_stress` known-risk warnings | 5/5 | 5/5 |

Newly caught attacks:

- `attachment_qr/02_pdf_embedded_link.eml`: 5.43 to 7.84 (`add_header`)
- `attachment_qr/04_office_macro_url.eml`: 5.10 to 6.10 (`add_header`)
- `phishing_html/09_javascript_redirect.eml`: 5.73 to 8.14 (`add_header`)
- `phishing_url/08_idn_homoglyph.eml`: 4.64 to 6.06 (`add_header`)

The highest standard legitimate score remains **3.50**, leaving **2.50** points
of margin below `add_header`. No standard legitimate fixture emits
`BAYES_SPAM`; legitimate Bayes evidence remains neutral or `BAYES_HAM`, whose
negative weight is unchanged.

## Remaining evasions

The eight remaining `no_action` attacks do not emit a positive tunable custom
symbol. They cover unsupported attachment/script extraction and URL patterns
that need detector or reputation logic rather than score changes:

- Classic or clean non-brand phishing URLs
- Shortened, bare, punycode, userinfo, and diluted URLs
- Crypto seed-phrase social engineering

Changing shared built-in housekeeping scores or lowering the global action
threshold enough to catch these messages would overfit corpus metadata and
would move legitimate fixtures to `add_header`. Those changes were rejected.
