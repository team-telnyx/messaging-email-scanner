# Custom Rspamd rules

MSG-1798 adds two multimap signals backed by local regular-expression maps:

| Symbol | Input | Score | Purpose |
| --- | --- | ---: | --- |
| `OBFUSCATED_SPAM` | Decoded message text | 5.0 | Detect substitution-based spam vocabulary |
| `IDN_HOMOGRAPH` | Parsed URL hostnames | 8.0 | Detect punycode, mixed-script labels, and known whole-script brand lookalikes |

The rules are registered in `config/override.d/multimap.conf`. Their maps live
under `config/local.d/maps.d/` and use Rspamd's `regexp;` map type. Both rules
set `one_shot = true` and neither is a prefilter or force-action rule.

## Obfuscated text

`OBFUSCATED_SPAM` scans decoded, flattened text parts with the expressions in
`config/local.d/maps.d/obfuscated_spam.map`. Matching is ASCII
case-insensitive. Word boundaries keep substitutions from matching arbitrary
substrings inside longer words.

The map currently detects these patterns:

| Target | Detected form(s) |
| --- | --- |
| viagra | `v[1!][a@]gra` (`v1agra`, `v1@gra`, `v!agra`, `v!@gra`) |
| cialis | `c1[a@]lis`, `c@lis` |
| penis | `p3n[1i]s`, `pen1s` |
| xanax | `x[a@]nax` (`x@nax`, `xanax`) |
| valium | `v[a@]lium` (`v@lium`, `valium`) |
| loan | `l0[a@]n` (`l0an`, `l0@n`) |
| poker | `p0k[e3]r` (`p0ker`, `p0k3r`) |
| casino | `c@s[i1]n[o0]`, `cas1n[o0]`, `casin0` |
| lottery | `l0tt[e3]ry` (`l0ttery`, `l0tt3ry`) |
| weight / weight loss | `w3[i!]ght` (`w3ight`, `w3!ght`) |
| mortgage | `m0rtgage`, `mortg@ge` |
| credit | `cr3d[i1]t`, `cred1t` |
| pharmacy | `pharm@cy`, `ph4rmacy` |
| bonus | `b0nus` |
| click | `cl1ck`, `c1ick` |
| offer | `0ffer`, `off3r` |
| prize | `pr1ze` |
| winner | `w1nner` |
| diet | `d1et` |
| cash | `c@sh` |

Except for `xanax` and `valium`, whose plain forms were explicitly included in
MSG-1798, expressions require at least one substitution. For example, plain
`cialis` does not emit `OBFUSCATED_SPAM`.

## IDN homographs

`IDN_HOMOGRAPH` examines each hostname parsed from message URLs. It covers
three complementary cases:

1. **Punycode:** `xn--` labels such as `xn--pple-43d.com`. Punycode identifies
   an encoded internationalized domain; it is a risk signal, not proof of
   abuse, because legitimate internationalized domains also use it.
2. **Mixed script:** ASCII Latin and Cyrillic or Greek characters in the
   **same DNS label**, such as Cyrillic `аpple.com` or `micrоsoft.com`.
3. **Whole-script brand lookalikes:** explicit Cyrillic labels for common
   brands, including `аррӏе` (Apple), `раураӏ` (PayPal), `рерѕі` (Pepsi), and
   `соса-соӏа` (Coca-Cola). These require explicit patterns because they do not
   mix scripts.

All-ASCII domains such as `apple.com` remain unmatched. The broad punycode
signal must be evaluated with the explicit lookalike patterns and other Rspamd
evidence rather than used as a deterministic rejection rule.

The map has explicit expressions for these confusable characters:

| Lookalike | Code point | Impersonated ASCII character |
| --- | --- | --- |
| Cyrillic `а` | U+0430 | `a` (U+0061) |
| Cyrillic `е` | U+0435 | `e` (U+0065) |
| Cyrillic `о` | U+043E | `o` (U+006F) |
| Cyrillic `р` | U+0440 | `p` (U+0070) |
| Cyrillic `с` | U+0441 | `c` (U+0063) |
| Greek `ο` | U+03BF | `o` (U+006F) |

A final expression covers other Latin/Cyrillic and Latin/Greek mixtures. All
Unicode IDN expressions use Rspamd's `/u` modifier, which is required for UTF-8
regular expressions.

## Scoring philosophy

These symbols contribute evidence to Rspamd's aggregate score; they do not make
a deterministic accept/reject decision:

- `OBFUSCATED_SPAM` scores 5.0. One suspicious substitution is useful evidence,
  but is not enough by itself to cross the scanner's 15.0 reject threshold.
- `IDN_HOMOGRAPH` scores 8.0 because IDN and lookalike URL labels are useful
  phishing indicators, while still remaining below that threshold on their own.
- `one_shot = true` prevents repeated occurrences in a checked part or hostname
  set from multiplying the configured contribution.
- Neither rule sets `prefilter`, `action`, or a force-action expression.

The symbols can therefore combine with URL reputation, phishing, Bayes, MIME,
and other signals. A score-based policy can reject the aggregate result, while
an observation or deterministic-only policy can retain the symbols as context.

## Launch gate: shadow false-positive evaluation

The Linear acceptance criterion for false-positive evaluation is a runtime
launch-gate activity; adding patterns and fixtures does **not** complete it.
Before either symbol influences enforcement:

- [ ] Run `OBFUSCATED_SPAM` and `IDN_HOMOGRAPH` in shadow mode against the
  representative shadow dataset used by MSG-1791.
- [ ] Label matched messages as malicious, benign, or indeterminate, and report
  match counts and false-positive rates separately for obfuscated text,
  punycode, mixed-script IDNs, and whole-script brand lookalikes.
- [ ] Review legitimate punycode domains and benign substitution matches;
  record any allowlist or pattern changes and rerun the evaluation after them.
- [ ] Attach the measured results and dataset/report identifiers to the launch
  decision. Do not mark this gate complete from unit or synthetic tests alone.
- [ ] Obtain Email Abuse, Deliverability, and Security approval for the measured
  false-positive rate before enabling enforcement.

Until this checklist is completed, the symbols remain shadow/observability
signals and the false-positive acceptance criterion remains pending.

## Adding or changing patterns

1. Add one expression per line to the appropriate map:
   - text substitutions: `config/local.d/maps.d/obfuscated_spam.map`
   - IDN and lookalike domains: `config/local.d/maps.d/idn_homograph.map`
2. Use Rspamd regexp-map syntax, including delimiters and modifiers. For
   example: `/\\bnew_patt3rn\\b/i`. Unicode IDN expressions must include `/u`.
3. Keep text patterns substitution-specific unless matching a plain term is an
   intentional policy decision. Use boundaries to avoid substring false
   positives.
4. For generic Unicode lookalikes, require Latin and the lookalike script within
   one label. Keep whole-script matches limited to reviewed brand patterns.
   Treat the intentionally broad punycode expression as a score signal, never a
   standalone malicious verdict.
5. Add both a positive fixture and a closely related benign negative fixture to
   `tests/obfuscated_text_test.sh` or `tests/idn_homograph_test.sh`.
6. Validate the shell and Rspamd configuration, then run the live scans:

   ```bash
   bash -n tests/obfuscated_text_test.sh tests/idn_homograph_test.sh
   rspamadm configtest
   tests/obfuscated_text_test.sh
   tests/idn_homograph_test.sh
   ```

Local map content is monitored by Rspamd and can reload without a process
restart. Changes to the multimap rule configuration itself require the normal
configuration reload/restart path.
