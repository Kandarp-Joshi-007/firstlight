# firstlight

**Early warning for Irish brand impersonation, from public certificate logs.**

Every HTTPS certificate issued anywhere on earth is published to public
Certificate Transparency logs within seconds. A phishing site needs a
certificate to avoid browser warnings — so **the attacker's domain appears in
these logs before the scam goes live.**

firstlight reads that stream, picks out domains imitating Irish banks, An Post,
Revenue, the HSE and others, and asks [Jev](https://typesafe.ai) — a
decision-only model that returns calibrated probabilities instead of text —
whether each one is really an impersonation attempt.

```
CT log  ──►  brand filter  ──►  Jev  ──►  SQLite
208/s        0.04% survive     $0.0000125    verdict + confidence
             free, local        per call
```

---

## Calibration — does the model actually work?

Before building any of this, the model was tested on **2,000 domains**: 1,000
known phishing, 1,000 legitimate, sampled from Tranco ranks 20k–300k so the
control group is genuinely hard (`crafina.top` and `unitiki.com` are real
sites; `google.com` would have proved nothing).

Against a keyword-and-edit-distance baseline of the kind existing CT phishing
tools use:

```
                  thresh   caught   recall   false+   precision
  Jev                0.7      223    22.3%        7       97.0%
  regex baseline     0.7       51     5.1%        0      100.0%

  Jev AUC 0.734   ·   regex AUC 0.772
```

**The baseline wins on AUC. Jev catches 4× more at a usable operating point.**
AUC rewards ranking across the whole range; the regex scores are coarse buckets
that rank acceptably but produce almost no high-confidence tail. What matters
operationally is how many you catch at near-zero false alarms, and there the
gap is 223 to 51.

Where Jev wins is where a keyword list structurally cannot help:

```
jev=0.97 rx=0.12  coiuinbase-logiion.godaddysites.com   (Coinbase typo, not in any list)
jev=0.87 rx=0.05  pgroupefinances...encaissement.ru     (French lure, misspelled)
jev=0.87 rx=0.60  giris-turkiye-gov-tr.org              (Turkish: giriş = "login")
jev=0.85 rx=0.33  2wawindowslockeduperror...support     (tech-support scam, no brand)
```

By stratum, at zero-to-minimal false positives:

```
  stratum          n   Jev@0.7          95% CI      regex@0.7
  english        500    22.0%  [18.6%, 25.8%]           3.8%
  non-english    400    18.8%  [15.2%, 22.9%]           2.2%
  punycode       100    38.0%  [29.1%, 47.8%]          23.0%
```

**Punycode is the one stratum Jev wins outright**, including on AUC (0.821 vs
0.756). Homoglyph attacks are semantic by construction — `xn--wkipedia-c2a.org`
is "wikipedia" with a substituted character, and the substitution *is* the
attack. A keyword list cannot see it.

Total calibration spend: **$0.05**.

### A hypothesis that died

At 150 domains, Jev looked dramatically better on non-English lures and a
multilingual advantage seemed like the headline. At 2,000 the effect vanished —
5.8× on English, 8.5× on non-English, with *lower* absolute recall on
non-English. Small samples lie. It is recorded here because the correction is
part of the result.

---

## Running it

```
python watch.py --once --no-jev     one pass, filter only, no key needed
python watch.py                     run continuously
python watch.py --stats             what has been found
python brands.py                    filter self-test
```

Set a key to enable scoring:

```
$env:OPENROUTER_API_KEY = '...'     # PowerShell
export OPENROUTER_API_KEY=...       # bash
```

Python 3.9+, `cryptography` for X.509 parsing, otherwise standard library.
Storage is SQLite; there is nothing to install or host.

TypeSafe paused direct signups on 2026-09-22, so this routes through
OpenRouter. Jev is **not** a chat model — it is absent from `/v1/models` and
rejected by `/chat/completions`. It lives at `/api/alpha/decisions`.

---

## The brand filter

Its only job is to cut a firehose to a handful of candidates. It is
deliberately generous: a wrong candidate costs $0.0000125 to dismiss, a missed
one is never seen again. **Precision is Jev's job.**

It is not a substring match, because real impersonation uses character
substitution (`rev0lut`), spacing (`an-post`), doubling (`anpostt`) and
homoglyphs. Tested against **391,986 real phishing domains**, four rounds of
tightening:

```
  naive substring       1,374 candidates    (61% junk — "aib" inside "saibo")
  + label boundaries      642
  + Irish context           334             ("revenue" also means Florida's)
  + decoys, tuned fuzzy     266             ("revolution" is not Revolut)
```

Each round was validated against the same corpus. The surviving hits are real:
`aib-accessportal.com`, `aib-accessonline.net`,
`365bankofireland-personalbanking.com`, `1npost.net`, `anapost.top`.

---

## Honest limitations

**Coverage is partial, by design.** A full tail of one CT log is ~121 GB/day,
because most entries are precertificates whose certificate sits in `extra_data`
and cannot be requested separately. firstlight stays at the *head* of the log and
processes what bandwidth allows, skipping forward when it falls behind — fresh
certificates matter more than complete ones when the whole point is lead time.
`--stats` reports exactly how partial. **Never present this as complete
coverage.**

**Recall is ~22%, and that is not fixable here.** Roughly half of real phishing
is hosted on `github.io`, `repl.co`, `glitch.me` or compromised legitimate
sites. The domain belongs to GitHub, not the attacker — no model can read intent
from a string that contains none.

**It detects impersonation, not confirmed phishing.** These are different
questions, and public blocklists answer the second. During calibration Jev
flagged `xn--wkipedia-c2a.org` — a homoglyph of wikipedia.org registered in
**2007**, which no blocklist records because it is not currently attacking
anyone. It is unmistakably an impersonation domain. Scored against a phishing
blocklist it counts as a false positive; that says more about the ground truth
than the model.

**Flagged is not guilty.** `lotusbet365.com` was flagged and is a legitimate
Indian betting brand — "Lotus" + "365", not bet365. Anything published from
this must be labelled *flagged for review*, never *confirmed phishing*, with a
contact for removal.

**These sources are unreliable.** certstream's public server accepts
connections and never sends a frame. crt.sh returns 502 on every query form.
Both were tried first; the direct CT log tail exists because they failed.

---

## Deployment

```
GitHub Actions (cron, Python)  ──►  commits site/data.json  ──►  Netlify deploys
```

**The collector cannot run on Netlify.** Netlify Functions support
JavaScript/TypeScript and Go only — Python is build-time only — and scheduled
functions cap at 30 seconds. GitHub Actions runs Python natively with no such
limit, and it is free for public repositories.

Committing results rather than writing to a database is deliberate: **git
history is a tamper-evident timestamp log.** Each detection's commit time is an
independent record of when it was found, which is the evidence behind any
"flagged N hours before the blocklists" claim. A database row you can edit
proves nothing.

**Setup**

1. Push to GitHub. The workflow runs every 30 minutes.
2. Add `OPENROUTER_API_KEY` under Settings → Secrets → Actions. Without it the
   filter still runs and everything is recorded as `unknown`.
3. Point Netlify at the repo. `netlify.toml` publishes `site/` with no build
   step; it redeploys automatically on each commit.

Preview locally:

```
python -m http.server -d site 8000
```

Two caveats. GitHub disables scheduled workflows on repositories with no commit
activity for 60 days — this one commits on every detection, so it stays alive
on its own. And scheduled runs are delayed under load, so treat the cadence as
approximate rather than exact.

---

## Layout

```
brands.py                    Irish brand targets + pre-filter  (392k-domain validation)
jev.py                       Jev client, thresholds, verdicts  (2k-domain calibration)
watch.py                     CT tailer, pipeline, SQLite, export
site/index.html              dashboard (static, reads data.json)
.github/workflows/watch.yml  collector on a 30-minute cron
netlify.toml                 static publish config
```
