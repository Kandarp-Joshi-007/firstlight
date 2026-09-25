"""Irish brand targets and the cheap pre-filter that finds candidate lookalikes.

This runs before Jev, and its only job is to cut a firehose down to a handful of
plausible candidates. It is deliberately generous: a false candidate here costs
$0.0000125 to dismiss, while a missed one is never seen again. Precision is
Jev's job, not this module's.

The matching is deliberately not a plain substring test. Real impersonation
domains use character substitution (rev0lut), spacing (an-post), doubled letters
(revolutt) and homoglyphs, none of which a naive `in` catches.
"""

from __future__ import annotations

import re
import unicodedata

# (token, canonical name, legitimate domains that must never be flagged)
BRANDS: list[tuple[str, str, tuple[str, ...]]] = [
    # Banking - the highest-value phishing targets in Ireland
    ("aib",            "AIB",                ("aib.ie", "aibgb.co.uk", "aibms.com")),
    ("bankofireland",  "Bank of Ireland",    ("bankofireland.com", "boi.com")),
    ("permanenttsb",   "Permanent TSB",      ("permanenttsb.ie",)),
    ("ptsb",           "Permanent TSB",      ("permanenttsb.ie", "ptsb.ie")),
    ("revolut",        "Revolut",            ("revolut.com", "revolut.ie")),
    ("creditunion",    "Credit Union",       ("creditunion.ie",)),
    ("avantmoney",     "Avant Money",        ("avantmoney.ie",)),
    ("anpost",         "An Post",            ("anpost.ie", "anpostmoney.ie")),

    # Government and public services
    ("revenue",        "Revenue",            ("revenue.ie", "ros.ie")),
    ("mygovid",        "MyGovID",            ("mygovid.ie",)),
    ("welfare",        "Dept of Social Prot",("mywelfare.ie", "gov.ie")),
    ("citizensinfo",   "Citizens Information",("citizensinformation.ie",)),
    ("hse",            "HSE",                ("hse.ie",)),
    ("vhi",            "VHI",                ("vhi.ie",)),

    # Utilities and telecoms
    ("electricireland","Electric Ireland",   ("electricireland.ie",)),
    ("bordgais",       "Bord Gais",          ("bordgaisenergy.ie",)),
    ("esbnetworks",    "ESB Networks",       ("esbnetworks.ie", "esb.ie")),
    ("eircom",         "Eir",                ("eir.ie", "eircom.net")),

    # Transport
    ("irishrail",      "Irish Rail",         ("irishrail.ie",)),
    ("dublinbus",      "Dublin Bus",         ("dublinbus.ie",)),
    ("leapcard",       "Leap Card",          ("leapcard.ie",)),
    ("aerlingus",      "Aer Lingus",         ("aerlingus.com",)),
    ("ryanair",        "Ryanair",            ("ryanair.com",)),

    # Retail / delivery commonly spoofed at Irish consumers
    ("supervalu",      "SuperValu",          ("supervalu.ie",)),
    ("dunnesstores",   "Dunnes Stores",      ("dunnesstores.com",)),
    ("fastway",        "Fastway",            ("fastway.ie",)),
]

# Character substitutions used to dodge naive string matching.
FOLD = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
    "$": "s", "@": "a", "!": "l", "|": "l",
})
DIGRAPHS = (("rn", "m"), ("vv", "w"), ("cl", "d"), ("nn", "n"), ("ii", "i"))

# Brand tokens that are also ordinary English words, or generic worldwide
# institution types. On their own they are almost pure noise:
# "wolfre.direct.quickconnect.to" is within two edits of "welfare", Florida's
# tax site matches "revenue", and "creditunion" matched Navy Federal, Suncoast,
# Chase and Reading - all US or UK, in an Irish-brand project. These require an
# Irish signal in the hostname before they count, and never match fuzzily.
GENERIC = {"revenue", "welfare", "creditunion"}
IRISH_HINTS = ("ie", "irish", "eire", "ireland", "gov", "ros")

# Longer words that merely contain a brand token. "revolution" contains
# "revolut" and accounted for most Revolut hits in a real phishing corpus.
DECOYS = {"revolut": ("revolution", "revolutionary", "revolutions")}


def normalise(host: str) -> str:
    """Fold a hostname towards its visual/phonetic skeleton for matching."""
    host = host.lower().lstrip("*.").strip(".")
    if "xn--" in host:                                  # decode homoglyph domains
        try:
            host = host.encode("ascii").decode("idna")
        except (UnicodeError, ValueError):
            pass
    # Strip accents so paypäl folds to paypal
    host = "".join(c for c in unicodedata.normalize("NFKD", host)
                   if not unicodedata.combining(c))
    host = host.translate(FOLD)
    host = re.sub(r"[^a-z0-9.]", "", host)              # drop hyphens, spacing tricks
    for a, b in DIGRAPHS:
        host = host.replace(a, b)
    return host


def normalise_keep_sep(host: str) -> str:
    """Same folding as normalise(), but keeps . - _ so labels stay separable."""
    host = host.lower().lstrip("*.").strip(".")
    if "xn--" in host:
        try:
            host = host.encode("ascii").decode("idna")
        except (UnicodeError, ValueError):
            pass
    host = "".join(c for c in unicodedata.normalize("NFKD", host)
                   if not unicodedata.combining(c))
    host = host.translate(FOLD)
    return re.sub(r"[^a-z0-9.\-_]", "", host)


def edit_distance(a: str, b: str, cap: int = 2) -> int:
    """Levenshtein, abandoned early once it exceeds `cap`."""
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        if min(cur) > cap:
            return cap + 1
        prev = cur
    return prev[-1]


def is_legitimate(host: str) -> bool:
    """True if this is the brand's own domain (or a subdomain of it)."""
    h = host.lower().lstrip("*.").strip(".")
    for _, _, legit in BRANDS:
        for d in legit:
            if h == d or h.endswith("." + d):
                return True
    return False


def match(host: str) -> tuple[str, str] | None:
    """Return (brand_name, why) if this host plausibly targets an Irish brand.

    Two ways to match. A token appearing anywhere in the folded hostname catches
    `aib-secure-login.top`. A near-miss on any single label catches `revolt.com`
    and `revoluts.net`, which contain no exact token at all.
    """
    if is_legitimate(host):
        return None

    folded = normalise(host)
    if not folded:
        return None
    labels = [l for l in folded.split(".") if l]
    # Separator-preserving tokens, so label boundaries survive. Without this,
    # "aib" matches inside "020saibo.com" and short tokens drown the output -
    # they were 61% of hits against a real phishing corpus, nearly all junk.
    parts = set(re.split(r"[.\-_]+", normalise_keep_sep(host)))

    irish = any(h in parts for h in IRISH_HINTS) or host.lower().endswith(".ie")

    for token, name, _ in BRANDS:
        if token in DECOYS and any(d in folded for d in DECOYS[token]):
            continue                      # "revolution" is not Revolut
        if token in GENERIC:
            # Ordinary English word: needs an Irish signal to mean anything,
            # but then may appear inside a label ("mywelfare-ie-login").
            if token in folded and irish:
                return name, f"'{token}' with Irish context"
        elif len(token) < 5:
            # Short tokens must BE a part, never merely appear inside one.
            if token in parts:
                return name, f"'{token}' as a label"
        elif token in folded:
            return name, f"contains '{token}'"

    for token, name, _ in BRANDS:
        # Fuzzy matching scaled to token length. Distance 2 on a 7-letter word
        # matches far too much unrelated traffic ("wolfre" ~ "welfare"), but
        # distance 1 there still catches the punycode lookalikes that were the
        # strongest stratum in calibration ("revlut" ~ "revolut").
        if len(token) < 6 or token in GENERIC:
            continue
        cap = 2 if len(token) >= 8 else 1
        for label in labels:
            if len(label) > len(token) + 3:
                continue                  # long labels: substring test already ran
            if edit_distance(label, token, cap) <= cap:
                return name, f"~'{token}' (edit distance {cap})"
    return None


if __name__ == "__main__":
    for h in ["aib-secure-login.top", "rev0lut-verify.xyz", "an-post.tracking.cc",
              "revolut.com", "www.aib.ie", "anpostt.ie", "xn--revlut-hva.com",
              "google.com", "hse-ie-refund.xyz", "randomshop.ie"]:
        m = match(h)
        print(f"  {h:<32} {'-> ' + m[0] + '  ' + m[1] if m else '(no match)'}")
