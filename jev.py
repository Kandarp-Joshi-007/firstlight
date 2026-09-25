"""Jev client - typed decisions about whether a domain impersonates a brand.

Routed through OpenRouter because TypeSafe paused direct signups on 2026-09-22.
Jev is not a chat model: it is absent from /v1/models and rejected by
/chat/completions. It lives at its own decisions endpoint.

Thresholds below come from a 2,000-domain calibration run (see README):
at 0.7 the measured precision was 97%, with no legitimate domain in the sample
scoring above 0.65.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

PROVIDERS = {
    "openrouter": ("https://openrouter.ai/api/alpha/decisions",
                   "typesafe/jev-1.13", "OPENROUTER_API_KEY"),
    "typesafe": ("https://api.typesafe.ai/v1/systemone",
                 "jev-1", "TYPESAFE_API_KEY"),
}

# Measured operating points, not guesses. See README "Calibration".
FLAG = 0.70        # publish as a candidate
REVIEW = 0.50      # hold for human review
RATE_PER_SEC = 15  # documented cap is 20/s; leave headroom

QUESTIONS = {
    "phishing": {
        "type": "noul",
        "instructions": "Is this domain name likely used for phishing, fraud, "
                        "or impersonation of a real organisation?",
    },
    "impersonates": {
        "type": "noul",
        "instructions": "Does this domain name imitate a known brand, bank, "
                        "payment service, government body or cloud provider?",
    },
    "target": {
        "type": "choice",
        "instructions": "If it imitates something, what kind of organisation?",
        "criteria": {
            "bank": "a bank or financial institution",
            "payment": "a payment or crypto service",
            "cloud": "a cloud, email or tech provider",
            "shipping": "a courier or postal service",
            "government": "a government or tax authority",
            "health": "a health service or insurer",
            "none": "it does not imitate any organisation",
        },
    },
}


class Jev:
    def __init__(self, provider: str | None = None):
        name = provider or os.environ.get("JEV_PROVIDER", "openrouter")
        self.url, self.model, key_var = PROVIDERS[name]
        self.key = os.environ.get(key_var)
        self.key_var = key_var
        self._next = 0.0
        self.auth_failed = False
        self.calls = 0
        self.cost = 0.0

    @property
    def ready(self) -> bool:
        return bool(self.key)

    def _throttle(self) -> None:
        now = time.monotonic()
        if now < self._next:
            time.sleep(self._next - now)
        self._next = max(now, self._next) + 1.0 / RATE_PER_SEC

    def judge(self, domain: str, brand: str, retries: int = 3) -> dict | None:
        """Score one domain. Returns None on failure - never raises.

        A watcher that dies because one HTTP call failed is useless, so every
        error path here degrades to "no verdict" and the caller moves on.
        """
        if not self.key:
            return None
        body = json.dumps({
            "model": self.model,
            "state": f"Domain name: {domain}\nSuspected target brand: {brand}",
            "questions": QUESTIONS,
        }).encode()

        for attempt in range(retries):
            self._throttle()
            req = urllib.request.Request(
                self.url, data=body,
                headers={"Authorization": f"Bearer {self.key}",
                         "Content-Type": "application/json"},
                method="POST")
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    out = json.loads(resp.read().decode())
                self.calls += 1
                self.cost += (out.get("usage") or {}).get("cost", 0.0)
                answers = out.get("answers") or {}
                return {
                    "phishing": (answers.get("phishing") or {}).get("noul"),
                    "impersonates": (answers.get("impersonates") or {}).get("noul"),
                    "target": (answers.get("target") or {}).get("choice"),
                }
            except urllib.error.HTTPError as exc:
                if exc.code in (401, 403):
                    # Fail loudly and once. Silently returning None here means
                    # the watcher runs for hours emitting "unknown" verdicts
                    # while the real problem is a dead key.
                    if not self.auth_failed:
                        self.auth_failed = True
                        detail = exc.read().decode("utf-8", "replace")[:160]
                        print(f"\n  !! {self.key_var} rejected ({exc.code}): "
                              f"{detail}\n     Jev scoring is DISABLED for this "
                              f"run; the filter still works.\n", file=sys.stderr)
                    self.key = None
                    return None
                if exc.code in (429, 500, 502, 503) and attempt < retries - 1:
                    time.sleep(2 ** attempt)
                    continue
                return None
            except (urllib.error.URLError, TimeoutError, OSError, ValueError):
                if attempt < retries - 1:
                    time.sleep(2 ** attempt)
                    continue
                return None
        return None


def verdict(score: float | None) -> str:
    if score is None:
        return "unknown"
    if score >= FLAG:
        return "flagged"
    if score >= REVIEW:
        return "review"
    return "clear"
