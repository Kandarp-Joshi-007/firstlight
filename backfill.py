"""Score a list of known domains through the same pipeline the watcher uses.

Two jobs. It populates the dashboard before the live tail has found anything —
Irish-brand impersonation appears in roughly 1 of every 2,400 domain names, so
a cold start shows nothing for a long time. And it re-verifies the filter and
the model against a corpus whose labels are already known.

Entries are recorded with source "backfill:<name>" rather than a CT log name,
so the dashboard can distinguish them from live detections. Presenting
historical corpus hits as live findings would misstate when they were seen.

    python backfill.py path/to/domains.txt --name phishdb --limit 300
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import brands
import jev as jev_mod
import watch


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("path", type=Path, help="file of domains, one per line")
    ap.add_argument("--name", default="corpus", help="source label")
    ap.add_argument("--limit", type=int, default=300, help="max to score")
    ap.add_argument("--dry-run", action="store_true",
                    help="filter only, do not call Jev or write")
    args = ap.parse_args()

    if not args.path.exists():
        print(f"no such file: {args.path}", file=sys.stderr)
        return 1

    candidates: list[tuple[str, str, str]] = []
    scanned = 0
    for line in args.path.read_text(encoding="utf-8", errors="replace").splitlines():
        domain = line.strip()
        if not domain or "." not in domain:
            continue
        scanned += 1
        hit = brands.match(domain)
        if hit:
            candidates.append((domain, hit[0], hit[1]))

    print(f"scanned {scanned:,} domains -> {len(candidates)} Irish-brand candidates")
    if args.dry_run:
        for d, b, r in candidates[:20]:
            print(f"  {d[:58]:<58} {b}  ({r})")
        return 0

    judge = jev_mod.Jev()
    if not judge.ready:
        print(f"{judge.key_var} not set", file=sys.stderr)
        return 1

    db = watch.connect()
    source = f"backfill:{args.name}"
    counts = {"flagged": 0, "review": 0, "clear": 0, "unknown": 0, "skipped": 0}

    for i, (domain, brand, reason) in enumerate(candidates[:args.limit], 1):
        if db.execute("SELECT 1 FROM detections WHERE domain=?",
                      (domain,)).fetchone():
            counts["skipped"] += 1
            continue
        scored = judge.judge(domain, brand)
        verdict = jev_mod.verdict((scored or {}).get("phishing"))
        counts[verdict] += 1
        db.execute("INSERT OR IGNORE INTO detections VALUES (?,?,?,?,?,?,?,?,?,?)",
                   (domain, brand, reason,
                    (scored or {}).get("phishing"),
                    (scored or {}).get("impersonates"),
                    (scored or {}).get("target"),
                    verdict, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    source, 0))
        if verdict == "flagged":
            print(f"  [flagged] {(scored or {}).get('phishing'):.2f}  "
                  f"{domain[:52]:<52} {brand}")
        if i % 25 == 0:
            db.commit()
    db.commit()

    print(f"\n{counts}")
    print(f"{judge.calls} Jev calls, ${judge.cost:.4f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
