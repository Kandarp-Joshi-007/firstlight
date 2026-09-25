"""firstlight - watch Certificate Transparency logs for Irish brand impersonation.

Every HTTPS certificate issued anywhere on earth is published to public
Certificate Transparency logs within seconds. A phishing site needs a
certificate to avoid browser warnings, so its domain appears here before the
scam goes live. That is the early warning.

Pipeline, cheapest stage first:

    CT log  ->  brand pre-filter  ->  Jev  ->  SQLite  ->  dashboard
    208/s        ~0.16% survive      $0.0000125    verdicts
                 (free, local)       per call

Why sampled: a full tail is ~121 GB/day, because most entries are
precertificates whose certificate sits in `extra_data` and cannot be requested
separately. So this stays at the HEAD of the log and processes what bandwidth
allows, skipping forward when it falls behind. Coverage is partial and the
stats command reports exactly how partial - never claim otherwise.

    python watch.py --once          one pass, then exit
    python watch.py                 run continuously
    python watch.py --stats         what has been found so far
    python watch.py --no-jev        filter only, no API calls, no key needed
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import signal
import sqlite3
import struct
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import brands
import jev as jev_mod

LOG_LIST = "https://www.gstatic.com/ct/log_list/v3/log_list.json"
PREFERRED = ("xenon2026h2", "xenon2027h1")     # measured as actively growing
BATCH = 64                                      # entries per get-entries call
DB = Path(__file__).parent / "firstlight.db"
UA = {"User-Agent": "firstlight/0.1 (research; brand-impersonation monitoring)"}

_stop = False


def _on_signal(*_):
    global _stop
    _stop = True
    print("\nstopping after this batch ...", file=sys.stderr)


# ---------------------------------------------------------------------------
# storage
# ---------------------------------------------------------------------------

def connect() -> sqlite3.Connection:
    db = sqlite3.connect(DB)
    db.execute("""CREATE TABLE IF NOT EXISTS detections (
        domain TEXT PRIMARY KEY,
        brand TEXT, reason TEXT,
        phishing REAL, impersonates REAL, target TEXT,
        verdict TEXT,
        first_seen TEXT, log TEXT, log_index INTEGER)""")
    db.execute("""CREATE TABLE IF NOT EXISTS progress (
        log TEXT PRIMARY KEY, position INTEGER, updated TEXT)""")
    db.execute("""CREATE TABLE IF NOT EXISTS runs (
        started TEXT, certs INTEGER, names INTEGER,
        candidates INTEGER, judged INTEGER, cost REAL)""")
    db.execute("CREATE INDEX IF NOT EXISTS idx_verdict ON detections(verdict)")
    db.commit()
    return db


# ---------------------------------------------------------------------------
# certificate transparency
# ---------------------------------------------------------------------------

def fetch(url: str, timeout: int = 30) -> bytes:
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def pick_log() -> tuple[str, str]:
    """Choose an actively-growing log from the authoritative Google list.

    Not hardcoded: log shards are retired and replaced on a schedule, and a
    hardcoded URL silently stops working when that happens.
    """
    data = json.loads(fetch(LOG_LIST))
    found = {}
    for op in data.get("operators", []):
        for log in op.get("logs", []):
            if "usable" not in (log.get("state") or {}):
                continue
            key = log["url"].rstrip("/").rsplit("/", 1)[-1].lower()
            found[key] = (log["description"], log["url"])
    for name in PREFERRED:
        if name in found:
            return found[name]
    raise RuntimeError("no preferred CT log is currently usable")


def tree_size(base: str) -> int:
    return json.loads(fetch(base.rstrip("/") + "/ct/v1/get-sth"))["tree_size"]


def domains_in(entry: dict) -> set[str]:
    """Extract DNS names from one CT log entry.

    Two entry types. An x509_entry carries the certificate inline in
    leaf_input; a precert_entry carries only the TBS portion there, so the
    usable certificate has to come from extra_data instead. Most live entries
    are precerts.
    """
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend

    leaf = base64.b64decode(entry["leaf_input"])
    entry_type = struct.unpack(">H", leaf[10:12])[0]
    if entry_type == 0:
        length = int.from_bytes(leaf[12:15], "big")
        der = leaf[15:15 + length]
    else:
        extra = base64.b64decode(entry["extra_data"])
        length = int.from_bytes(extra[0:3], "big")
        der = extra[3:3 + length]
        inner = int.from_bytes(der[0:3], "big")
        if inner and inner < len(der):
            der = der[3:3 + inner]

    cert = x509.load_der_x509_certificate(der, default_backend())
    names: set[str] = set()
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        names.update(san.value.get_values_for_type(x509.DNSName))
    except Exception:
        pass
    for attr in cert.subject:
        if attr.oid == x509.NameOID.COMMON_NAME and isinstance(attr.value, str):
            names.add(attr.value)
    return names


# ---------------------------------------------------------------------------
# pipeline
# ---------------------------------------------------------------------------

def run_pass(db, judge, base: str, log_name: str, batches: int,
             quiet: bool = False) -> dict:
    head = tree_size(base)
    row = db.execute("SELECT position FROM progress WHERE log=?",
                     (log_name,)).fetchone()
    pos = row[0] if row else head - BATCH * batches

    # Staying at the head matters more than completeness: a detection is only
    # interesting if it beats the blocklists, and that means fresh certificates.
    behind = head - pos
    if behind > BATCH * batches * 3:
        pos = head - BATCH * batches
        if not quiet:
            print(f"  (skipped forward {behind - BATCH * batches:,} entries "
                  f"to stay at the head)")

    stats = {"certs": 0, "names": 0, "candidates": 0, "judged": 0, "new": 0,
             "flagged": 0, "skipped": 0}

    for _ in range(batches):
        if _stop:
            break
        try:
            raw = fetch(f"{base.rstrip('/')}/ct/v1/get-entries"
                        f"?start={pos}&end={pos + BATCH - 1}")
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                time.sleep(2)
                continue
            break
        except (urllib.error.URLError, TimeoutError, OSError):
            break

        entries = json.loads(raw).get("entries", [])
        if not entries:
            break

        for offset, entry in enumerate(entries):
            stats["certs"] += 1
            try:
                names = domains_in(entry)
            except Exception:
                continue
            stats["names"] += len(names)

            for name in names:
                hit = brands.match(name)
                if not hit:
                    continue
                stats["candidates"] += 1
                brand, reason = hit

                if db.execute("SELECT 1 FROM detections WHERE domain=?",
                              (name,)).fetchone():
                    stats["skipped"] += 1
                    continue

                scored = judge.judge(name, brand) if judge.ready else None
                if scored:
                    stats["judged"] += 1
                v = jev_mod.verdict((scored or {}).get("phishing"))
                if v == "flagged":
                    stats["flagged"] += 1

                db.execute(
                    "INSERT OR IGNORE INTO detections VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (name, brand, reason,
                     (scored or {}).get("phishing"),
                     (scored or {}).get("impersonates"),
                     (scored or {}).get("target"),
                     v, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                     log_name, pos + offset))
                stats["new"] += 1
                if not quiet and v in ("flagged", "review"):
                    score = (scored or {}).get("phishing")
                    print(f"  [{v:<7}] {score if score is None else f'{score:.2f}'}"
                          f"  {name[:56]:<56} {brand}")

        pos += len(entries)
        db.execute("INSERT OR REPLACE INTO progress VALUES (?,?,?)",
                   (log_name, pos, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())))
        db.commit()

    return stats


def show_stats(db) -> None:
    total, = db.execute("SELECT COUNT(*) FROM detections").fetchone()
    print(f"\n{'=' * 64}\n  FIRSTLIGHT - {total:,} candidate domains seen\n{'=' * 64}\n")
    if not total:
        print("  nothing yet. run:  python watch.py --once\n")
        return
    print("  by verdict")
    for v, n in db.execute("SELECT verdict, COUNT(*) FROM detections "
                           "GROUP BY verdict ORDER BY 2 DESC"):
        print(f"    {v:<10}{n:>6}")
    print("\n  by brand")
    for b, n in db.execute("SELECT brand, COUNT(*) FROM detections "
                           "GROUP BY brand ORDER BY 2 DESC LIMIT 10"):
        print(f"    {b:<24}{n:>6}")
    print("\n  most recent flagged")
    rows = db.execute("SELECT domain, brand, phishing, target, first_seen "
                      "FROM detections WHERE verdict='flagged' "
                      "ORDER BY first_seen DESC LIMIT 12").fetchall()
    if not rows:
        print("    none yet")
    for d, b, p, t, ts in rows:
        print(f"    {p:.2f}  {d[:48]:<48} {b} / {t}  {ts[:16]}")
    agg = db.execute("SELECT SUM(certs), SUM(names), SUM(candidates), "
                     "SUM(judged), SUM(cost) FROM runs").fetchone()
    if agg and agg[0]:
        certs, names, cands, judged, cost = (x or 0 for x in agg)
        print(f"\n  processed {certs:,} certificates / {names:,} domain names")
        print(f"  {cands:,} reached the filter, {judged:,} judged, "
              f"${cost:.4f} spent")
        print(f"\n  COVERAGE: the log runs at ~208 certs/sec. This sample is "
              f"partial\n  by design - see README. Do not report it as "
              f"complete coverage.")
    print()


def export_site(db, path: Path) -> None:
    """Write the dashboard's data file.

    Committed to git by CI, which makes the commit timestamp an independent
    record of when each domain was detected - the evidence behind any
    "flagged N hours before the blocklists" claim.
    """
    rows = db.execute(
        "SELECT domain, brand, reason, phishing, target, verdict, first_seen, log "
        "FROM detections WHERE verdict IN ('flagged','review') "
        "ORDER BY first_seen DESC LIMIT 500").fetchall()
    agg = db.execute("SELECT SUM(certs), SUM(names), SUM(candidates), "
                     "SUM(judged), SUM(cost) FROM runs").fetchone() or (0,) * 5
    counts = dict(db.execute("SELECT verdict, COUNT(*) FROM detections "
                             "GROUP BY verdict").fetchall())
    # Derive "scored" from the detections themselves. Taking it from `runs`
    # undercounts anything backfill.py added and makes the header contradict
    # the table below it.
    judged, = db.execute("SELECT COUNT(*) FROM detections "
                         "WHERE phishing IS NOT NULL").fetchone()
    payload = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "totals": {
            "certificates": agg[0] or 0, "names": agg[1] or 0,
            "candidates": agg[2] or 0, "judged": judged,
            "cost_usd": round(agg[4] or 0.0, 4),
            "flagged": counts.get("flagged", 0),
            "review": counts.get("review", 0),
        },
        # `source` distinguishes a live CT sighting from a scored corpus entry.
        # Without it the page would imply every row was seen on the wire.
        "detections": [
            {"domain": d, "brand": b, "reason": r, "score": p,
             "target": t, "verdict": v, "seen": s,
             "source": "backfill" if str(g).startswith("backfill") else "live"}
            for d, b, r, p, t, v, s, g in rows
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=1), encoding="utf-8")
    print(f"  exported {len(rows)} detections -> {path}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--once", action="store_true", help="one pass then exit")
    ap.add_argument("--stats", action="store_true", help="show what was found")
    ap.add_argument("--export", metavar="PATH", nargs="?",
                    const="site/data.json",
                    help="write the dashboard data file and exit")
    ap.add_argument("--batches", type=int, default=8,
                    help=f"get-entries calls per pass ({BATCH} certs each)")
    ap.add_argument("--interval", type=int, default=60,
                    help="seconds between passes in continuous mode")
    ap.add_argument("--no-jev", action="store_true",
                    help="filter only, no API calls")
    args = ap.parse_args()

    db = connect()
    if args.stats:
        show_stats(db)
        return 0
    if args.export:
        export_site(db, Path(__file__).parent / args.export)
        return 0

    signal.signal(signal.SIGINT, _on_signal)
    judge = jev_mod.Jev()
    if args.no_jev:
        judge.key = None
    elif not judge.ready:
        print(f"{judge.key_var} not set - running filter-only.\n"
              f"  PowerShell:  $env:{judge.key_var} = '...'", file=sys.stderr)

    desc, base = pick_log()
    log_name = base.rstrip("/").rsplit("/", 1)[-1]
    print(f"watching {desc}\n  {base}")
    print(f"  {args.batches} batches x {BATCH} = ~{args.batches * BATCH} certs/pass"
          f"{'' if judge.ready else '   (no Jev key - filter only)'}\n")

    while not _stop:
        started = time.time()
        s = run_pass(db, judge, base, log_name, args.batches)
        db.execute("INSERT INTO runs VALUES (?,?,?,?,?,?)",
                   (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    s["certs"], s["names"], s["candidates"], s["judged"],
                    judge.cost))
        db.commit()
        print(f"  pass: {s['certs']:,} certs, {s['names']:,} names, "
              f"{s['candidates']} candidates, {s['new']} new, "
              f"{s['flagged']} flagged  [{time.time() - started:.0f}s]")
        if args.once or _stop:
            break
        time.sleep(args.interval)

    if judge.calls:
        print(f"\n{judge.calls} Jev calls, ${judge.cost:.4f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
