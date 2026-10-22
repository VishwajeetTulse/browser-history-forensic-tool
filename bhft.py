#!/usr/bin/env python3
"""
Browser History Forensic Analysis Tool (BHFT)

A small digital-forensics utility that reads the SQLite "History" database
used by Chromium-based browsers (Google Chrome, Microsoft Edge, Brave),
preserves the evidence with SHA-256 hashes, and produces:

  * a chronological timeline of visited URLs
  * a list of downloaded files
  * top visited domains
  * keyword search hits
  * a CSV export and a self-contained HTML report

Only the Python standard library is used, so the tool runs anywhere Python 3
is available.

Usage examples
--------------
    python bhft.py --browser edge
    python bhft.py --browser chrome --keyword bank
    python bhft.py --db samples/History --out output
"""

import argparse
import csv
import datetime as dt
import hashlib
import html
import os
import platform
import shutil
import sqlite3
import sys
from collections import Counter
from urllib.parse import urlparse

# --------------------------------------------------------------------------
# 1. Evidence acquisition helpers
# --------------------------------------------------------------------------

def default_history_path(browser):
    """Return the default location of the History file for a browser on
    the current operating system."""
    home = os.path.expanduser("~")
    local = os.environ.get("LOCALAPPDATA", os.path.join(home, "AppData", "Local"))
    paths = {
        "chrome": os.path.join(local, "Google", "Chrome", "User Data", "Default", "History"),
        "edge":   os.path.join(local, "Microsoft", "Edge", "User Data", "Default", "History"),
        "brave":  os.path.join(local, "BraveSoftware", "Brave-Browser", "User Data", "Default", "History"),
    }
    if sys.platform.startswith("linux"):
        paths = {
            "chrome": os.path.join(home, ".config", "google-chrome", "Default", "History"),
            "edge":   os.path.join(home, ".config", "microsoft-edge", "Default", "History"),
            "brave":  os.path.join(home, ".config", "BraveSoftware", "Brave-Browser", "Default", "History"),
        }
    elif sys.platform == "darwin":
        lib = os.path.join(home, "Library", "Application Support")
        paths = {
            "chrome": os.path.join(lib, "Google", "Chrome", "Default", "History"),
            "edge":   os.path.join(lib, "Microsoft Edge", "Default", "History"),
            "brave":  os.path.join(lib, "BraveSoftware", "Brave-Browser", "Default", "History"),
        }
    return paths[browser]


def sha256_of_file(path):
    """Compute the SHA-256 digest of a file (read in 1 MB chunks)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def acquire_evidence(src, out_dir):
    """Copy the live History file into the output folder (the browser keeps
    the original locked) and verify the copy with SHA-256."""
    os.makedirs(out_dir, exist_ok=True)
    dst = os.path.join(out_dir, "History_evidence_copy.db")
    shutil.copy2(src, dst)
    src_hash = sha256_of_file(src)
    dst_hash = sha256_of_file(dst)
    if src_hash != dst_hash:
        raise RuntimeError("Hash mismatch after copy: evidence integrity cannot be guaranteed")
    return dst, src_hash


# --------------------------------------------------------------------------
# 2. Parsing helpers
# --------------------------------------------------------------------------

WEBKIT_EPOCH_DELTA = 11644473600  # seconds between 1601-01-01 and 1970-01-01


def webkit_to_datetime(micros):
    """Chromium stores times as microseconds since 1601-01-01 UTC."""
    if not micros:
        return None
    seconds = micros / 1_000_000 - WEBKIT_EPOCH_DELTA
    return dt.datetime.fromtimestamp(seconds, dt.timezone.utc).astimezone()


def read_visits(db_path):
    """Return a list of visit dictionaries ordered by time."""
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    rows = con.execute(
        """
        SELECT v.visit_time, u.url, u.title, u.visit_count, u.typed_count
        FROM visits v JOIN urls u ON v.url = u.id
        ORDER BY v.visit_time
        """
    ).fetchall()
    con.close()
    visits = []
    for visit_time, url, title, visit_count, typed_count in rows:
        when = webkit_to_datetime(visit_time)
        visits.append({
            "time": when.strftime("%Y-%m-%d %H:%M:%S") if when else "",
            "url": url,
            "title": title or "",
            "domain": urlparse(url).netloc,
            "visit_count": visit_count,
            "typed_count": typed_count,
        })
    return visits


def read_downloads(db_path):
    """Return downloaded files with their source URL and timestamps."""
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        rows = con.execute(
            "SELECT target_path, tab_url, start_time, received_bytes FROM downloads ORDER BY start_time"
        ).fetchall()
    except sqlite3.OperationalError:
        rows = []
    con.close()
    downloads = []
    for target, url, start, size in rows:
        when = webkit_to_datetime(start)
        downloads.append({
            "time": when.strftime("%Y-%m-%d %H:%M:%S") if when else "",
            "file": target,
            "url": url or "",
            "bytes": size,
        })
    return downloads


# --------------------------------------------------------------------------
# 3. Analysis helpers
# --------------------------------------------------------------------------

def top_domains(visits, n=10):
    return Counter(v["domain"] for v in visits if v["domain"]).most_common(n)


def keyword_hits(visits, keyword):
    k = keyword.lower()
    return [v for v in visits if k in v["url"].lower() or k in v["title"].lower()]


def daily_activity(visits):
    return sorted(Counter(v["time"][:10] for v in visits if v["time"]).items())


# --------------------------------------------------------------------------
# 4. Reporting helpers
# --------------------------------------------------------------------------

def write_csv(rows, path, fields):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def write_html_report(out_dir, meta, visits, downloads, domains, hits, days):
    e = html.escape
    parts = ["<!doctype html><html><head><meta charset='utf-8'>",
             "<title>Browser History Forensic Report</title>",
             "<style>body{font-family:Segoe UI,Arial;margin:30px;color:#222}"
             "table{border-collapse:collapse;width:100%;margin-bottom:24px;font-size:13px}"
             "th,td{border:1px solid #bbb;padding:4px 6px;text-align:left;vertical-align:top}"
             "th{background:#e8eef7}h1{color:#1a3d7c}h2{border-bottom:2px solid #1a3d7c}"
             ".meta td:first-child{font-weight:bold;width:220px}</style></head><body>",
             "<h1>Browser History Forensic Analysis Report</h1>",
             "<h2>1. Evidence Details</h2><table class='meta'>"]
    for k, v in meta.items():
        parts.append(f"<tr><td>{e(k)}</td><td>{e(str(v))}</td></tr>")
    parts.append("</table>")

    parts.append("<h2>2. Summary</h2><table class='meta'>")
    parts.append(f"<tr><td>Total visits</td><td>{len(visits)}</td></tr>")
    parts.append(f"<tr><td>Unique URLs</td><td>{len({v['url'] for v in visits})}</td></tr>")
    parts.append(f"<tr><td>Unique domains</td><td>{len({v['domain'] for v in visits})}</td></tr>")
    parts.append(f"<tr><td>Downloads</td><td>{len(downloads)}</td></tr>")
    if visits:
        parts.append(f"<tr><td>First visit</td><td>{e(visits[0]['time'])}</td></tr>")
        parts.append(f"<tr><td>Last visit</td><td>{e(visits[-1]['time'])}</td></tr>")
    parts.append("</table>")

    parts.append("<h2>3. Top Visited Domains</h2><table><tr><th>#</th><th>Domain</th><th>Visits</th></tr>")
    for i, (d, c) in enumerate(domains, 1):
        parts.append(f"<tr><td>{i}</td><td>{e(d)}</td><td>{c}</td></tr>")
    parts.append("</table>")

    parts.append("<h2>4. Daily Activity</h2><table><tr><th>Date</th><th>Visits</th></tr>")
    for d, c in days:
        parts.append(f"<tr><td>{e(d)}</td><td>{c}</td></tr>")
    parts.append("</table>")

    if meta.get("Keyword"):
        parts.append(f"<h2>5. Keyword Hits for '{e(meta['Keyword'])}' ({len(hits)})</h2>")
        parts.append("<table><tr><th>Time</th><th>Title</th><th>URL</th></tr>")
        for v in hits:
            parts.append(f"<tr><td>{e(v['time'])}</td><td>{e(v['title'])}</td><td>{e(v['url'])}</td></tr>")
        parts.append("</table>")

    parts.append("<h2>6. Downloads</h2><table><tr><th>Time</th><th>File</th><th>Source URL</th><th>Bytes</th></tr>")
    for d in downloads:
        parts.append(f"<tr><td>{e(d['time'])}</td><td>{e(d['file'])}</td><td>{e(d['url'])}</td><td>{d['bytes']}</td></tr>")
    parts.append("</table>")

    parts.append("<h2>7. Full Timeline</h2><table><tr><th>#</th><th>Time</th><th>Title</th><th>URL</th><th>Visits</th><th>Typed</th></tr>")
    for i, v in enumerate(visits, 1):
        parts.append(f"<tr><td>{i}</td><td>{e(v['time'])}</td><td>{e(v['title'])}</td>"
                     f"<td>{e(v['url'])}</td><td>{v['visit_count']}</td><td>{v['typed_count']}</td></tr>")
    parts.append("</table></body></html>")

    path = os.path.join(out_dir, "report.html")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(parts))
    return path


# --------------------------------------------------------------------------
# 5. Main program
# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Browser History Forensic Analysis Tool")
    ap.add_argument("--browser", choices=["chrome", "edge", "brave"],
                    help="read the default History file of this browser")
    ap.add_argument("--db", help="path to a History SQLite file (overrides --browser)")
    ap.add_argument("--out", default="output", help="output folder (default: output)")
    ap.add_argument("--keyword", help="search URLs and titles for this keyword")
    ap.add_argument("--top", type=int, default=10, help="number of top domains to show")
    args = ap.parse_args()

    if not args.db and not args.browser:
        ap.error("give --browser or --db")
    src = args.db or default_history_path(args.browser)
    if not os.path.exists(src):
        sys.exit(f"History file not found: {src}")

    print("=" * 70)
    print(" Browser History Forensic Analysis Tool")
    print("=" * 70)

    # Step 1 - acquire
    print(f"[1] Acquiring evidence from: {src}")
    copy, digest = acquire_evidence(src, args.out)
    print(f"    SHA-256 : {digest}")
    print(f"    Working copy saved to: {copy}")

    # Step 2 - parse
    print("[2] Parsing history database ...")
    visits = read_visits(copy)
    downloads = read_downloads(copy)
    print(f"    {len(visits)} visits, {len(downloads)} downloads found")

    # Step 3 - analyse
    print("[3] Analysing ...")
    domains = top_domains(visits, args.top)
    hits = keyword_hits(visits, args.keyword) if args.keyword else []
    days = daily_activity(visits)

    print(f"\n    Top {args.top} domains:")
    for d, c in domains:
        print(f"      {c:5d}  {d}")
    if visits:
        print(f"\n    Activity window: {visits[0]['time']}  ->  {visits[-1]['time']}")
    if args.keyword:
        print(f"\n    Keyword '{args.keyword}': {len(hits)} hit(s)")
        for v in hits[:10]:
            print(f"      {v['time']}  {v['url']}")

    # Step 4 - report
    print("\n[4] Writing reports ...")
    write_csv(visits, os.path.join(args.out, "timeline.csv"),
              ["time", "url", "title", "domain", "visit_count", "typed_count"])
    write_csv(downloads, os.path.join(args.out, "downloads.csv"), ["time", "file", "url", "bytes"])
    meta = {
        "Source file": src,
        "SHA-256 of evidence": digest,
        "Acquired on": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Examiner machine": platform.node(),
        "Keyword": args.keyword or "",
    }
    report = write_html_report(args.out, meta, visits, downloads, domains, hits, days)
    print(f"    timeline.csv, downloads.csv and report.html written to '{args.out}'")
    print(f"    Open: {os.path.abspath(report)}")
    print("Done.")


if __name__ == "__main__":
    main()
