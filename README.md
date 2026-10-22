# Browser History Forensic Analysis Tool (BHFT)

A simple digital-forensics tool, written in pure Python (standard library only),
that acquires and analyses the browsing history of Chromium-based browsers
(Google Chrome, Microsoft Edge, Brave).

Mini project for **Cyber Security and Digital Forensics (CSDF)**, Laboratory Practice IV,
BE Computer Engineering, Savitribai Phule Pune University.

## What it does

1. **Acquire** – copies the browser's `History` SQLite file (the live file is locked by
   the browser) and records its SHA-256 hash so integrity can be proven later.
2. **Parse** – reads the `urls`, `visits` and `downloads` tables and converts Chromium's
   WebKit timestamps (microseconds since 1601-01-01) to normal local date-times.
3. **Analyse** – builds a chronological timeline, counts the most visited domains,
   shows daily activity and searches for a keyword in URLs and page titles.
4. **Report** – writes `timeline.csv`, `downloads.csv` and a self-contained `report.html`.

## Quick start

```bash
# create a demo History database (no real user data needed)
python make_sample_db.py

# analyse the demo database and search for the keyword "bank"
python bhft.py --db samples/History --out output --keyword bank

# analyse the real Microsoft Edge / Google Chrome history of the current user
python bhft.py --browser edge
python bhft.py --browser chrome --keyword invoice
```

Open `output/report.html` in any browser to see the report.

## Options

| Option | Meaning |
|---|---|
| `--browser chrome\|edge\|brave` | read that browser's default History file |
| `--db PATH` | read any History file (e.g. one copied from a seized machine) |
| `--out DIR` | output folder (default `output`) |
| `--keyword WORD` | case-insensitive search in URLs and titles |
| `--top N` | number of top domains to list (default 10) |

## Tests

```bash
pip install pytest
python -m pytest -v
```

## Project structure

```
bhft.py             the tool (single file, ~280 lines)
make_sample_db.py   generates samples/History for demos and tests
test_bhft.py        unit + end-to-end tests (pytest)
report/             LaTeX project report (SPPU BE format)
```

## Requirements

Python 3.9 or newer. No third-party packages are required to run the tool.
