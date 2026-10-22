"""Unit tests for bhft.py - run with:  python -m pytest -v"""
import datetime as dt
import hashlib
import os
import subprocess
import sys

import bhft

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLE = os.path.join(HERE, "samples", "History")


def setup_module(module):
    if not os.path.exists(SAMPLE):
        subprocess.check_call([sys.executable, os.path.join(HERE, "make_sample_db.py")])


def test_webkit_epoch_conversion():
    # 1970-01-01 00:00:00 UTC expressed as WebKit microseconds
    micros = bhft.WEBKIT_EPOCH_DELTA * 1_000_000
    assert bhft.webkit_to_datetime(micros).astimezone(dt.timezone.utc).year == 1970
    assert bhft.webkit_to_datetime(0) is None


def test_sha256_matches_hashlib():
    with open(SAMPLE, "rb") as f:
        expected = hashlib.sha256(f.read()).hexdigest()
    assert bhft.sha256_of_file(SAMPLE) == expected


def test_read_visits_sorted_and_complete():
    visits = bhft.read_visits(SAMPLE)
    assert len(visits) > 0
    times = [v["time"] for v in visits]
    assert times == sorted(times)
    assert all(v["domain"] for v in visits)


def test_downloads_read():
    downloads = bhft.read_downloads(SAMPLE)
    assert len(downloads) == 3
    assert downloads[0]["file"].endswith(".pdf")


def test_keyword_search_case_insensitive():
    visits = bhft.read_visits(SAMPLE)
    assert len(bhft.keyword_hits(visits, "BANK")) == len(bhft.keyword_hits(visits, "bank")) > 0
    assert bhft.keyword_hits(visits, "zzz-not-there") == []


def test_top_domains_order():
    visits = bhft.read_visits(SAMPLE)
    tops = bhft.top_domains(visits, 3)
    assert len(tops) == 3
    assert tops[0][1] >= tops[1][1] >= tops[2][1]


def test_end_to_end_cli(tmp_path):
    out = tmp_path / "out"
    r = subprocess.run([sys.executable, os.path.join(HERE, "bhft.py"), "--db", SAMPLE,
                        "--out", str(out), "--keyword", "bank"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert (out / "report.html").exists()
    assert (out / "timeline.csv").exists()
    assert (out / "History_evidence_copy.db").exists()
    assert "SHA-256" in r.stdout
