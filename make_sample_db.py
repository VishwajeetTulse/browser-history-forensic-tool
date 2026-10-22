"""
Creates samples/History - a small SQLite database in the same schema that
Google Chrome / Microsoft Edge use, so the tool can be demonstrated and
tested without touching a real user's browser data.
"""
import datetime as dt
import os
import random
import sqlite3

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples", "History")
WEBKIT_EPOCH_DELTA = 11644473600


def to_webkit(d):
    return int((d.timestamp() + WEBKIT_EPOCH_DELTA) * 1_000_000)


SITES = [
    ("https://www.google.com/search?q=python+sqlite", "python sqlite - Google Search"),
    ("https://docs.python.org/3/library/sqlite3.html", "sqlite3 - DB-API 2.0 interface"),
    ("https://github.com/", "GitHub"),
    ("https://stackoverflow.com/questions/tagged/python", "Newest python Questions"),
    ("https://www.youtube.com/watch?v=dQw4w9WgXcQ", "YouTube"),
    ("https://mail.google.com/mail/u/0/", "Inbox - Gmail"),
    ("https://www.amazon.in/", "Amazon.in"),
    ("https://netbanking.examplebank.com/login", "Example Bank - Net Banking Login"),
    ("https://netbanking.examplebank.com/transfer", "Example Bank - Fund Transfer"),
    ("https://www.wikipedia.org/", "Wikipedia"),
    ("https://en.wikipedia.org/wiki/Digital_forensics", "Digital forensics - Wikipedia"),
    ("https://www.sppu.in/", "Savitribai Phule Pune University"),
    ("https://drive.google.com/drive/my-drive", "My Drive - Google Drive"),
    ("https://www.linkedin.com/feed/", "Feed | LinkedIn"),
    ("https://chat.openai.com/", "ChatGPT"),
]


def main():
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    if os.path.exists(OUT):
        os.remove(OUT)
    con = sqlite3.connect(OUT)
    con.executescript(
        """
        CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT,
            visit_count INTEGER DEFAULT 0, typed_count INTEGER DEFAULT 0,
            last_visit_time INTEGER, hidden INTEGER DEFAULT 0);
        CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER,
            from_visit INTEGER, transition INTEGER, segment_id INTEGER,
            visit_duration INTEGER);
        CREATE TABLE downloads(id INTEGER PRIMARY KEY, target_path TEXT,
            tab_url TEXT, start_time INTEGER, received_bytes INTEGER,
            total_bytes INTEGER);
        """
    )
    random.seed(7)
    for i, (url, title) in enumerate(SITES, 1):
        con.execute("INSERT INTO urls(id,url,title,visit_count,typed_count) VALUES(?,?,?,?,?)",
                    (i, url, title, 0, random.randint(0, 3)))

    start = dt.datetime(2026, 10, 13, 9, 0, 0)
    vid = 1
    for day in range(5):
        t = start + dt.timedelta(days=day)
        for _ in range(random.randint(8, 14)):
            t += dt.timedelta(minutes=random.randint(3, 50))
            uid = random.randint(1, len(SITES))
            con.execute("INSERT INTO visits(id,url,visit_time,from_visit,transition,segment_id,visit_duration)"
                        " VALUES(?,?,?,?,?,?,?)", (vid, uid, to_webkit(t), 0, 805306368, 0, 0))
            con.execute("UPDATE urls SET visit_count=visit_count+1, last_visit_time=? WHERE id=?",
                        (to_webkit(t), uid))
            vid += 1

    downloads = [
        (r"C:\Users\student\Downloads\sqlite3_manual.pdf", "https://docs.python.org/3/library/sqlite3.html",
         start + dt.timedelta(days=1, hours=2), 482311),
        (r"C:\Users\student\Downloads\statement_sep2026.pdf", "https://netbanking.examplebank.com/transfer",
         start + dt.timedelta(days=2, hours=5), 120450),
        (r"C:\Users\student\Downloads\setup_tool.exe", "https://github.com/",
         start + dt.timedelta(days=4, hours=1), 9833120),
    ]
    for i, (path, url, when, size) in enumerate(downloads, 1):
        con.execute("INSERT INTO downloads VALUES(?,?,?,?,?,?)", (i, path, url, to_webkit(when), size, size))
    con.commit()
    con.close()
    print(f"Sample database written to {OUT} with {vid - 1} visits and {len(downloads)} downloads")


if __name__ == "__main__":
    main()
