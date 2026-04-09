#!/usr/bin/env python3
"""
Security News Collector — MongoDB edition
Collects global security news from RSS/Atom feeds.

Usage:
  python3 security_news.py fetch [--source NAME]
  python3 security_news.py list  [--search TEXT] [--source NAME] [--since YYYY-MM-DD] [--limit N]
  python3 security_news.py stats
  python3 security_news.py export [--output FILE]
  python3 security_news.py sources
"""

import os
import json
import argparse
import sys
import re
from datetime import datetime, timezone, timedelta
from typing import Optional
import urllib.request
import urllib.error
import urllib.parse
import http.cookiejar
import xml.etree.ElementTree as ET

from pymongo import MongoClient, DESCENDING, ASCENDING
from pymongo.errors import DuplicateKeyError

# ─── Config ───────────────────────────────────────────────────────────────────

MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
DB_NAME   = os.environ.get("MONGO_DB",  "secnews")

DEFAULT_FEEDS = {
    "Krebs on Security":       "https://krebsonsecurity.com/feed/",
    "The Hacker News":         "https://feeds.feedburner.com/TheHackersNews",
    "BleepingComputer":        "https://www.bleepingcomputer.com/feed/",
    "SecurityWeek":            "https://feeds.feedburner.com/securityweek",
    "Dark Reading":            "https://www.darkreading.com/rss.xml",
    "Threatpost":              "https://threatpost.com/feed/",
    "Graham Cluley":           "https://grahamcluley.com/feed/",
    "CISA Advisories":         "https://www.cisa.gov/feeds/hsfeed.xml",
    "US-CERT":                 "https://www.cisa.gov/uscert/ncas/alerts.xml",
    "NVD Recent CVEs":         "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml",
    "Schneier on Security":    "https://www.schneier.com/feed/atom/",
    "Help Net Security":       "https://www.helpnetsecurity.com/feed/",
    "Infosecurity Magazine":   "https://www.infosecurity-magazine.com/rss/news/",
    "SANS Internet Stormcast": "https://isc.sans.edu/rssfeed_full.xml",
    "TechTalkThai Security":   "https://www.techtalkthai.com/category/security/feed/",
}

# ─── DB helpers ───────────────────────────────────────────────────────────────

def get_db():
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    return client[DB_NAME]


# ─── Date helpers ─────────────────────────────────────────────────────────────

# Common timezone abbreviation → UTC offset in minutes
_TZ = {
    "EDT": -240, "EST": -300, "CDT": -300, "CST": -360,
    "MDT": -360, "MST": -420, "PDT": -420, "PST": -480,
    "GMT": 0,    "UTC": 0,    "UT":  0,    "Z":   0,
    "BST": 60,   "CET": 60,   "CEST": 120, "EET": 120, "EEST": 180,
    "ICT": 420,  "SGT": 480,  "JST": 540,  "KST": 540,
    "AEST": 600, "AEDT": 660, "NZST": 720, "NZDT": 780,
    "IST": 330,  "WIB": 420,  "WIT": 540,
}
_MONTHS = {"Jan":1,"Feb":2,"Mar":3,"Apr":4,"May":5,"Jun":6,
           "Jul":7,"Aug":8,"Sep":9,"Oct":10,"Nov":11,"Dec":12}


def to_datetime(text: Optional[str]) -> Optional[datetime]:
    """Parse date string to UTC datetime object (for MongoDB Date storage)."""
    if not text:
        return None
    text = text.strip()

    # ISO 8601
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.strptime(text, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).replace(tzinfo=None)
        except ValueError:
            pass

    # RFC 2822: "Tue, 29 Jul 2025 13:53:52 EDT" or "29 Jul 2025 13:53:52 +0000"
    m = re.match(
        r'(?:\w+,\s+)?(\d{1,2})\s+(\w{3})\s+(\d{4})\s+(\d{2}):(\d{2}):(\d{2})\s+([+-]\d{4}|\w+)$',
        text,
    )
    if m:
        day, mon_s, yr, h, mi, s, tz_s = m.groups()
        mon = _MONTHS.get(mon_s)
        if mon:
            try:
                if tz_s.startswith(("+", "-")):
                    sign   = 1 if tz_s[0] == "+" else -1
                    offset = timedelta(hours=int(tz_s[1:3]), minutes=int(tz_s[3:5])) * sign
                else:
                    offset = timedelta(minutes=_TZ.get(tz_s, 0))
                tz_obj = timezone(offset)
                dt = datetime(int(yr), mon, int(day), int(h), int(mi), int(s), tzinfo=tz_obj)
                return dt.astimezone(timezone.utc).replace(tzinfo=None)
            except (ValueError, OverflowError):
                pass
    return None


def init_collections(db) -> None:
    """Create indexes and seed default feeds if first run."""
    db.articles.create_index("url",    unique=True)
    db.articles.create_index([("published_dt", DESCENDING)])
    db.articles.create_index([("fetched_at",   DESCENDING)])
    db.articles.create_index("source")

    db.feeds.create_index("name", unique=True)

    if db.feeds.count_documents({}) == 0:
        now = datetime.now(timezone.utc)
        db.feeds.insert_many([
            {"name": name, "url": url, "enabled": True,
             "last_fetch": None, "created_at": now}
            for name, url in DEFAULT_FEEDS.items()
        ])
        print(f"  Seeded {len(DEFAULT_FEEDS)} default feeds.")


# ─── RSS fetching ─────────────────────────────────────────────────────────────

_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/131.0.0.0 Safari/537.36",
    "Accept": "application/rss+xml, application/xml, text/xml, */*",
    "Accept-Language": "en-US,en;q=0.9,th;q=0.8",
}


def fetch_url(url: str, timeout: int = 15) -> Optional[bytes]:
    """Fetch URL with cookie support and retry for WAF challenges (Incapsula)."""
    import time

    # [SECURITY] Only allow http/https to prevent SSRF via file:// etc.
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        print(f"  [WARN] Blocked non-http(s) URL scheme: {parsed.scheme}://{parsed.netloc}",
              file=sys.stderr)
        return None

    cj     = http.cookiejar.CookieJar()
    handlers = [urllib.request.HTTPCookieProcessor(cj)]
    opener   = urllib.request.build_opener(*handlers)

    for attempt in range(3):
        req = urllib.request.Request(url, headers=_HEADERS)
        try:
            with opener.open(req, timeout=timeout) as resp:
                # [SECURITY] Cap read size to 5MB to prevent OOM / XML bombs
                data = resp.read(5 * 1024 * 1024)
            # Check if we got a WAF challenge page instead of real content
            if b'<rss' in data[:500] or b'<feed' in data[:500] or b'<?xml' in data[:200]:
                return data
            # Incapsula challenge — cookies set, retry
            if b'Incapsula' in data or b'_Incapsula_Resource' in data:
                print(f"  [INFO] WAF challenge detected for {url}, retrying ({attempt+1}/3)…",
                      file=sys.stderr)
                time.sleep(1.5)
                continue
            # Unknown HTML — return as-is (parser will handle error)
            return data
        except urllib.error.HTTPError as e:
            print(f"  [WARN] HTTP {e.code} for {url} (attempt {attempt+1})", file=sys.stderr)
            if attempt < 2:
                time.sleep(1)
                continue
            return None
        except urllib.error.URLError as e:
            reason = str(e.reason) if hasattr(e, 'reason') else str(e)
            print(f"  [WARN] URLError for {url}: {reason} (attempt {attempt+1})", file=sys.stderr)
            # [SECURITY] Do NOT silently disable SSL verification — log and skip instead
            if 'CERTIFICATE_VERIFY_FAILED' in reason or 'SSL' in reason:
                print(
                    f"  [WARN] SSL certificate error for {url} — skipping (certificate validation "
                    f"is required for security). Verify the feed URL is correct.",
                    file=sys.stderr,
                )
                return None
            if attempt < 2:
                time.sleep(1)
                continue
            return None
        except Exception as e:
            print(f"  [WARN] {type(e).__name__}: {e} for {url}", file=sys.stderr)
            return None
    print(f"  [WARN] WAF challenge not resolved after retries: {url}", file=sys.stderr)
    return None


def parse_date(text: Optional[str]) -> Optional[str]:
    if not text:
        return None
    text = text.strip()
    for fmt in (
        "%a, %d %b %Y %H:%M:%S %z",
        "%a, %d %b %Y %H:%M:%S %Z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d %H:%M:%S",
    ):
        try:
            dt = datetime.strptime(text, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.isoformat()
        except ValueError:
            continue
    return text


def strip_tags(text: Optional[str]) -> str:
    if not text:
        return ""
    clean = re.sub(r"<[^>]+>", " ", text)
    clean = re.sub(r"\s+", " ", clean).strip()
    return clean[:500]


def parse_rss(data: bytes, source: str) -> list[dict]:
    _MAX_ARTICLES = 500  # [SECURITY] Cap articles per feed to prevent memory exhaustion
    articles = []
    try:
        root = ET.fromstring(data)
    except ET.ParseError as e:
        print(f"  [WARN] XML parse error for {source}: {e}", file=sys.stderr)
        return articles

    ns = {"atom": "http://www.w3.org/2005/Atom"}

    def _safe_url(u: str) -> str:
        """Return url only if it has http/https scheme, else empty string."""
        u = (u or "").strip()
        p = urllib.parse.urlparse(u)
        return u if p.scheme in ("http", "https") else ""

    # Atom
    if root.tag == "{http://www.w3.org/2005/Atom}feed":
        for entry in root.findall("atom:entry", ns):
            if len(articles) >= _MAX_ARTICLES:
                break
            title_el   = entry.find("atom:title",   ns)
            link_el    = entry.find("atom:link",    ns)
            summary_el = entry.find("atom:summary", ns) or entry.find("atom:content", ns)
            date_el    = entry.find("atom:published", ns) or entry.find("atom:updated", ns)
            url = ""
            if link_el is not None:
                url = link_el.get("href", link_el.text or "")
            url = _safe_url(url)   # [SECURITY] validate URL scheme
            if not url:
                continue
            articles.append({
                "source":    source,
                "title":     strip_tags(title_el.text if title_el is not None else ""),
                "url":       url,
                "summary":   strip_tags(summary_el.text if summary_el is not None else ""),
                "published": parse_date(date_el.text if date_el is not None else None),
            })
        return articles

    # RSS 2.0
    channel = root.find("channel") or root
    for item in channel.findall("item"):
        if len(articles) >= _MAX_ARTICLES:
            break
        title_el = item.find("title")
        link_el  = item.find("link")
        desc_el  = item.find("description")
        date_el  = item.find("pubDate")

        url = (link_el.text or "").strip() if link_el is not None else ""
        if not url:
            guid_el = item.find("guid")
            if guid_el is not None and (guid_el.text or "").startswith("http"):
                url = guid_el.text.strip()
        url = _safe_url(url)   # [SECURITY] validate URL scheme
        if not url:
            continue

        articles.append({
            "source":    source,
            "title":     strip_tags(title_el.text if title_el is not None else ""),
            "url":       url,
            "summary":   strip_tags(desc_el.text if desc_el is not None else ""),
            "published": parse_date(date_el.text if date_el is not None else None),
        })
    return articles


def fetch_feed(source: str, url: str) -> list[dict]:
    print(f"  Fetching: {source}")
    data = fetch_url(url)
    if data is None:
        return []
    return parse_rss(data, source)


def save_articles(db, articles: list[dict]) -> tuple[int, list[dict]]:
    """Upsert articles; return (new_count, list_of_new_article_dicts)."""
    if not articles:
        return 0, []
    now       = datetime.now(timezone.utc).isoformat()
    new_count = 0
    new_arts  = []
    for a in articles:
        try:
            doc = {
                "source":       a["source"],
                "title":        a["title"],
                "url":          a["url"],
                "summary":      a.get("summary", ""),
                "published":    a.get("published"),
                "published_dt": to_datetime(a.get("published")),
                "fetched_at":   now,
            }
            result = db.articles.update_one(
                {"url": a["url"]},
                {"$setOnInsert": doc},
                upsert=True,
            )
            if result.upserted_id:
                new_count += 1
                new_arts.append(doc)
        except DuplicateKeyError:
            pass
    return new_count, new_arts


# ─── CLI commands ─────────────────────────────────────────────────────────────

def cmd_fetch(args) -> None:
    db = get_db()
    init_collections(db)

    feeds = list(db.feeds.find({"enabled": True}, {"name": 1, "url": 1}))
    if args.source:
        feeds = [f for f in feeds if args.source.lower() in f["name"].lower()]
    if not feeds:
        print("No matching feeds.")
        return

    total_new = 0
    print(f"Fetching {len(feeds)} feed(s)…\n")
    now = datetime.now(timezone.utc)
    for feed in feeds:
        arts      = fetch_feed(feed["name"], feed["url"])
        new, _    = save_articles(db, arts)
        db.feeds.update_one({"_id": feed["_id"]}, {"$set": {"last_fetch": now}})
        print(f"  => {len(arts)} items, {new} new\n")
        total_new += new

    print(f"Done. Total new articles: {total_new}")


def cmd_list(args) -> None:
    db    = get_db()
    filt  = {}
    if args.source:
        filt["source"] = {"$regex": args.source, "$options": "i"}
    if args.search:
        filt["$or"] = [
            {"title":   {"$regex": args.search, "$options": "i"}},
            {"summary": {"$regex": args.search, "$options": "i"}},
        ]
    if args.since:
        filt["published"] = {"$gte": args.since}

    cursor = db.articles.find(filt, {"_id": 0, "source": 1, "title": 1, "url": 1, "published": 1})\
                        .sort("published", DESCENDING)\
                        .limit(args.limit or 50)
    rows = list(cursor)
    if not rows:
        print("No articles found.")
        return
    for a in rows:
        date_str = (a.get("published") or "")[:10]
        print(f"[{date_str}] {a['source']}")
        print(f"  {a['title']}")
        print(f"  {a['url']}\n")


def cmd_stats(args) -> None:
    db    = get_db()
    total = db.articles.count_documents({})
    print(f"Total articles: {total}\n")
    print(f"{'Source':<38} {'Count':>6}")
    print("-" * 46)
    pipeline = [
        {"$group": {"_id": "$source", "count": {"$sum": 1}}},
        {"$sort":  {"count": DESCENDING}},
    ]
    for row in db.articles.aggregate(pipeline):
        print(f"{row['_id']:<38} {row['count']:>6}")


def cmd_export(args) -> None:
    db     = get_db()
    cursor = db.articles.find({}, {"_id": 0}).sort("published", DESCENDING)
    data   = list(cursor)
    out    = args.output or "security_news_export.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)
    print(f"Exported {len(data)} articles to {out}")


def cmd_sources(args) -> None:
    db    = get_db()
    feeds = list(db.feeds.find({}, {"_id": 0, "name": 1, "url": 1, "enabled": 1}).sort("name", 1))
    print(f"{'#':<3} {'En':<4} {'Source':<35} URL")
    print("-" * 95)
    for i, f in enumerate(feeds, 1):
        status = "✓" if f.get("enabled") else "✗"
        print(f"{i:<3} {status:<4} {f['name']:<35} {f['url']}")


def main():
    parser = argparse.ArgumentParser(description="Security News Collector (MongoDB)")
    sub    = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("fetch", help="Fetch articles from enabled feeds")
    p.add_argument("--source", help="Filter by source name (partial)")
    p.set_defaults(func=cmd_fetch)

    p = sub.add_parser("list", help="List collected articles")
    p.add_argument("--source", help="Filter by source name")
    p.add_argument("--search", help="Search in title/summary")
    p.add_argument("--since",  help="Since date (YYYY-MM-DD)")
    p.add_argument("--limit",  type=int, default=50)
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("stats",   help="Show statistics")
    p.set_defaults(func=cmd_stats)

    p = sub.add_parser("export",  help="Export to JSON")
    p.add_argument("--output", help="Output file path")
    p.set_defaults(func=cmd_export)

    p = sub.add_parser("sources", help="List configured feeds")
    p.set_defaults(func=cmd_sources)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
