#!/usr/bin/env python3
"""Cyber news dashboard: sources (feeds.yml) -> SQLite -> enrichment -> static HTML.

Usage:
  python cyber_dashboard.py                    build the dashboard from feeds.yml
  python cyber_dashboard.py add URL [-n NAME]  discover a feed for URL and append it to feeds.yml
  python cyber_dashboard.py --sample           render an offline preview with fake data
"""
import argparse, calendar, hashlib, html, json, os, re, sqlite3, sys, time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse

import profiles

BASE = Path(__file__).resolve().parent
CONFIG = BASE / "feeds.yml"
LOCAL_CONFIG = BASE / "feeds.local.yml"  # written by the UI (Config tab), not tracked by git
DB = str(BASE / "news.db")
OUT = BASE / "public" / "index.html"
KEEP_DAYS = 30
DEFAULT_LIMIT = 40
DEFAULT_REFRESH_MIN = 60   # server mode: minutes between automatic updates
MIN_REFRESH_MIN = 10       # lower bound, to stay polite to the sites
MAX_REFRESH_MIN = 1440
UA = "cyber-news-dashboard/1.0 (+personal project)"
FEED_MIME = {"application/rss+xml", "application/atom+xml"}
COMMON_PATHS = ["/feed", "/feed/", "/rss", "/rss.xml", "/atom.xml", "/index.xml", "/feeds/posts/default"]
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

TAGS = {
    "ransomware": r"ransomware|lockbit|akira|qilin|extortion",
    "APT": r"\bAPT\d*\b|state-sponsored|nation-state|lazarus|sandworm|turla|espionage",
    "vuln": r"CVE-\d{4}-\d{4,}|vulnerabilit|zero-day|0-day|\bRCE\b|patch|podatno",
    "breach": r"data breach|leak|stolen data|wyciek|exposed",
    "malware": r"malware|trojan|backdoor|botnet|infostealer|stealer|loader",
    "phishing": r"phishing|smishing|\bBEC\b|credential theft",
    "AI": r"\bAI\b|\bLLM\b|prompt injection|machine learning|artificial intelligence",
}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


# ---------- helpers ----------

def http_get(url):
    import requests
    r = requests.get(url, headers={"User-Agent": UA}, timeout=20)
    r.raise_for_status()
    return r


def clean(text, limit=280):
    text = html.unescape(re.sub(r"<[^>]+>", " ", text or ""))
    text = re.sub(r"\s+", " ", text).strip()
    return text[: limit - 1] + "…" if len(text) > limit else text


def parse_date(value):
    try:
        dt = datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None
    return int((dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp())


def validate_url(url):
    """Reject non-http(s) URLs and hosts that resolve to private/loopback/blocked addresses."""
    import ipaddress, socket
    u = urlparse(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise ValueError("URL must start with http:// or https://")
    if os.environ.get("ALLOW_PRIVATE_URLS") == "1":
        return
    try:
        infos = socket.getaddrinfo(u.hostname, None)
    except socket.gaierror:
        raise ValueError(f"Cannot resolve host: {u.hostname}")
    for info in infos:
        if not ipaddress.ip_address(info[4][0].split("%")[0]).is_global:
            raise ValueError("Private, local or blocked (0.0.0.0) addresses are not allowed "
                             "(set ALLOW_PRIVATE_URLS=1 to override)")


# ---------- collectors: each returns [{title, url, summary, published|None}] ----------

def collect_rss(url, limit):
    import feedparser
    feed = feedparser.parse(http_get(url).content)  # http_get raises on HTTP errors / timeouts
    if feed.bozo and not feed.entries:
        raise ValueError(f"not a valid feed: {feed.bozo_exception}")
    out = []
    for e in feed.entries[:limit]:
        if not e.get("link"):
            continue
        ts = e.get("published_parsed") or e.get("updated_parsed")
        out.append(dict(title=e.get("title", ""), url=e["link"], summary=e.get("summary", ""),
                        published=calendar.timegm(ts) if ts else None))
    return out


def discover_feed(url):
    """Find a feed for a site: <link rel=alternate> first, then common paths."""
    from bs4 import BeautifulSoup
    import feedparser
    try:
        soup = BeautifulSoup(http_get(url).text, "html.parser")
        for link in soup.find_all("link", rel="alternate"):
            if link.get("type") in FEED_MIME and link.get("href"):
                return urljoin(url, link["href"])
    except Exception:
        pass
    base = url.rstrip("/")
    for path in COMMON_PATHS:
        try:
            if feedparser.parse(http_get(base + path).content).entries:
                return base + path
        except Exception:
            continue
    return None


def collect_sitemap(src, limit):
    import xml.etree.ElementTree as ET
    from bs4 import BeautifulSoup
    ns = "{http://www.sitemaps.org/schemas/sitemap/0.9}"
    needle = src.get("url_contains", "")
    pages = []
    for u in ET.fromstring(http_get(src["url"]).content).iter(ns + "url"):
        loc = u.findtext(ns + "loc")
        if loc and needle in loc:
            pages.append((u.findtext(ns + "lastmod") or "", loc))
    out = []
    for lastmod, loc in sorted(pages, reverse=True)[: min(limit, 15)]:  # one request per page
        try:
            soup = BeautifulSoup(http_get(loc).text, "html.parser")
        except Exception:
            continue

        def meta(prop):
            tag = soup.find("meta", attrs={"property": prop})
            return tag.get("content", "") if tag else ""

        title = meta("og:title") or (soup.title.string if soup.title and soup.title.string else loc)
        out.append(dict(title=title, url=loc, summary=meta("og:description"), published=parse_date(lastmod)))
    return out


def collect_scrape(src, limit):
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(http_get(src["url"]).text, "html.parser")
    out = []
    for node in soup.select(src["item"])[:limit]:
        title = node.select_one(src.get("title", "a"))
        link = node.select_one(src.get("link", "a"))
        if title and link and link.get("href"):
            out.append(dict(title=title.get_text(" ", strip=True), url=urljoin(src["url"], link["href"]),
                            summary="", published=None))
    return out


def collect(src):
    entries = _collect(src)
    if not entries:
        raise ValueError("no items found" + (" - check the CSS selectors" if src.get("type") == "scrape" else ""))
    return entries


def _collect(src):
    kind, limit = src.get("type", "rss"), int(src.get("limit", DEFAULT_LIMIT))
    if kind == "rss":
        return collect_rss(src["url"], limit)
    if kind == "auto":
        feed = discover_feed(src["url"])
        if not feed:
            raise ValueError("no feed found - try type: sitemap or scrape")
        return collect_rss(feed, limit)
    if kind == "sitemap":
        return collect_sitemap(src, limit)
    if kind == "scrape":
        return collect_scrape(src, limit)
    raise ValueError(f"unknown type '{kind}'")


# ---------- storage + enrichment ----------

def init_db(path=DB):
    con = sqlite3.connect(path, timeout=30)
    con.execute("""CREATE TABLE IF NOT EXISTS items(
        id TEXT PRIMARY KEY, title TEXT, url TEXT, source TEXT,
        published INTEGER, summary TEXT, cves TEXT, tags TEXT)""")
    con.execute("""CREATE TABLE IF NOT EXISTS source_status(
        name TEXT PRIMARY KEY, last_attempt INTEGER, last_success INTEGER, ok INTEGER,
        error TEXT, fetched INTEGER, new_items INTEGER)""")
    con.execute("""CREATE TABLE IF NOT EXISTS fetch_log(
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, source TEXT, level TEXT, message TEXT)""")
    con.execute("CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT)")
    profiles.ensure_schema(con)  # users, dashboards, per-user flags (+ migration of older databases)
    return con


def get_setting(con, key, default=None):
    row = con.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row[0] if row else default


def set_setting(con, key, value):
    con.execute("INSERT OR REPLACE INTO settings(key, value) VALUES (?, ?)", (key, str(value)))


def get_refresh_minutes(con):
    """Minutes between automatic updates in server mode (0 = manual only)."""
    try:
        return int(get_setting(con, "refresh_minutes", DEFAULT_REFRESH_MIN))
    except (TypeError, ValueError):
        return DEFAULT_REFRESH_MIN


def store(con, source, entries):
    """Deduplicate by URL, extract CVEs, tag by keywords. Items without a date get first-seen time."""
    new = 0
    for e in entries:
        title, summary = clean(e["title"], 200), clean(e["summary"])
        blob = f"{title} {summary}"
        cves = sorted({c.upper() for c in CVE_RE.findall(blob)})
        tags = [t for t, rx in TAGS.items() if re.search(rx, blob, re.I)]
        item_id = hashlib.sha256(e["url"].split("?")[0].encode()).hexdigest()[:16]
        cur = con.execute("INSERT OR IGNORE INTO items VALUES (?,?,?,?,?,?,?,?)",
                          (item_id, title, e["url"], source, e["published"] or int(time.time()),
                           summary, ",".join(cves), ",".join(tags)))
        new += cur.rowcount
    con.commit()
    return new


_KEV = (0, set())


def load_kev(max_age=6 * 3600):
    """CISA KEV CVE ids, cached in memory so repeated updates (server mode) do not refetch."""
    global _KEV
    if _KEV[1] and time.time() - _KEV[0] < max_age:
        return _KEV[1]
    try:
        ids = {v["cveID"] for v in http_get(KEV_URL).json()["vulnerabilities"]}
        _KEV = (time.time(), ids)
        return ids
    except Exception as e:
        print(f"[!] CISA KEV unavailable: {e}")
        return _KEV[1]  # a stale cache beats nothing


def cached_kev():
    """KEV ids already in memory (never touches the network)."""
    return _KEV[1]


# ---------- config + commands ----------

def _read_yaml(path):
    import yaml
    return (yaml.safe_load(path.read_text(encoding="utf-8")) or []) if path.exists() else []


def read_local():
    return _read_yaml(LOCAL_CONFIG)


def write_local(entries):
    """feeds.local.yml is machine-managed by the UI; it extends/overrides feeds.yml by source name."""
    import yaml
    header = "# Managed by the dashboard UI (Config tab). Extends/overrides feeds.yml. Not tracked by git.\n"
    tmp = LOCAL_CONFIG.with_suffix(".tmp")
    tmp.write_text(header + yaml.safe_dump(entries, sort_keys=False, allow_unicode=True), encoding="utf-8")
    tmp.replace(LOCAL_CONFIG)


def load_config():
    """Merge feeds.yml (origin 'base') with feeds.local.yml (origin 'local'); local overrides by name."""
    merged = {}
    for path, origin in ((CONFIG, "base"), (LOCAL_CONFIG, "local")):
        for s in _read_yaml(path):
            if not (isinstance(s, dict) and s.get("name")):
                print(f"[!] skipping invalid entry in {path.name}: {s}")
            elif s["name"] in merged:
                merged[s["name"]].update(s)
            else:
                merged[s["name"]] = dict(s, origin=origin)
    sources = []
    for s in merged.values():
        if s.get("url"):
            sources.append(s)
        else:
            print(f"[!] source '{s['name']}' has no url, skipping")
    return sources


def log(con, source, level, message):
    con.execute("INSERT INTO fetch_log(ts, source, level, message) VALUES (?,?,?,?)",
                (int(time.time()), source, level, message[:500]))


def set_status(con, name, ok, error="", fetched=0, new=0):
    now = int(time.time())
    row = con.execute("SELECT last_success FROM source_status WHERE name=?", (name,)).fetchone()
    last_success = now if ok else (row[0] if row else None)
    con.execute("INSERT OR REPLACE INTO source_status VALUES (?,?,?,?,?,?,?)",
                (name, now, last_success, int(ok), error[:300], fetched, new))
    log(con, name, "ok" if ok else "error", f"{fetched} entries, {new} new" if ok else error)
    con.commit()


def run_update(only=None):
    """Fetch all enabled sources (or just `only`), record status + log, rebuild the page."""
    con = init_db()
    if not only:  # a full run restarts the schedule; set first so a crash cannot cause a retry loop
        set_setting(con, "last_run", int(time.time()))
        con.commit()
    sources = load_config()
    ok = failed = 0
    for src in sources:
        name = src["name"]
        if (only and name != only) or not src.get("enabled", True):
            continue
        try:
            entries = collect(src)
            set_status(con, name, True, fetched=len(entries), new=store(con, name, entries))
            ok += 1
        except Exception as e:
            set_status(con, name, False, error=f"{type(e).__name__}: {e}")
            failed += 1
            print(f"[!] {name}: {e}")
    now = int(time.time())
    log(con, "update", "info", f"finished: {ok} ok, {failed} failed" + (f" (only {only})" if only else ""))
    # items flagged Important are kept past the retention window
    con.execute("DELETE FROM items WHERE published < ? AND url NOT IN (SELECT url FROM user_important)",
                (now - KEEP_DAYS * 86400,))
    con.execute("DELETE FROM user_read WHERE url NOT IN (SELECT url FROM items)")
    con.execute("DELETE FROM user_important WHERE url NOT IN (SELECT url FROM items)")
    con.execute("DELETE FROM fetch_log WHERE ts < ?", (now - 14 * 86400,))
    names = [s["name"] for s in sources]
    con.execute(f"DELETE FROM source_status WHERE name NOT IN ({','.join('?' * len(names))})", names)
    kev = load_kev()
    if not kev:
        log(con, "CISA KEV", "error", "catalog unavailable - KEV flags are missing")
    con.commit()
    render(con, kev)
    con.close()
    return ok, failed


def config_snapshot(con):
    """Sources + their last status + recent log, for the Config tab."""
    status = {r[0]: dict(ok=bool(r[3]), last_attempt=r[1], last_success=r[2], error=r[4], fetched=r[5], new=r[6])
              for r in con.execute("SELECT name,last_attempt,last_success,ok,error,fetched,new_items FROM source_status")}
    sources = [dict(name=s["name"], type=s.get("type", "rss"), url=s["url"], enabled=s.get("enabled", True),
                    origin=s["origin"], status=status.get(s["name"])) for s in load_config()]
    rows = con.execute("SELECT ts,source,level,message FROM fetch_log ORDER BY id DESC LIMIT 150").fetchall()
    mins = get_refresh_minutes(con)
    last_run = int(get_setting(con, "last_run", 0) or 0)
    return dict(sources=sources, updating=False, refresh_minutes=mins,
                next_run=(last_run + mins * 60) if mins else None,
                last_update=max((v["last_attempt"] for v in status.values()), default=None),
                log=[dict(ts=a, source=b, level=c, message=d) for a, b, c, d in rows])


def add_source(url, name=None):
    if not urlparse(url).scheme:
        url = "https://" + url
    feed = discover_feed(url)
    if not feed:
        print("No feed found. Add it manually to feeds.yml as type: sitemap or type: scrape.")
        return 1
    name = name or urlparse(url).netloc.removeprefix("www.")
    with CONFIG.open("a", encoding="utf-8") as f:
        f.write(f"\n- name: {json.dumps(name, ensure_ascii=False)}\n  type: rss\n  url: {feed}\n")
    print(f"Added '{name}' -> {feed}")
    return 0


# ---------- sample mode (offline preview) ----------

def sample():
    now = int(time.time())
    base = "https://example.com/"
    rows = [
        ("Demo · RSS", 12, "Ransomware gang claims attack on European logistics provider",
         "The group says it exfiltrated internal documents and set a payment deadline."),
        ("Demo · RSS", 35, "Zero-day in enterprise VPN appliance exploited in the wild (CVE-2026-00001)",
         "Attackers chain an authentication bypass with a command injection. Vendor patch is available."),
        ("Demo · Sitemap", 70, "Nation-state APT targets energy sector with new backdoor",
         "Researchers link the espionage campaign to infrastructure used in earlier operations."),
        ("Demo · RSS", 110, "Prompt injection flaw lets attackers hijack AI coding assistants",
         "A crafted repository file can make the assistant execute attacker-controlled commands."),
        ("Demo · Scrape", 160, "Phishing campaign abuses trusted file-sharing links to steal credentials",
         "Messages pass basic filters because the links point to legitimate cloud services."),
        ("Demo · RSS", 240, "Infostealer malware spreads via fake browser update pages",
         "The loader fetches a stealer that targets saved passwords and session cookies."),
        ("Demo · RSS", 400, "Patch Tuesday: actively exploited bugs fixed, including CVE-2026-00007",
         "Administrators are urged to prioritise the elevation-of-privilege issue."),
        ("Demo · Sitemap", 600, "Data breach exposes records of 2 million customers at retail chain",
         "Leaked data includes names, emails and order history; no payment data reported."),
        ("Demo · RSS", 900, "Wyciek danych z platformy e-commerce - zalecana zmiana haseł",
         "Zespół reagowania publikuje komunikat i zalecenia dla użytkowników."),
        ("Demo · Scrape", 1500, "New botnet targets unpatched home routers",
         "Infected devices are used for DDoS and proxying malicious traffic."),
    ]
    con = init_db(":memory:")
    for i, (src, mins, title, summary) in enumerate(rows):
        store(con, src, [dict(title=title, url=f"{base}demo-{i}", summary=summary, published=now - mins * 60)])
    def st(ok, fetched=0, new=0, error="", ok_ago=720, last_ok=True):
        return dict(ok=ok, last_attempt=now - 720, last_success=(now - ok_ago) if last_ok else None,
                    error=error, fetched=fetched, new=new)

    cfg = dict(updating=False, last_update=now - 720, refresh_minutes=15, next_run=now + 480, sources=[
        dict(name="Demo · RSS", type="rss", url="https://example.com/feed", enabled=True, origin="base",
             status=st(True, 40, 6)),
        dict(name="Demo · Sitemap", type="sitemap", url="https://example.com/sitemap.xml", enabled=True,
             origin="local", status=st(True, 12, 2)),
        dict(name="Demo · Scrape", type="scrape", url="https://example.com/news", enabled=True, origin="local",
             status=st(False, error="ValueError: no items found - check the CSS selectors", ok_ago=172800)),
        dict(name="Demo · Dead feed", type="rss", url="https://example.com/old-feed", enabled=True, origin="base",
             status=st(False, last_ok=False, error="HTTPError: 404 Client Error: Not Found for url: https://example.com/old-feed")),
        dict(name="Demo · Paused", type="rss", url="https://example.com/paused", enabled=False, origin="base",
             status=None),
    ], log=[
        dict(ts=now - 720, source="update", level="info", message="finished: 2 ok, 2 failed"),
        dict(ts=now - 722, source="Demo · Dead feed", level="error",
             message="HTTPError: 404 Client Error: Not Found for url: https://example.com/old-feed"),
        dict(ts=now - 724, source="Demo · Scrape", level="error",
             message="ValueError: no items found - check the CSS selectors"),
        dict(ts=now - 726, source="Demo · Sitemap", level="ok", message="12 entries, 2 new"),
        dict(ts=now - 730, source="Demo · RSS", level="ok", message="40 entries, 6 new"),
        dict(ts=now - 4320, source="update", level="info", message="finished: 3 ok, 1 failed"),
    ])
    def dash(i, name, sources=None):
        return dict(id=i, name=name, all=sources is None, sources=sources or [], unread=0)

    demo_state = dict(users=[dict(id=1, name="Alice"), dict(id=2, name="Bob")], dashboards={
        "1": [dash(1, "Everything"), dash(2, "Vendor blogs", ["Demo · RSS", "Demo · Sitemap"]),
              dash(3, "Local feeds", ["Demo · Scrape"])],
        "2": [dash(4, "Everything"), dash(5, "Only RSS", ["Demo · RSS"])]})
    render(con, {"CVE-2026-00001", "CVE-2026-00007"}, banner="Sample data: fictional headlines, sources and users, layout preview only",
           cfg=cfg, demo=True, demo_state=demo_state)


# ---------- rendering ----------

def _js(obj):
    return json.dumps(obj, ensure_ascii=False).replace("</", "<\\/")


def load_items(con, kev, sources=None, user_id=None):
    """Newest 400 items (only from `sources` if given) plus the Important items of `user_id`
    (of any user when None). Important items outlive the retention window."""
    if sources is not None and not sources:
        return [], []
    src_sql, src_params = "", []
    if sources is not None:
        src_sql = f" AND source IN ({','.join('?' * len(sources))})"
        src_params = list(sources)
    imp_sql = "SELECT url FROM user_important" + (" WHERE user_id = ?" if user_id is not None else "")
    rows = con.execute(
        "SELECT title,url,source,published,summary,cves,tags FROM items WHERE url IN "
        f"(SELECT url FROM items WHERE 1=1{src_sql} ORDER BY published DESC LIMIT 400) "
        f"OR (url IN ({imp_sql}){src_sql}) ORDER BY published DESC",
        src_params + ([user_id] if user_id is not None else []) + src_params).fetchall()
    items, all_tags = [], set()
    for title, url, source, ts, summary, cves, tags in rows:
        cve_list = [c for c in cves.split(",") if c]
        tag_list = [t for t in tags.split(",") if t]
        in_kev = [c for c in cve_list if c in kev]
        if in_kev:
            tag_list.append("KEV")
        all_tags.update(tag_list)
        items.append(dict(title=title, url=url, source=source, ts=ts, summary=summary,
                          cves=cve_list, kev=in_kev, tags=tag_list))
    return items, sorted(all_tags)


def items_payload(con, kev, sources=None, user_id=None):
    """What the page needs to redraw itself without a reload (served at /api/items)."""
    items, tags = load_items(con, kev, sources, user_id)
    updated = con.execute("SELECT MAX(last_attempt) FROM source_status").fetchone()[0]
    return dict(items=items, tags=tags, updated=updated or int(time.time()))


def render(con, kev, banner="", cfg=None, demo=False, demo_state=None):
    payload = items_payload(con, kev)
    cfg = cfg or config_snapshot(con)
    values = {
        "DATA": _js(payload["items"]), "TAGS": _js(payload["tags"]), "CFG": _js(cfg),
        "DEMO": "true" if demo else "false", "DEMOSTATE": _js(demo_state),
        "GENERATED": str(cfg.get("last_update") or payload["updated"]),
        "BANNER": f'<div class="banner">{html.escape(banner)}</div>' if banner else "",
    }
    # one pass over the template: text inside the values (e.g. a headline containing "__CFG__") is never re-scanned
    page = re.sub(r"__(DATA|TAGS|CFG|DEMOSTATE|DEMO|GENERATED|BANNER)__", lambda m: values[m.group(1)], TEMPLATE)
    OUT.parent.mkdir(exist_ok=True)
    tmp = OUT.with_suffix(".tmp")  # atomic: the server never serves a half-written page
    tmp.write_text(page, encoding="utf-8")
    tmp.replace(OUT)
    print(f"[+] wrote {OUT} ({len(payload['items'])} items)")


TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Cyber News Dashboard</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--fg:#1a1d21;--mute:#667;--bd:#dde1e6;--acc:#2563eb;--kev:#dc2626;--star:#d97706}
@media(prefers-color-scheme:dark){:root{--bg:#0f1216;--card:#171b21;--fg:#e6e9ee;--mute:#8b95a3;--bd:#2a313b;--acc:#60a5fa;--kev:#f87171;--star:#fbbf24}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}
main{max-width:900px;margin:0 auto;padding:20px 16px}
h1{font-size:1.4rem;margin:0}.sub{color:var(--mute);font-size:.85rem}
.top{display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:14px}
.auto{display:inline-flex;align-items:center;gap:6px;font-size:.82rem;color:var(--mute);cursor:pointer;user-select:none}
.banner{background:var(--card);border:1px dashed var(--acc);color:var(--acc);border-radius:8px;padding:6px 12px;margin-bottom:12px;font-size:.85rem}
input{width:100%;padding:10px 12px;border:1px solid var(--bd);border-radius:8px;background:var(--card);color:var(--fg);font:inherit}
.chips{display:flex;flex-wrap:wrap;gap:6px;margin:10px 0 16px}
.chip{border:1px solid var(--bd);background:var(--card);color:var(--fg);border-radius:999px;padding:3px 12px;cursor:pointer;font:inherit;font-size:.82rem}
.chip.on{background:var(--acc);border-color:var(--acc);color:#fff}
.chip.imp{border-color:var(--star);color:var(--star)}
.chip.imp.on{background:var(--star);border-color:var(--star);color:#1a1d21}
.card{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:12px 14px;margin-bottom:10px}
.card.imp{border-left:4px solid var(--star)}
.card-top{display:flex;justify-content:space-between;align-items:flex-start;gap:8px}
.card a{color:var(--fg);font-weight:600;text-decoration:none}.card a:hover{color:var(--acc)}
.star{flex:none;border:0;background:none;cursor:pointer;font-size:1.2rem;line-height:1.2;color:var(--mute);padding:0 2px}
.star:hover,.star.on{color:var(--star)}
.meta{color:var(--mute);font-size:.78rem;margin-top:2px}.sum{margin:6px 0;color:var(--mute);font-size:.88rem}
.tag{display:inline-block;font-size:.72rem;border:1px solid var(--bd);border-radius:4px;padding:0 6px;margin-right:4px}
.tag.kev{border-color:var(--kev);color:var(--kev);font-weight:700}
.tabs{display:flex;flex-wrap:wrap;gap:4px;border-bottom:1px solid var(--bd);margin-bottom:12px}
.tab{background:none;border:0;border-bottom:2px solid transparent;color:var(--mute);padding:8px 14px;cursor:pointer;font:inherit;white-space:nowrap}
.tab.on{color:var(--fg);border-bottom-color:var(--acc);font-weight:600}
.card.read{opacity:.55}
.foot{display:flex;justify-content:space-between;align-items:center;gap:8px}
.rd{flex:none;border:1px solid var(--bd);background:none;color:var(--mute);border-radius:6px;padding:2px 10px;cursor:pointer;font:inherit;font-size:.78rem}
.rd:hover{color:var(--acc);border-color:var(--acc)}
#bulk{margin-left:auto;align-self:center}
[hidden]{display:none!important}
input[type=checkbox]{width:auto}
select{padding:10px 12px;border:1px solid var(--bd);border-radius:8px;background:var(--card);color:var(--fg);font:inherit}
.box{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:12px 14px;margin-bottom:14px}
.row{display:flex;gap:8px;margin-top:8px;flex-wrap:wrap;align-items:center}.row>input{flex:1;min-width:140px}
.cfgbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;color:var(--mute);font-size:.85rem}
.note{border:1px dashed var(--acc);color:var(--acc);border-radius:8px;padding:6px 12px;margin-bottom:12px;font-size:.85rem}
h3{font-size:1rem;margin:18px 0 8px}h3 label{font-weight:400;font-size:.8rem;color:var(--mute);margin-left:8px}
.src{background:var(--card);border:1px solid var(--bd);border-left:4px solid var(--bd);border-radius:8px;padding:8px 12px;margin-bottom:8px;word-break:break-word}
.src.ok{border-left-color:#16a34a}.src.bad{border-left-color:var(--kev)}.src.off{opacity:.6}
.srch{display:flex;flex-wrap:wrap;align-items:center;gap:6px}.acts{margin-left:auto;display:flex;gap:4px}
.err{color:var(--kev);font-size:.82rem;margin-top:4px;font-family:ui-monospace,monospace}
.logrow{font-size:.8rem;padding:3px 0;border-bottom:1px solid var(--bd);word-break:break-word}.lt{color:var(--mute);margin-right:6px}
.logrow.error{color:var(--kev)}
.empty{color:var(--mute);text-align:center;padding:30px 0}
.tools{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.usersel{padding:4px 8px;font-size:.82rem}
.dashbar{display:flex;flex-wrap:wrap;gap:6px;margin:0 0 12px}
.dash{border:1px solid var(--bd);background:var(--card);color:var(--fg);border-radius:8px;padding:5px 12px;cursor:pointer;font:inherit;font-size:.85rem}
.dash.on{background:var(--acc);border-color:var(--acc);color:#fff}
.dash .cnt{opacity:.75;margin-left:6px;font-size:.78rem}
.rd.pri{color:var(--acc);border-color:var(--acc)}
.chk{font-size:.85rem;color:var(--mute);display:flex;align-items:center;gap:6px;margin:8px 0 4px}
.urow{display:flex;align-items:center;gap:6px;padding:6px 0;border-bottom:1px solid var(--bd)}.urow .nm{flex:1}
.dcard{border:1px solid var(--bd);border-radius:8px;padding:10px 12px;margin-top:10px}.dcard.dirty{border-color:var(--acc)}
.srcs{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:2px 12px;margin:6px 0 10px}
.srcs label{font-size:.85rem;display:flex;align-items:center;gap:6px;cursor:pointer}.srcs label.off{opacity:.6}
</style></head><body><main>
<h1>Cyber News Dashboard</h1>
<div class="top"><div class="sub">Updated <span id="updated"></span> · <span id="count"></span></div>
<div class="tools"><select id="userSel" class="usersel" title="Switch user" aria-label="Switch user" hidden></select>
<label class="auto" title="Server mode: loads new items as soon as an update finishes. Static mode: reloads the page every 10 minutes."><input type="checkbox" id="auto"> Auto-refresh</label></div></div>
__BANNER__
<div class="dashbar" id="dashbar" hidden></div>
<nav class="tabs" id="tabs"></nav>
<input id="q" type="search" placeholder="Search title, CVE, source…">
<div class="chips" id="chips"></div>
<div id="list"></div>
<section id="cfg" hidden>
<div class="cfgbar"><span id="cfgInfo"></span><button class="rd" id="upd" hidden>Update now</button></div>
<div class="note" id="cfgMsg" hidden></div>
<div class="box" id="schedBox" hidden><b>Refresh schedule</b>
<div class="row"><label for="fEvery">Fetch all sources every</label><select id="fEvery"></select><span class="meta" id="nextRun"></span></div>
<div class="meta">Applies to all sources. A change takes effect immediately; if the new interval has already passed since the last run, an update starts within seconds.</div>
</div>
<div class="box" id="accBox" hidden><b>Users</b> <span class="meta">Profiles without passwords: each has their own dashboards and read / Important flags. Anyone who can open this page can switch to any of them.</span>
<div id="userList"></div>
<div class="row"><input id="fUser" placeholder="New user name" maxlength="40" aria-label="New user name"><button class="rd" id="fUserAdd">Add user</button></div></div>
<div class="box" id="dashBox" hidden><b>Dashboards of <span id="dashOwner"></span></b>
<div class="meta">A dashboard shows only the sources you tick. The list of sources is shared by all users.</div>
<div id="dashEditor"></div>
<div class="row"><button class="rd" id="fDashNew">+ New dashboard</button></div></div>
<div class="box" id="addBox" hidden><b>Add source</b>
<div class="row"><input id="fUrl" placeholder="Site or feed URL"><input id="fName" placeholder="Name (optional)"></div>
<div class="row"><select id="fType"><option value="detect">Auto-detect feed</option><option value="rss">RSS/Atom feed URL</option><option value="sitemap">Sitemap</option><option value="scrape">HTML scrape</option></select><button class="rd" id="fAdd">Add</button></div>
<div class="row" id="xSitemap" hidden><input id="fContains" placeholder="URL must contain (optional), e.g. /blog/"></div>
<div class="row" id="xScrape" hidden><input id="fItem" placeholder="Item selector, e.g. article.post"><input id="fTitle" placeholder="Title selector (default: a)"><input id="fLink" placeholder="Link selector (default: a)"></div>
</div>
<h3>Sources</h3><div id="cfgTable"></div>
<h3>Log <label><input type="checkbox" id="errOnly"> errors only</label></h3><div id="cfgLog"></div>
</section>
</main>
<script>
let DATA=__DATA__, TAGS=__TAGS__;
const DEMO=__DEMO__, DEMOSTATE=__DEMOSTATE__, EMBEDDED=DATA;
const KEY="cnd:read", IKEY="cnd:imp", AKEY="cnd:auto", UKEY="cnd:user", DKEY="cnd:dash:";
const VIEWS={all:"All",unread:"Not read",read:"Read",config:"Config"};
const EVERY=[[0,"Off (manual only)"],[10,"10 minutes"],[15,"15 minutes"],[30,"30 minutes"],[60,"1 hour"],[120,"2 hours"],[240,"4 hours"],[720,"12 hours"]];
const AUTO_MS=30000, STATIC_RELOAD_MS=600000;
let active=new Set(), q="", view="all", onlyImp=false, read=new Set(), important=new Set(), shown=[];
let CFG=__CFG__, editable=DEMO, msg="", errOnly=false, poll=null, wasUpdating=false, synced=false;
let dataTs=__GENERATED__, known=new Set(), auto=false, autoT=null, loadedFor="";
let USERS=[], me=null, DASHES=[], dash=null, drafts={};
const loadedAt=Date.now();
const $=id=>document.getElementById(id);
const lsRaw=k=>{try{return localStorage.getItem(k)}catch(e){return null}};
const lsGet=k=>{try{return JSON.parse(lsRaw(k)||"[]")}catch(e){return []}};
const lsSet=(k,v)=>{try{localStorage.setItem(k,v)}catch(e){}};
const save=()=>lsSet(KEY,JSON.stringify([...read]));
const saveImp=()=>lsSet(IKEY,JSON.stringify([...important]));
read=new Set(lsGet(KEY));important=new Set(lsGet(IKEY));
try{auto=localStorage.getItem(AKEY)==="1"}catch(e){}
function setData(items,tags){DATA=items;TAGS=tags;known=new Set(DATA.map(i=>i.url))}
const tagsOf=items=>[...new Set(items.flatMap(i=>i.tags))].sort();
const curDash=()=>DASHES.find(d=>d.id===dash);
// demo preview: users and dashboards live in the page, filtering happens here
function applyDemo(){const d=curDash();const items=!d||d.all?EMBEDDED:EMBEDDED.filter(i=>d.sources.includes(i.source));setData(items,tagsOf(items))}
const demoUnread=d=>EMBEDDED.filter(i=>(d.all||d.sources.includes(i.source))&&!read.has(i.url)).length;
setData(DATA,TAGS);
if(DEMO&&DEMOSTATE){USERS=DEMOSTATE.users;me=USERS[0].id;DASHES=DEMOSTATE.dashboards[String(me)];dash=DASHES[0].id;applyDemo()}
read=new Set([...read].filter(u=>known.has(u)));
important=new Set([...important].filter(u=>known.has(u)));
const esc=s=>String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const ago=ts=>{const h=(Date.now()/1000-ts)/3600;return h<1?Math.max(1,Math.round(h*60))+" min ago":h<48?Math.round(h)+" h ago":Math.round(h/24)+" d ago"};
const fmtDay=ts=>new Date(ts*1000).toLocaleString([],{weekday:"short",day:"numeric",month:"short",hour:"2-digit",minute:"2-digit"});
const fmtFull=ts=>new Date(ts*1000).toLocaleString([],{day:"numeric",month:"short",hour:"2-digit",minute:"2-digit"});
const inMin=ts=>Math.max(1,Math.round((ts-Date.now()/1000)/60))+" min";
const EMPTY={all:"No items match.",unread:"All caught up.",read:"Nothing marked as read yet."};
// ---- server sync (only when served by server.py)
const hdrs=()=>me?{"X-User":String(me)}:{};
async function getJSON(path){const r=await fetch(path,{cache:"no-store",headers:hdrs()});if(!r.ok)throw new Error("HTTP "+r.status);return r.json()}
async function api(path,body){
  if(DEMO)throw new Error("demo preview, no server attached - nothing was changed");
  const r=await fetch(path,{method:"POST",headers:Object.assign({"Content-Type":"application/json"},hdrs()),body:JSON.stringify(body||{})});
  let d={};try{d=await r.json()}catch(e){}
  if(!r.ok)throw new Error(d.error||"HTTP "+r.status);
  return d}
function syncDrafts(){
  const ids=new Set(DASHES.map(d=>String(d.id)));
  for(const k of Object.keys(drafts))if(k!=="new"&&!ids.has(k))delete drafts[k];
  for(const d of DASHES){const k=String(d.id);if(!drafts[k]||!drafts[k].dirty)drafts[k]={name:d.name,all:d.all,sources:[...d.sources],dirty:false}}}
async function loadRemote(){
  let u;
  try{u=await getJSON("api/users")}catch(e){return}
  if(!Array.isArray(u.users)||!u.users.length)return;
  USERS=u.users;
  if(!USERS.some(x=>x.id===me)){const s=Number(lsRaw(UKEY));me=USERS.some(x=>x.id===s)?s:USERS[0].id;lsSet(UKEY,String(me))}
  try{
    const [a,b,c]=await Promise.all([getJSON("api/read"),getJSON("api/important"),getJSON("api/dashboards")]);
    if(!Array.isArray(a.read)||!Array.isArray(b.important)||!Array.isArray(c.dashboards))return;
    read=new Set(a.read);important=new Set(b.important);DASHES=c.dashboards;synced=true;save();saveImp();
  }catch(e){return}
  syncDrafts();
  if(!DASHES.some(d=>d.id===dash)){const w=Number(lsRaw(DKEY+me));dash=DASHES.some(d=>d.id===w)?w:(DASHES[0]?DASHES[0].id:null)}
  await loadConfig();
  if(loadedFor!==me+":"+dash)await loadItems()}
async function refreshDashes(){
  try{const c=await getJSON("api/dashboards");if(Array.isArray(c.dashboards)){DASHES=c.dashboards;syncDrafts();render()}}catch(e){}}
function push(urls,flag){if(synced)api("api/read",{urls,read:flag}).then(refreshDashes).catch(()=>{})}
function pushImp(urls,flag){if(synced)api("api/important",{urls,important:flag}).catch(()=>{})}
async function loadItems(){
  try{const d=await getJSON("api/items"+(dash?"?dashboard="+dash:""));if(!Array.isArray(d.items))return;
    setData(d.items,d.tags||[]);dataTs=d.updated||dataTs;loadedFor=me+":"+dash;render()}catch(e){}}
async function loadConfig(){
  try{CFG=await getJSON("api/config");editable=true;
    if(CFG.updating){wasUpdating=true;if(!poll)poll=setInterval(loadConfig,1500)}
    else{if(poll){clearInterval(poll);poll=null}
      if(wasUpdating){wasUpdating=false;msg="Update finished.";await loadItems()}}
    render()}catch(e){}}
async function selectDash(id){
  if(id===dash)return;
  dash=id;lsSet(DKEY+me,String(id));active.clear();
  if(DEMO){applyDemo();render();return}
  await loadItems()}
async function switchUser(id){
  me=id;lsSet(UKEY,String(id));dash=null;active.clear();onlyImp=false;drafts={};
  if(DEMO){DASHES=DEMOSTATE.dashboards[String(me)];dash=DASHES[0].id;syncDrafts();applyDemo();render();return}
  await loadRemote()}
// ---- auto-refresh
async function tick(){
  if(document.hidden||DEMO)return;
  if(synced){
    await loadRemote();
    if(!CFG.updating&&CFG.last_update&&CFG.last_update>dataTs)await loadItems();
  }else if(Date.now()-loadedAt>STATIC_RELOAD_MS)location.reload()}
function setAuto(on){
  auto=on;lsSet(AKEY,on?"1":"0");clearInterval(autoT);autoT=null;
  if(on){tick();autoT=setInterval(tick,AUTO_MS)}}
function fromHash(){const h=location.hash.slice(1);view=VIEWS[h]?h:"all"}
// ---- Config tab
function renderSched(){
  $("schedBox").hidden=!editable;if(!editable)return;
  const cur=Number(CFG.refresh_minutes)||0,sel=$("fEvery");
  const opts=EVERY.slice();if(!opts.some(o=>o[0]===cur))opts.push([cur,cur+" minutes"]);
  if(document.activeElement!==sel){sel.innerHTML=opts.map(o=>`<option value="${o[0]}">${o[1]}</option>`).join("");sel.value=String(cur)}
  $("nextRun").textContent=!cur?"Scheduled updates are off.":CFG.updating?"Updating now...":!CFG.next_run?"":CFG.next_run*1000<=Date.now()?"Next update: due now":"Next update in "+inMin(CFG.next_run)}
function dcard(id,d,names){
  const off=new Set(CFG.sources.filter(s=>!s.enabled).map(s=>s.name));
  const all=names.concat(d.sources.filter(s=>!names.includes(s)));
  const sources=all.map(s=>{const gone=!names.includes(s);
    return `<label class="${gone||off.has(s)?"off":""}"><input type="checkbox" data-f="src" data-s="${esc(s)}" ${d.all||d.sources.includes(s)?"checked":""} ${d.all?"disabled":""}> ${esc(s)}${gone?" (not configured)":off.has(s)?" (disabled)":""}</label>`}).join("");
  return `<div class="dcard ${d.dirty?"dirty":""}" data-id="${esc(id)}">
    <div class="row"><input data-f="name" value="${esc(d.name)}" maxlength="40" placeholder="Dashboard name" aria-label="Dashboard name"></div>
    <label class="chk"><input type="checkbox" data-f="all" ${d.all?"checked":""}> All sources (including ones added later)</label>
    <div class="srcs">${sources}</div>
    <div class="row"><button class="rd pri" data-da="save">${id==="new"?"Create":"Save"}</button>
    ${id==="new"?`<button class="rd" data-da="cancel">Cancel</button>`:`<button class="rd" data-da="delete">Delete</button>`}</div></div>`}
function renderAccounts(force){
  const on=editable&&(synced||DEMO)&&USERS.length>0;
  $("accBox").hidden=!on;$("dashBox").hidden=!on;if(!on)return;
  // never rebuild while somebody is typing in a text field of these boxes (checkboxes and buttons are fine)
  const ae=document.activeElement;
  if(!force&&ae&&ae.matches("#accBox input:not([type=checkbox]),#dashBox input:not([type=checkbox])"))return;
  $("userList").innerHTML=USERS.map(u=>`<div class="urow"><span class="nm">${esc(u.name)}${u.id===me?` <span class="tag">you</span>`:""}</span>
    <button class="rd" data-ua="rename" data-id="${u.id}">Rename</button>${USERS.length>1?`<button class="rd" data-ua="delete" data-id="${u.id}">Delete</button>`:""}</div>`).join("");
  const mine=USERS.find(u=>u.id===me);$("dashOwner").textContent=mine?mine.name:"";
  const names=CFG.sources.map(s=>s.name);
  $("dashEditor").innerHTML=Object.keys(drafts).map(id=>dcard(id,drafts[id],names)).join("")}
function renderConfig(){
  $("cfgInfo").textContent="Last update: "+(CFG.last_update?ago(CFG.last_update):"never")+(CFG.updating?" · updating...":"");
  $("upd").hidden=!editable;$("upd").disabled=!!CFG.updating;$("addBox").hidden=!editable;
  const note=editable?msg:"Read-only view: status as of the last build. Users, dashboards, adding sources and the refresh schedule need the self-hosted server (see README).";
  $("cfgMsg").hidden=!note;$("cfgMsg").textContent=note;
  renderSched();renderAccounts();
  $("cfgTable").innerHTML=CFG.sources.length?CFG.sources.map(s=>{
    const x=s.status,c=!s.enabled?"off":!x?"":x.ok?"ok":"bad",l=!s.enabled?"disabled":!x?"never fetched":x.ok?"OK":"FAILED",nm=esc(s.name);
    return `<div class="src ${c}"><div class="srch"><b>${nm}</b><span class="tag">${esc(s.type)}</span><span class="tag ${c==="bad"?"kev":""}">${l}</span>
      ${editable?`<span class="acts"><button class="rd" data-a="refresh" data-n="${nm}">Refresh</button>
      <button class="rd" data-a="toggle" data-n="${nm}" data-e="${s.enabled?0:1}">${s.enabled?"Disable":"Enable"}</button>
      ${s.origin==="local"?`<button class="rd" data-a="remove" data-n="${nm}">Remove</button>`:""}</span>`:""}</div>
      <div class="meta">${esc(s.url)}</div>
      <div class="meta">${x?`Last attempt ${ago(x.last_attempt)} · last success ${x.last_success?ago(x.last_success):"never"} · ${x.fetched} entries, ${x.new} new`:"No fetch yet"}</div>
      ${x&&!x.ok?`<div class="err">${esc(x.error)}</div>`:""}</div>`}).join(""):`<div class="empty">No sources configured.</div>`;
  const L=CFG.log.filter(l=>!errOnly||l.level==="error");
  $("cfgLog").innerHTML=L.length?L.map(l=>`<div class="logrow ${l.level}"><span class="lt">${new Date(l.ts*1000).toLocaleString()}</span>
    <span class="tag ${l.level==="error"?"kev":""}">${l.level==="error"?"FAILED":l.level==="ok"?"OK":"INFO"}</span> <b>${esc(l.source)}</b> ${esc(l.message)}</div>`).join(""):`<div class="empty">No log entries.</div>`;
}
// ---- main render
function render(){
  const cfg=view==="config";
  const nRead=DATA.filter(i=>read.has(i.url)).length,nImp=DATA.filter(i=>important.has(i.url)).length;
  const n={all:DATA.length,read:nRead,unread:DATA.length-nRead};
  const f=DATA.filter(i=>(view==="all"||(view==="read")===read.has(i.url))&&
    (!onlyImp||important.has(i.url))&&
    (!active.size||[...active].every(t=>i.tags.includes(t)))&&
    (!q||(i.title+i.source+i.summary+i.cves.join(" ")).toLowerCase().includes(q)));
  shown=cfg?[]:f;
  const bulkN=cfg?0:view==="read"?f.length:f.filter(i=>!read.has(i.url)).length;
  const failed=CFG.sources.filter(s=>s.enabled&&s.status&&!s.status.ok).length;
  $("updated").textContent=fmtFull(dataTs);
  const multi=(synced||DEMO)&&USERS.length>1,sel=$("userSel");
  sel.hidden=!multi;
  if(multi&&document.activeElement!==sel)sel.innerHTML=USERS.map(u=>`<option value="${u.id}" ${u.id===me?"selected":""}>👤 ${esc(u.name)}</option>`).join("");
  const bar=(synced||DEMO)&&DASHES.length>1&&!cfg;
  $("dashbar").hidden=!bar;
  if(bar)$("dashbar").innerHTML=DASHES.map(d=>`<button class="dash ${d.id===dash?"on":""}" data-d="${d.id}" aria-pressed="${d.id===dash}">${esc(d.name)}<span class="cnt">${d.id===dash?n.unread:DEMO?demoUnread(d):(d.unread||0)}</span></button>`).join("");
  $("tabs").innerHTML=Object.keys(VIEWS).map(v=>`<button class="tab ${v===view?"on":""}" data-v="${v}">${VIEWS[v]}${v==="config"?(failed?" ⚠ "+failed:""):" ("+n[v]+")"}</button>`).join("")+
    (bulkN?`<button class="rd" id="bulk">${view==="read"?"Mark all as unread":"Mark all as read"} (${bulkN})</button>`:"");
  for(const id of ["q","chips","list"])$(id).hidden=cfg;
  $("cfg").hidden=!cfg;
  if(cfg){$("count").textContent=CFG.sources.length+" sources";renderConfig();return}
  $("chips").innerHTML=`<button class="chip imp ${onlyImp?"on":""}" data-imp="1" aria-pressed="${onlyImp}">★ Important (${nImp})</button>`+
    TAGS.map(t=>`<button class="chip ${active.has(t)?"on":""}" data-t="${esc(t)}">${esc(t)}</button>`).join("");
  $("count").textContent=f.length+" items";
  $("list").innerHTML=f.length?f.map(i=>{const r=read.has(i.url),s=important.has(i.url);return `<div class="card ${r?"read":""} ${s?"imp":""}">
    <div class="card-top"><a href="${esc(i.url)}" target="_blank" rel="noopener noreferrer">${esc(i.title)}</a>
    <button class="star ${s?"on":""}" data-s="${esc(i.url)}" aria-pressed="${s}" title="${s?"Remove Important flag":"Flag as Important"}">${s?"★":"☆"}</button></div>
    <div class="meta">${esc(i.source)} · ${fmtDay(i.ts)} · ${ago(i.ts)}</div>
    ${i.summary?`<div class="sum">${esc(i.summary)}</div>`:""}
    <div class="foot"><div>${i.tags.map(t=>`<span class="tag ${t==="KEV"?"kev":""}">${esc(t)}</span>`).join("")}
    ${i.cves.slice(0,5).map(c=>`<span class="tag ${i.kev.includes(c)?"kev":""}">${esc(c)}</span>`).join("")}</div>
    <button class="rd" data-u="${esc(i.url)}">${r?"Mark as unread":"Mark as read"}</button></div></div>`}).join(""):
    `<div class="empty">${onlyImp?"No important items match. Click ☆ on a card to flag it.":EMPTY[view]}</div>`;
}
// ---- events
$("chips").onclick=e=>{const b=e.target.closest("button");if(!b)return;
  if(b.dataset.imp)onlyImp=!onlyImp;
  else if(b.dataset.t){const t=b.dataset.t;active.has(t)?active.delete(t):active.add(t)}
  else return;
  render()};
$("tabs").onclick=e=>{
  if(e.target.id==="bulk"){const mark=view!=="read";
    shown.forEach(i=>mark?read.add(i.url):read.delete(i.url));save();push(shown.map(i=>i.url),mark);render();return}
  const v=e.target.dataset.v;if(!v)return;
  view=v;try{history.replaceState(null,"","#"+v)}catch(_){}render();if(v==="config")loadConfig()};
$("list").onclick=e=>{
  const st=e.target.closest(".star");
  if(st){const u=st.dataset.s,flag=!important.has(u);flag?important.add(u):important.delete(u);saveImp();pushImp([u],flag);render();return}
  const b=e.target.closest(".rd");if(!b)return;
  const u=b.dataset.u,flag=!read.has(u);flag?read.add(u):read.delete(u);save();push([u],flag);render()};
$("dashbar").onclick=e=>{const b=e.target.closest("[data-d]");if(b)selectDash(Number(b.dataset.d))};
$("userSel").onchange=e=>switchUser(Number(e.target.value));
$("q").oninput=e=>{q=e.target.value.toLowerCase();render()};
$("auto").onchange=e=>setAuto(e.target.checked);
$("fType").onchange=e=>{$("xSitemap").hidden=e.target.value!=="sitemap";$("xScrape").hidden=e.target.value!=="scrape"};
$("errOnly").onchange=e=>{errOnly=e.target.checked;renderConfig()};
$("fEvery").onchange=async e=>{
  try{const d=await api("api/settings",{refresh_minutes:Number(e.target.value)});
    msg=d.refresh_minutes?"Refresh interval saved: every "+d.refresh_minutes+" min.":"Scheduled updates turned off.";
    e.target.blur();await loadConfig()}
  catch(err){msg="Error: "+err.message;e.target.blur();render()}};
// users
$("accBox").onclick=async e=>{
  const b=e.target.closest("button");if(!b)return;
  try{
    if(b.id==="fUserAdd"){const name=$("fUser").value.trim();const d=await api("api/users",{name});$("fUser").value="";
      msg=`Added user "${name}". Pick them from the 👤 menu at the top.`;await loadRemote()}
    else if(b.dataset.ua==="rename"){const id=Number(b.dataset.id),cur=(USERS.find(u=>u.id===id)||{}).name||"";
      const name=prompt("New name",cur);if(name===null)return;await api("api/users/rename",{id,name});msg="User renamed.";await loadRemote()}
    else if(b.dataset.ua==="delete"){const id=Number(b.dataset.id),u=USERS.find(x=>x.id===id);
      if(!confirm(`Delete user "${u?u.name:id}" with all their dashboards and flags?`))return;
      await api("api/users/delete",{id});msg="User deleted.";if(id===me){me=null;dash=null;drafts={}}await loadRemote()}
    else return;
  }catch(err){msg="Error: "+err.message;render()}};
// dashboards (drafts survive re-renders; nothing is sent until Save)
const card=el=>el.closest(".dcard");
$("dashBox").addEventListener("input",e=>{
  const c=card(e.target);if(!c||e.target.dataset.f!=="name")return;
  const d=drafts[c.dataset.id];d.name=e.target.value;d.dirty=true;c.classList.add("dirty")});
$("dashBox").addEventListener("change",e=>{
  const c=card(e.target),f=e.target.dataset.f;if(!c||!f)return;
  const d=drafts[c.dataset.id];d.dirty=true;
  if(f==="all"){d.all=e.target.checked;renderAccounts(true)}
  else if(f==="src"){const s=e.target.dataset.s,i=d.sources.indexOf(s);
    if(e.target.checked&&i<0)d.sources.push(s);else if(!e.target.checked&&i>=0)d.sources.splice(i,1);c.classList.add("dirty")}});
$("dashBox").onclick=async e=>{
  const b=e.target.closest("button");if(!b)return;
  if(b.id==="fDashNew"){drafts["new"]={name:"",all:false,sources:[],dirty:true};renderAccounts(true);return}
  const c=card(b);if(!c)return;
  const id=c.dataset.id,d=drafts[id],act=b.dataset.da;
  try{
    if(act==="cancel"){delete drafts["new"];renderAccounts(true);return}
    if(act==="save"){
      const body={name:d.name,all:d.all,sources:d.all?[]:d.sources};
      if(id==="new"){const r=await api("api/dashboards",body);delete drafts["new"];msg=`Dashboard "${d.name.trim()}" created.`;
        await refreshDashes();await selectDash(r.id)}
      else{await api("api/dashboards/update",Object.assign({id:Number(id)},body));d.dirty=false;msg="Dashboard saved.";
        await refreshDashes();if(Number(id)===dash)await loadItems()}
      renderAccounts(true);render()}
    else if(act==="delete"){
      if(!confirm(`Delete dashboard "${d.name}"?`))return;
      await api("api/dashboards/delete",{id:Number(id)});msg="Dashboard deleted.";delete drafts[id];
      if(Number(id)===dash){dash=null}await refreshDashes();
      if(dash===null){dash=DASHES[0]?DASHES[0].id:null;lsSet(DKEY+me,String(dash));await loadItems()}
      renderAccounts(true);render()}
  }catch(err){msg="Error: "+err.message;render()}};
$("cfg").onclick=async e=>{
  const b=e.target.closest("button");if(!b)return;
  const a=b.dataset.a,n=b.dataset.n,v=id=>$(id).value.trim();
  try{
    if(b.id==="upd"){await api("api/update");wasUpdating=true}
    else if(b.id==="fAdd"){
      const p={url:v("fUrl"),name:v("fName"),type:v("fType")};
      if(p.type==="sitemap")p.url_contains=v("fContains");
      if(p.type==="scrape"){p.item=v("fItem");p.title=v("fTitle");p.link=v("fLink")}
      const d=await api("api/sources",p);wasUpdating=!!d.updating;
      ["fUrl","fName","fContains","fItem","fTitle","fLink"].forEach(id=>$(id).value="");
      msg=`Added "${d.name}" (${d.type}). Fetching...`;await loadConfig();return}
    else if(a==="refresh"){await api("api/update",{source:n});wasUpdating=true}
    else if(a==="toggle"){const on=b.dataset.e==="1";await api("api/sources/toggle",{name:n,enabled:on});wasUpdating=on}
    else if(a==="remove"){if(!confirm("Remove source "+n+"?"))return;await api("api/sources/remove",{name:n})}
    else return;
    msg="";await loadConfig();
  }catch(err){msg="Error: "+err.message;render()}
};
window.addEventListener("hashchange",()=>{fromHash();render()});
document.addEventListener("visibilitychange",()=>{if(!document.hidden){auto?tick():loadRemote()}});
$("auto").checked=auto;
syncDrafts();fromHash();render();loadRemote();
if(auto)autoT=setInterval(tick,AUTO_MS);
</script></body></html>
"""


def main():
    ap = argparse.ArgumentParser(description="Cyber news dashboard")
    ap.add_argument("--sample", action="store_true", help="render offline preview with fake data")
    sub = ap.add_subparsers(dest="cmd")
    add = sub.add_parser("add", help="discover a feed and append it to feeds.yml")
    add.add_argument("url")
    add.add_argument("-n", "--name")
    args = ap.parse_args()
    if args.cmd == "add":
        sys.exit(add_source(args.url, args.name))
    sample() if args.sample else run_update()


if __name__ == "__main__":
    main()
