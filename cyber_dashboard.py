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

BASE = Path(__file__).resolve().parent
CONFIG = BASE / "feeds.yml"
LOCAL_CONFIG = BASE / "feeds.local.yml"  # written by the UI (Config tab), not tracked by git
DB = str(BASE / "news.db")
OUT = BASE / "public" / "index.html"
KEEP_DAYS = 30
DEFAULT_LIMIT = 40
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
    con.execute("CREATE TABLE IF NOT EXISTS read_state(url TEXT PRIMARY KEY)")
    con.execute("""CREATE TABLE IF NOT EXISTS source_status(
        name TEXT PRIMARY KEY, last_attempt INTEGER, last_success INTEGER, ok INTEGER,
        error TEXT, fetched INTEGER, new_items INTEGER)""")
    con.execute("""CREATE TABLE IF NOT EXISTS fetch_log(
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, source TEXT, level TEXT, message TEXT)""")
    return con


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
    con.execute("DELETE FROM items WHERE published < ?", (now - KEEP_DAYS * 86400,))
    con.execute("DELETE FROM read_state WHERE url NOT IN (SELECT url FROM items)")
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
    return dict(sources=sources, updating=False,
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

    cfg = dict(updating=False, last_update=now - 720, sources=[
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
    render(con, {"CVE-2026-00001", "CVE-2026-00007"}, banner="Sample data: fictional headlines and sources, layout preview only",
           cfg=cfg, demo=True)


# ---------- rendering ----------

def render(con, kev, banner="", cfg=None, demo=False):
    rows = con.execute("SELECT title,url,source,published,summary,cves,tags FROM items "
                       "ORDER BY published DESC LIMIT 400").fetchall()
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
    cfg = cfg or config_snapshot(con)
    page = (TEMPLATE.replace("__DATA__", json.dumps(items, ensure_ascii=False).replace("</", "<\\/"))
            .replace("__TAGS__", json.dumps(sorted(all_tags)))
            .replace("__CFG__", json.dumps(cfg, ensure_ascii=False).replace("</", "<\\/"))
            .replace("__DEMO__", "true" if demo else "false")
            .replace("__UPDATED__", time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()))
            .replace("__BANNER__", f'<div class="banner">{html.escape(banner)}</div>' if banner else ""))
    OUT.parent.mkdir(exist_ok=True)
    tmp = OUT.with_suffix(".tmp")  # atomic: the server never serves a half-written page
    tmp.write_text(page, encoding="utf-8")
    tmp.replace(OUT)
    print(f"[+] wrote {OUT} ({len(items)} items)")


TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Cyber News Dashboard</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--fg:#1a1d21;--mute:#667;--bd:#dde1e6;--acc:#2563eb;--kev:#dc2626}
@media(prefers-color-scheme:dark){:root{--bg:#0f1216;--card:#171b21;--fg:#e6e9ee;--mute:#8b95a3;--bd:#2a313b;--acc:#60a5fa;--kev:#f87171}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}
main{max-width:900px;margin:0 auto;padding:20px 16px}
h1{font-size:1.4rem;margin:0}.sub{color:var(--mute);font-size:.85rem;margin-bottom:14px}
.banner{background:var(--card);border:1px dashed var(--acc);color:var(--acc);border-radius:8px;padding:6px 12px;margin-bottom:12px;font-size:.85rem}
input{width:100%;padding:10px 12px;border:1px solid var(--bd);border-radius:8px;background:var(--card);color:var(--fg);font:inherit}
.chips{display:flex;flex-wrap:wrap;gap:6px;margin:10px 0 16px}
.chip{border:1px solid var(--bd);background:var(--card);color:var(--fg);border-radius:999px;padding:3px 12px;cursor:pointer;font:inherit;font-size:.82rem}
.chip.on{background:var(--acc);border-color:var(--acc);color:#fff}
.card{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:12px 14px;margin-bottom:10px}
.card a{color:var(--fg);font-weight:600;text-decoration:none}.card a:hover{color:var(--acc)}
.meta{color:var(--mute);font-size:.78rem;margin-top:2px}.sum{margin:6px 0;color:var(--mute);font-size:.88rem}
.tag{display:inline-block;font-size:.72rem;border:1px solid var(--bd);border-radius:4px;padding:0 6px;margin-right:4px}
.tag.kev{border-color:var(--kev);color:var(--kev);font-weight:700}
.tabs{display:flex;gap:4px;border-bottom:1px solid var(--bd);margin-bottom:12px}
.tab{background:none;border:0;border-bottom:2px solid transparent;color:var(--mute);padding:8px 14px;cursor:pointer;font:inherit}
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
.row{display:flex;gap:8px;margin-top:8px;flex-wrap:wrap}.row>input{flex:1;min-width:140px}
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
</style></head><body><main>
<h1>Cyber News Dashboard</h1>
<div class="sub">Updated __UPDATED__ · <span id="count"></span></div>
__BANNER__
<nav class="tabs" id="tabs"></nav>
<input id="q" type="search" placeholder="Search title, CVE, source…">
<div class="chips" id="chips"></div>
<div id="list"></div>
<section id="cfg" hidden>
<div class="cfgbar"><span id="cfgInfo"></span><button class="rd" id="upd" hidden>Update now</button></div>
<div class="note" id="cfgMsg" hidden></div>
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
const DATA=__DATA__, TAGS=__TAGS__, DEMO=__DEMO__;
const KEY="cnd:read", VIEWS={all:"All",unread:"Not read",read:"Read",config:"Config"};
let active=new Set(), q="", view="all", read=new Set(), shown=[];
let CFG=__CFG__, editable=DEMO, msg="", errOnly=false, poll=null, wasUpdating=false, synced=false;
try{read=new Set(JSON.parse(localStorage.getItem(KEY)||"[]"))}catch(e){}
const known=new Set(DATA.map(i=>i.url));
read=new Set([...read].filter(u=>known.has(u)));
const $=id=>document.getElementById(id);
const save=()=>{try{localStorage.setItem(KEY,JSON.stringify([...read]))}catch(e){}};
const esc=s=>String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const ago=ts=>{const h=(Date.now()/1000-ts)/3600;return h<1?Math.round(h*60)+" min ago":h<48?Math.round(h)+" h ago":Math.round(h/24)+" d ago"};
const EMPTY={all:"No items match.",unread:"All caught up.",read:"Nothing marked as read yet."};
// ---- server sync (only when served by server.py)
async function loadRemote(){try{const r=await fetch("api/read",{cache:"no-store"});if(!r.ok)return;
  const d=await r.json();if(!Array.isArray(d.read))return;
  read=new Set(d.read.filter(u=>known.has(u)));synced=true;save();render();loadConfig()}catch(e){}}
function push(urls,flag){if(!synced)return;
  fetch("api/read",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({urls,read:flag})}).catch(()=>{})}
async function api(path,body){
  if(DEMO)throw new Error("demo preview, no server attached - nothing was changed");
  const r=await fetch(path,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body||{})});
  let d={};try{d=await r.json()}catch(e){}
  if(!r.ok)throw new Error(d.error||"HTTP "+r.status);
  return d}
async function loadConfig(){
  try{const r=await fetch("api/config",{cache:"no-store"});if(!r.ok)return;
    CFG=await r.json();editable=true;
    if(CFG.updating){wasUpdating=true;if(!poll)poll=setInterval(loadConfig,1500)}
    else{if(poll){clearInterval(poll);poll=null}
      if(wasUpdating){wasUpdating=false;msg="Update finished. Reload the page to see new items."}}
    render()}catch(e){}}
function fromHash(){const h=location.hash.slice(1);view=VIEWS[h]?h:"all"}
// ---- Config tab
function renderConfig(){
  $("cfgInfo").textContent="Last update: "+(CFG.last_update?ago(CFG.last_update):"never")+(CFG.updating?" · updating...":"");
  $("upd").hidden=!editable;$("upd").disabled=!!CFG.updating;$("addBox").hidden=!editable;
  const note=editable?msg:"Read-only view: status as of the last build. Adding sources from here needs the self-hosted server (see README).";
  $("cfgMsg").hidden=!note;$("cfgMsg").textContent=note;
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
  const n={all:DATA.length,read:DATA.filter(i=>read.has(i.url)).length};n.unread=n.all-n.read;
  const f=DATA.filter(i=>(view==="all"||(view==="read")===read.has(i.url))&&
    (!active.size||[...active].every(t=>i.tags.includes(t)))&&
    (!q||(i.title+i.source+i.summary+i.cves.join(" ")).toLowerCase().includes(q)));
  shown=cfg?[]:f;
  const bulkN=cfg?0:view==="read"?f.length:f.filter(i=>!read.has(i.url)).length;
  const failed=CFG.sources.filter(s=>s.enabled&&s.status&&!s.status.ok).length;
  $("tabs").innerHTML=Object.keys(VIEWS).map(v=>`<button class="tab ${v===view?"on":""}" data-v="${v}">${VIEWS[v]}${v==="config"?(failed?" ⚠ "+failed:""):" ("+n[v]+")"}</button>`).join("")+
    (bulkN?`<button class="rd" id="bulk">${view==="read"?"Mark all as unread":"Mark all as read"} (${bulkN})</button>`:"");
  for(const id of ["q","chips","list"])$(id).hidden=cfg;
  $("cfg").hidden=!cfg;
  if(cfg){$("count").textContent=CFG.sources.length+" sources";renderConfig();return}
  $("count").textContent=f.length+" items";
  $("list").innerHTML=f.length?f.map(i=>{const r=read.has(i.url);return `<div class="card ${r?"read":""}">
    <a href="${esc(i.url)}" target="_blank" rel="noopener noreferrer">${esc(i.title)}</a>
    <div class="meta">${esc(i.source)} · ${ago(i.ts)}</div>
    ${i.summary?`<div class="sum">${esc(i.summary)}</div>`:""}
    <div class="foot"><div>${i.tags.map(t=>`<span class="tag ${t==="KEV"?"kev":""}">${esc(t)}</span>`).join("")}
    ${i.cves.slice(0,5).map(c=>`<span class="tag ${i.kev.includes(c)?"kev":""}">${esc(c)}</span>`).join("")}</div>
    <button class="rd" data-u="${esc(i.url)}">${r?"Mark as unread":"Mark as read"}</button></div></div>`}).join(""):
    `<div class="empty">${EMPTY[view]}</div>`;
}
// ---- events
$("chips").innerHTML=TAGS.map(t=>`<button class="chip" data-t="${esc(t)}">${esc(t)}</button>`).join("");
$("chips").onclick=e=>{const t=e.target.dataset.t;if(!t)return;
  active.has(t)?active.delete(t):active.add(t);e.target.classList.toggle("on");render()};
$("tabs").onclick=e=>{
  if(e.target.id==="bulk"){const mark=view!=="read";
    shown.forEach(i=>mark?read.add(i.url):read.delete(i.url));save();push(shown.map(i=>i.url),mark);render();return}
  const v=e.target.dataset.v;if(!v)return;
  view=v;try{history.replaceState(null,"","#"+v)}catch(_){}render();if(v==="config")loadConfig()};
$("list").onclick=e=>{const b=e.target.closest(".rd");if(!b)return;
  const u=b.dataset.u,flag=!read.has(u);flag?read.add(u):read.delete(u);save();push([u],flag);render()};
$("q").oninput=e=>{q=e.target.value.toLowerCase();render()};
$("fType").onchange=e=>{$("xSitemap").hidden=e.target.value!=="sitemap";$("xScrape").hidden=e.target.value!=="scrape"};
$("errOnly").onchange=e=>{errOnly=e.target.checked;renderConfig()};
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
document.addEventListener("visibilitychange",()=>{if(!document.hidden)loadRemote()});
fromHash();render();loadRemote();
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
