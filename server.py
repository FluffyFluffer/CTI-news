#!/usr/bin/env python3
"""Self-hosted server: serves the dashboard, syncs read/unread state and manages sources.

Standard library only (plus the dependencies of cyber_dashboard.py).
Run:  python server.py [--host 0.0.0.0] [--port 8080]

Environment:
  ALLOWED_HOSTS       extra Host header values to accept (comma separated)
  ALLOW_PRIVATE_URLS  set to 1 to let the UI add sources on private/LAN addresses
"""
import argparse
import ipaddress
import json
import os
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import cyber_dashboard as cd

MAX_BODY = 1_000_000
ALLOWED_SUFFIXES = (".lan", ".local", ".home", ".home.arpa", ".ts.net")
UPDATE_LOCK = threading.Lock()   # held while an update runs
CONFIG_LOCK = threading.Lock()   # serialises edits of feeds.local.yml


class ApiError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def host_allowed(header):
    """Blocks DNS-rebinding: accept IPs, single-label names, LAN/tailnet suffixes and ALLOWED_HOSTS."""
    host = (header or "").strip().lower()
    host = host[1:host.find("]")] if host.startswith("[") else host.split(":")[0]
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    extra = [h.strip().lower() for h in os.environ.get("ALLOWED_HOSTS", "").split(",") if h.strip()]
    return "." not in host or host.endswith(ALLOWED_SUFFIXES) or host in extra


def db():
    return sqlite3.connect(cd.DB, timeout=10)


def start_update(only=None):
    if not UPDATE_LOCK.acquire(blocking=False):
        raise ApiError(409, "An update is already running")

    def job():
        try:
            cd.run_update(only)
        except Exception as e:
            print(f"[!] update failed: {e}")
        finally:
            UPDATE_LOCK.release()

    threading.Thread(target=job, daemon=True).start()


def find_source(name):
    return next((s for s in cd.load_config() if s["name"] == name), None)


# ---------- API handlers: take the JSON body, return a dict, raise ApiError on failure ----------

def api_read(p):
    urls = [u for u in p["urls"] if isinstance(u, str)]
    flag = bool(p["read"])
    con = db()
    try:
        with con:
            if flag:
                con.executemany("INSERT OR IGNORE INTO read_state(url) VALUES (?)", [(u,) for u in urls])
            else:
                con.executemany("DELETE FROM read_state WHERE url = ?", [(u,) for u in urls])
    finally:
        con.close()
    return {"ok": True, "count": len(urls)}


def api_add(p):
    url = str(p.get("url", "")).strip()
    if not url:
        raise ApiError(400, "URL is required")
    if "://" not in url:
        url = "https://" + url
    kind = p.get("type", "detect")
    name = (str(p.get("name") or "").strip() or urlparse(url).netloc.removeprefix("www."))[:80]
    try:
        cd.validate_url(url)
        if kind == "detect":
            feed = cd.discover_feed(url)
            if not feed:
                raise ApiError(422, "No feed found on that page. Try 'Sitemap' or 'HTML scrape'.")
            cd.validate_url(feed)
            kind, url = "rss", feed
        elif kind not in ("rss", "sitemap", "scrape"):
            raise ApiError(400, "Unknown source type")
    except ValueError as e:
        raise ApiError(400, str(e))
    entry = {"name": name, "type": kind, "url": url}
    if kind == "sitemap" and str(p.get("url_contains") or "").strip():
        entry["url_contains"] = str(p["url_contains"]).strip()
    if kind == "scrape":
        if not str(p.get("item") or "").strip():
            raise ApiError(400, "Item selector is required for HTML scrape")
        entry["item"] = str(p["item"]).strip()
        for k in ("title", "link"):
            if str(p.get(k) or "").strip():
                entry[k] = str(p[k]).strip()
    with CONFIG_LOCK:
        if find_source(name):
            raise ApiError(409, f"A source named '{name}' already exists")
        local = cd.read_local()
        local.append(entry)
        cd.write_local(local)
    try:
        start_update(name)
        started = True
    except ApiError:
        started = False  # another update is running; the new source is picked up next run
    return {"ok": True, "name": name, "type": kind, "url": url, "updating": started}


def api_toggle(p):
    name, flag = str(p["name"]), bool(p["enabled"])
    with CONFIG_LOCK:
        if not find_source(name):
            raise ApiError(404, "Unknown source")
        local = cd.read_local()
        for e in local:
            if e.get("name") == name:
                e["enabled"] = flag
                break
        else:
            local.append({"name": name, "enabled": flag})  # override of a feeds.yml source
        cd.write_local(local)
    if flag:
        try:
            start_update(name)
        except ApiError:
            pass
    return {"ok": True}


def api_remove(p):
    name = str(p["name"])
    with CONFIG_LOCK:
        src = find_source(name)
        if not src:
            raise ApiError(404, "Unknown source")
        if src["origin"] != "local":
            raise ApiError(400, "This source comes from feeds.yml - disable it instead")
        cd.write_local([e for e in cd.read_local() if e.get("name") != name])
    con = db()
    try:
        with con:
            con.execute("DELETE FROM source_status WHERE name = ?", (name,))
    finally:
        con.close()
    return {"ok": True}


def api_update(p):
    only = p.get("source") or None
    if only and not find_source(only):
        raise ApiError(404, "Unknown source")
    start_update(only)
    return {"ok": True, "updating": True}


ROUTES = {"/api/read": api_read, "/api/sources": api_add, "/api/sources/toggle": api_toggle,
          "/api/sources/remove": api_remove, "/api/update": api_update}


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _guard(self):
        if host_allowed(self.headers.get("Host")):
            return True
        self._send(403, {"error": "Host not allowed. Set ALLOWED_HOSTS to add your hostname."})
        return False

    def do_GET(self):
        if not self._guard():
            return
        path = self.path.split("?")[0]
        if path in ("/", "/index.html"):
            if cd.OUT.exists():
                self._send(200, cd.OUT.read_bytes(), "text/html; charset=utf-8")
            else:
                self._send(503, b"Dashboard not built yet. Run: python cyber_dashboard.py", "text/plain")
        elif path == "/api/read":
            con = db()
            try:
                urls = [r[0] for r in con.execute("SELECT url FROM read_state")]
            finally:
                con.close()
            self._send(200, {"read": urls})
        elif path == "/api/config":
            con = db()
            try:
                snap = cd.config_snapshot(con)
            finally:
                con.close()
            snap["updating"] = UPDATE_LOCK.locked()
            self._send(200, snap)
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._guard():
            return
        handler = ROUTES.get(self.path.split("?")[0])
        if not handler:
            return self._send(404, {"error": "not found"})
        # Requiring JSON forces a CORS preflight, so other websites cannot call these endpoints.
        if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
            return self._send(415, {"error": "expected application/json"})
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length > MAX_BODY:
                raise ValueError("body too large")
            body = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(body, dict):
                raise TypeError("body must be an object")
            code, out = 200, handler(body)
        except ApiError as e:
            code, out = e.code, {"error": str(e)}
        except (ValueError, KeyError, TypeError):
            code, out = 400, {"error": "bad request"}
        self._send(code, out)


def main():
    ap = argparse.ArgumentParser(description="Cyber news dashboard server")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()
    cd.init_db().close()  # make sure tables exist
    print(f"Serving on http://{args.host}:{args.port}")
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
