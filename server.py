#!/usr/bin/env python3
"""Self-hosted server: serves the dashboard, users and dashboards, read/Important sync, sources and schedule.

Standard library only (plus the dependencies of cyber_dashboard.py).
Run:  python server.py [--host 0.0.0.0] [--port 8080]

Environment:
  ALLOWED_HOSTS       extra Host header values to accept (comma separated)
  NO_SCHEDULER        set to 1 to disable the built-in scheduler (updates only on demand)
  SCHEDULER_TICK      seconds between scheduler checks (default 20)
  ALLOW_PRIVATE_URLS  set to 1 to let the UI add sources on private/LAN addresses
"""
import argparse
import ipaddress
import json
import os
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import cyber_dashboard as cd
import profiles

MAX_BODY = 1_000_000
SCHEDULER_TICK = max(1, int(os.environ.get("SCHEDULER_TICK", "20")))
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

def _set_flags(table, uid, urls, flag):
    """Add/remove URLs in one of the per-user flag tables (table name is a constant, never user input)."""
    if not isinstance(urls, list):
        raise TypeError("urls must be a list")
    urls = [u for u in urls if isinstance(u, str)]
    con = db()
    try:
        with con:
            if flag:
                con.executemany(f"INSERT OR IGNORE INTO {table}(user_id, url) VALUES (?, ?)", [(uid, u) for u in urls])
            else:
                con.executemany(f"DELETE FROM {table} WHERE user_id = ? AND url = ?", [(uid, u) for u in urls])
    finally:
        con.close()
    return {"ok": True, "count": len(urls)}


def api_read(p, uid):
    return _set_flags("user_read", uid, p["urls"], bool(p["read"]))


def api_important(p, uid):
    return _set_flags("user_important", uid, p["urls"], bool(p["important"]))


def api_settings(p):
    """Currently one setting: how often the built-in scheduler refreshes all sources."""
    raw = p["refresh_minutes"]
    if isinstance(raw, bool):
        raise ApiError(400, "refresh_minutes must be a number")
    try:
        mins = int(raw)
    except (TypeError, ValueError):
        raise ApiError(400, "refresh_minutes must be a number")
    if mins != 0 and not cd.MIN_REFRESH_MIN <= mins <= cd.MAX_REFRESH_MIN:
        raise ApiError(400, f"Choose 0 (manual only) or {cd.MIN_REFRESH_MIN}-{cd.MAX_REFRESH_MIN} minutes")
    con = db()
    try:
        with con:
            cd.set_setting(con, "refresh_minutes", mins)
            cd.log(con, "settings", "info", f"refresh interval set to {mins} min" if mins else "scheduled updates turned off")
    finally:
        con.close()
    return {"ok": True, "refresh_minutes": mins}


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


def known_sources():
    return {s["name"] for s in cd.load_config()}


def run_profiles(fn, *args):
    """Run a profiles.* function in its own transaction and translate its errors to HTTP errors."""
    con = db()
    try:
        with con:
            return fn(con, *args)
    except profiles.NotFound as e:
        raise ApiError(404, str(e))
    except ValueError as e:
        raise ApiError(400, str(e))
    finally:
        con.close()


def api_user_create(p):
    uid = run_profiles(profiles.create_user, p.get("name"))
    return {"ok": True, "id": uid}


def api_user_rename(p):
    run_profiles(profiles.rename_user, int(p["id"]), p.get("name"))
    return {"ok": True}


def api_user_delete(p):
    run_profiles(profiles.delete_user, int(p["id"]))
    return {"ok": True}


def api_dash_create(p, uid):
    did = run_profiles(profiles.create_dashboard, uid, p.get("name"), bool(p.get("all")),
                       p.get("sources", []), known_sources())
    return {"ok": True, "id": did}


def api_dash_update(p, uid):
    run_profiles(profiles.update_dashboard, uid, int(p["id"]), p.get("name"), bool(p.get("all")),
                 p.get("sources", []), known_sources())
    return {"ok": True}


def api_dash_delete(p, uid):
    run_profiles(profiles.delete_dashboard, uid, int(p["id"]))
    return {"ok": True}


# path -> (handler, needs_user). Handlers that need a user also receive the user id.
ROUTES = {
    "/api/read": (api_read, True), "/api/important": (api_important, True),
    "/api/dashboards": (api_dash_create, True), "/api/dashboards/update": (api_dash_update, True),
    "/api/dashboards/delete": (api_dash_delete, True),
    "/api/users": (api_user_create, False), "/api/users/rename": (api_user_rename, False),
    "/api/users/delete": (api_user_delete, False),
    "/api/settings": (api_settings, False), "/api/sources": (api_add, False),
    "/api/sources/toggle": (api_toggle, False), "/api/sources/remove": (api_remove, False),
    "/api/update": (api_update, False),
}


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

    def _user(self):
        """The profile making the request (X-User header). This only says who is using the page; it is not authentication."""
        try:
            uid = int(self.headers.get("X-User", ""))
        except ValueError:
            raise ApiError(400, "Missing or invalid X-User header")
        con = db()
        try:
            if not profiles.get_user(con, uid):
                raise ApiError(404, "Unknown user")
        finally:
            con.close()
        return uid

    def do_GET(self):
        if not self._guard():
            return
        u = urlparse(self.path)
        try:
            self._get(u.path, parse_qs(u.query))
        except ApiError as e:
            self._send(e.code, {"error": str(e)})
        except (ValueError, KeyError, TypeError):
            self._send(400, {"error": "bad request"})

    def _get(self, path, qs):
        if path in ("/", "/index.html"):
            if cd.OUT.exists():
                self._send(200, cd.OUT.read_bytes(), "text/html; charset=utf-8")
            else:
                self._send(503, b"Dashboard not built yet. Run: python cyber_dashboard.py", "text/plain")
        elif path in ("/api/read", "/api/important"):
            table = "user_read" if path == "/api/read" else "user_important"
            uid = self._user()
            con = db()
            try:
                urls = [r[0] for r in con.execute(f"SELECT url FROM {table} WHERE user_id = ?", (uid,))]
            finally:
                con.close()
            self._send(200, {("read" if path == "/api/read" else "important"): urls})
        elif path == "/api/users":
            con = db()
            try:
                self._send(200, {"users": profiles.list_users(con)})
            finally:
                con.close()
        elif path == "/api/dashboards":
            uid = self._user()
            con = db()
            try:
                dashes = profiles.list_dashboards(con, uid)
                counts = profiles.unread_counts(con, uid, dashes)
            finally:
                con.close()
            for d in dashes:
                d["unread"] = counts.get(d["id"], 0)
            self._send(200, {"dashboards": dashes})
        elif path == "/api/items":
            did = int(qs["dashboard"][0]) if "dashboard" in qs else None
            uid = self._user() if did is not None else None
            con = db()
            try:
                sources = None
                if did is not None:
                    try:
                        sources = profiles.source_filter(con, uid, did)
                    except profiles.NotFound as e:
                        raise ApiError(404, str(e))
                payload = cd.items_payload(con, cd.cached_kev(), sources, uid)
            finally:
                con.close()
            self._send(200, payload)
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
        route = ROUTES.get(self.path.split("?")[0])
        if not route:
            return self._send(404, {"error": "not found"})
        handler, needs_user = route
        # Requiring JSON forces a CORS preflight, so other websites cannot call these endpoints.
        if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
            return self._send(415, {"error": "expected application/json"})
        try:
            uid = self._user() if needs_user else None
            length = int(self.headers.get("Content-Length", 0))
            if length > MAX_BODY:
                raise ValueError("body too large")
            body = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(body, dict):
                raise TypeError("body must be an object")
            code, out = 200, (handler(body, uid) if needs_user else handler(body))
        except ApiError as e:
            code, out = e.code, {"error": str(e)}
        except (ValueError, KeyError, TypeError):
            code, out = 400, {"error": "bad request"}
        self._send(code, out)


def scheduler():
    """Runs a full update whenever the configured interval has passed since the last run started."""
    time.sleep(5)
    while True:
        try:
            con = db()
            try:
                mins = cd.get_refresh_minutes(con)
                last = int(cd.get_setting(con, "last_run", 0) or 0)
            finally:
                con.close()
            if mins > 0 and time.time() - last >= mins * 60:
                try:
                    start_update()
                except ApiError:
                    pass  # an update is already running
        except Exception as e:
            print(f"[!] scheduler: {e}")
        time.sleep(SCHEDULER_TICK)


def main():
    ap = argparse.ArgumentParser(description="Cyber news dashboard server")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()
    cd.init_db().close()  # make sure tables exist
    if os.environ.get("NO_SCHEDULER") != "1":
        threading.Thread(target=scheduler, daemon=True).start()
    print(f"Serving on http://{args.host}:{args.port}")
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
