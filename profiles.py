"""Users (profiles without passwords) and their dashboards.

* A user owns dashboards and has their own read / Important flags.
* A dashboard is a named selection of sources. A dashboard with ``all_sources`` follows the
  full source list, including sources added later.
* The source list itself (feeds.yml + feeds.local.yml) is shared by everyone.

Profiles are NOT a security boundary: they only separate who sees what. Anyone who can open the
server can switch to any profile, so keep it on your LAN / tailnet.

All functions take an open sqlite3 connection and do not commit; the caller owns the transaction.
"""
import sqlite3

MAX_NAME = 40
MAX_USERS = 20
MAX_DASHBOARDS = 30
LIST_LIMIT = 400  # items shown per dashboard (same number as cyber_dashboard.load_items)
DEFAULT_USER = "Default"
DEFAULT_DASHBOARD = "Everything"


class NotFound(LookupError):
    """Unknown user or dashboard (or one that belongs to somebody else)."""


# ---------- schema + migration ----------

def ensure_schema(con):
    """Create the tables (idempotent) and move the flags of older versions to the first user."""
    con.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE COLLATE NOCASE)""")
    con.execute("""CREATE TABLE IF NOT EXISTS dashboards(
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
        name TEXT NOT NULL COLLATE NOCASE, all_sources INTEGER NOT NULL DEFAULT 0,
        UNIQUE(user_id, name))""")
    con.execute("""CREATE TABLE IF NOT EXISTS dashboard_sources(
        dashboard_id INTEGER NOT NULL, source TEXT NOT NULL, PRIMARY KEY(dashboard_id, source))""")
    con.execute("""CREATE TABLE IF NOT EXISTS user_read(
        user_id INTEGER NOT NULL, url TEXT NOT NULL, PRIMARY KEY(user_id, url))""")
    con.execute("""CREATE TABLE IF NOT EXISTS user_important(
        user_id INTEGER NOT NULL, url TEXT NOT NULL, PRIMARY KEY(user_id, url))""")

    first = con.execute("SELECT MIN(id) FROM users").fetchone()[0]
    if first is None:
        try:
            first = create_user(con, DEFAULT_USER)
        except (sqlite3.IntegrityError, ValueError):  # another process created it a moment ago
            first = con.execute("SELECT MIN(id) FROM users").fetchone()[0]

    tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    for old, new in (("read_state", "user_read"), ("important_state", "user_important")):
        if old in tables:  # single-user versions kept the flags without an owner
            con.execute(f"INSERT OR IGNORE INTO {new}(user_id, url) SELECT ?, url FROM {old}", (first,))
            con.execute(f"DROP TABLE {old}")
    con.commit()


# ---------- validation ----------

def clean_name(raw, label="Name"):
    name = " ".join(str(raw or "").split())
    if not name:
        raise ValueError(f"{label} is required")
    if len(name) > MAX_NAME:
        raise ValueError(f"{label} is too long (max {MAX_NAME} characters)")
    if not name.isprintable():
        raise ValueError(f"{label} contains invalid characters")
    return name


def _check_sources(sources, known):
    if not isinstance(sources, list):
        raise ValueError("sources must be a list")
    out = []
    for s in sources:
        if not isinstance(s, str):
            raise ValueError("sources must be a list of names")
        if s not in known:
            raise ValueError(f"Unknown source: {s}")
        if s not in out:
            out.append(s)
    return out


# ---------- users ----------

def list_users(con):
    return [{"id": i, "name": n} for i, n in con.execute("SELECT id, name FROM users ORDER BY id")]


def get_user(con, uid):
    row = con.execute("SELECT id, name FROM users WHERE id = ?", (uid,)).fetchone()
    return {"id": row[0], "name": row[1]} if row else None


def create_user(con, name):
    name = clean_name(name, "User name")
    if con.execute("SELECT COUNT(*) FROM users").fetchone()[0] >= MAX_USERS:
        raise ValueError(f"At most {MAX_USERS} users")
    try:
        uid = con.execute("INSERT INTO users(name) VALUES (?)", (name,)).lastrowid
    except sqlite3.IntegrityError:
        raise ValueError(f"A user named '{name}' already exists")
    con.execute("INSERT INTO dashboards(user_id, name, all_sources) VALUES (?, ?, 1)", (uid, DEFAULT_DASHBOARD))
    return uid


def rename_user(con, uid, name):
    name = clean_name(name, "User name")
    if not get_user(con, uid):
        raise NotFound("Unknown user")
    try:
        con.execute("UPDATE users SET name = ? WHERE id = ?", (name, uid))
    except sqlite3.IntegrityError:
        raise ValueError(f"A user named '{name}' already exists")


def delete_user(con, uid):
    if not get_user(con, uid):
        raise NotFound("Unknown user")
    if con.execute("SELECT COUNT(*) FROM users").fetchone()[0] <= 1:
        raise ValueError("Cannot delete the last user")
    con.execute("DELETE FROM dashboard_sources WHERE dashboard_id IN (SELECT id FROM dashboards WHERE user_id = ?)", (uid,))
    for table in ("dashboards", "user_read", "user_important"):
        con.execute(f"DELETE FROM {table} WHERE user_id = ?", (uid,))
    con.execute("DELETE FROM users WHERE id = ?", (uid,))


# ---------- dashboards ----------

def _sources_of(con, did):
    return [r[0] for r in con.execute("SELECT source FROM dashboard_sources WHERE dashboard_id = ? ORDER BY source", (did,))]


def list_dashboards(con, uid):
    rows = con.execute("SELECT id, name, all_sources FROM dashboards WHERE user_id = ? ORDER BY id", (uid,)).fetchall()
    return [{"id": i, "name": n, "all": bool(a), "sources": _sources_of(con, i)} for i, n, a in rows]


def get_dashboard(con, uid, did):
    """The dashboard, but only if it belongs to `uid`."""
    row = con.execute("SELECT id, name, all_sources FROM dashboards WHERE id = ? AND user_id = ?", (did, uid)).fetchone()
    return {"id": row[0], "name": row[1], "all": bool(row[2]), "sources": _sources_of(con, row[0])} if row else None


def _require_sources(all_sources, sources, known):
    if all_sources:
        return []
    sources = _check_sources(sources, known)
    if not sources:
        raise ValueError("Select at least one source, or choose 'All sources'")
    return sources


def create_dashboard(con, uid, name, all_sources, sources, known):
    name = clean_name(name, "Dashboard name")
    if not get_user(con, uid):
        raise NotFound("Unknown user")
    if con.execute("SELECT COUNT(*) FROM dashboards WHERE user_id = ?", (uid,)).fetchone()[0] >= MAX_DASHBOARDS:
        raise ValueError(f"At most {MAX_DASHBOARDS} dashboards per user")
    sources = _require_sources(all_sources, sources, known)
    try:
        did = con.execute("INSERT INTO dashboards(user_id, name, all_sources) VALUES (?, ?, ?)",
                          (uid, name, int(bool(all_sources)))).lastrowid
    except sqlite3.IntegrityError:
        raise ValueError(f"You already have a dashboard named '{name}'")
    con.executemany("INSERT INTO dashboard_sources(dashboard_id, source) VALUES (?, ?)", [(did, s) for s in sources])
    return did


def update_dashboard(con, uid, did, name, all_sources, sources, known):
    name = clean_name(name, "Dashboard name")
    if not get_dashboard(con, uid, did):
        raise NotFound("Unknown dashboard")
    sources = _require_sources(all_sources, sources, known)
    try:
        con.execute("UPDATE dashboards SET name = ?, all_sources = ? WHERE id = ?", (name, int(bool(all_sources)), did))
    except sqlite3.IntegrityError:
        raise ValueError(f"You already have a dashboard named '{name}'")
    con.execute("DELETE FROM dashboard_sources WHERE dashboard_id = ?", (did,))
    con.executemany("INSERT INTO dashboard_sources(dashboard_id, source) VALUES (?, ?)", [(did, s) for s in sources])


def delete_dashboard(con, uid, did):
    if not get_dashboard(con, uid, did):
        raise NotFound("Unknown dashboard")
    if con.execute("SELECT COUNT(*) FROM dashboards WHERE user_id = ?", (uid,)).fetchone()[0] <= 1:
        raise ValueError("Cannot delete the last dashboard")
    con.execute("DELETE FROM dashboard_sources WHERE dashboard_id = ?", (did,))
    con.execute("DELETE FROM dashboards WHERE id = ?", (did,))


def source_filter(con, uid, did):
    """None for a dashboard that shows every source, else the list of its sources."""
    d = get_dashboard(con, uid, did)
    if not d:
        raise NotFound("Unknown dashboard")
    return None if d["all"] else d["sources"]


def unread_counts(con, uid, dashboards=None):
    """{dashboard id: unread items among the newest LIST_LIMIT items the dashboard shows}."""
    out = {}
    for d in (dashboards if dashboards is not None else list_dashboards(con, uid)):
        sources = None if d["all"] else d["sources"]
        if sources is not None and not sources:
            out[d["id"]] = 0
            continue
        where = "" if sources is None else f"WHERE source IN ({','.join('?' * len(sources))})"
        out[d["id"]] = con.execute(
            f"SELECT COUNT(*) FROM (SELECT url FROM items {where} ORDER BY published DESC LIMIT {LIST_LIMIT}) "
            "WHERE url NOT IN (SELECT url FROM user_read WHERE user_id = ?)",
            (list(sources) if sources is not None else []) + [uid]).fetchone()[0]
    return out
