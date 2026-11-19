# Cyber News Dashboard

A self-hosted aggregator for cybersecurity news. It pulls articles from RSS feeds, sitemaps and plain HTML pages, enriches them (CVE extraction, CISA KEV flagging, topic tags) and renders a fast, searchable single-page dashboard with read/unread tracking that syncs across your devices.

> **Live demo (sample data):** deploy the repo to GitHub Pages and put your link here.

## Features

- **Many source types, one config file.** Add a site by editing `feeds.yml` or running one command. No code changes.
- **Feed auto-discovery.** Give it a site URL and it finds the RSS/Atom feed (`<link rel="alternate">`, then common paths).
- **Fallbacks for sites without RSS:** sitemap reader (uses `og:title` / `og:description`) and CSS-selector scraper.
- **Enrichment**
  - extracts CVE IDs from titles and summaries
  - flags CVEs present in the [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog (red `KEV` tag)
  - keyword tagging: `ransomware`, `APT`, `vuln`, `breach`, `malware`, `phishing`, `AI`
- **Deduplication** by canonical URL, 30-day history in SQLite.
- **UI:** full-text search, combinable tag filters, dark mode, mobile-friendly.
- **Read tracking:** `All` / `Not read` / `Read` tabs, per-item toggle, "mark all as read" for the current filter.
- **Config tab:** per-source status (OK / FAILED / never fetched / disabled), last attempt and last success, entries and new items, the exact error message, and a fetch log with an "errors only" filter. In self-hosted mode you can also add, refresh, disable and remove sources from the browser.
- **Two deployment modes:** static site on GitHub Pages, or self-hosted on a Raspberry Pi with cross-device sync and private access over Tailscale.

## Architecture

```mermaid
flowchart LR
    A[feeds.yml + feeds.local.yml] --> B[cyber_dashboard.py]
    S1[RSS / Atom] --> B
    S2[Sitemaps] --> B
    S3[HTML scraping] --> B
    K[CISA KEV JSON] --> B
    B --> D[(SQLite news.db)]
    B --> H[public/index.html]
    H --> W[Browser]
    W <-->|read state, sources, status| V[server.py]
    V <--> D
```

- `cyber_dashboard.py` collects, deduplicates, enriches and renders a static page.
- `server.py` (optional, standard library only) serves that page and stores the read/unread state in the same SQLite file, so every device sees the same state.
- Without `server.py` the page falls back to `localStorage` (per browser).

## Quick start

Requires Python 3.9+.

```bash
git clone https://github.com/FluffyFluffer/CTI-news.git
cd cyber-news-dashboard
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python cyber_dashboard.py          # fetch news and build public/index.html
python server.py                   # serve on http://localhost:8080 (with cross-device read sync)
```

Preview the UI without network access (fake data):

```bash
python cyber_dashboard.py --sample
```

## Adding sources

Edit `feeds.yml`, or let the tool find the feed for you:

```bash
python cyber_dashboard.py add https://example.com -n "Example Blog"
```

| `type`    | Use it when                          | Fields                                           |
|-----------|--------------------------------------|--------------------------------------------------|
| `rss`     | you know the feed URL                | `url`                                            |
| `auto`    | you only know the site URL           | `url` (feed is discovered on each run)           |
| `sitemap` | the site has no feed but a sitemap   | `url`, optional `url_contains`, `limit`          |
| `scrape`  | plain HTML listing                   | `url`, `item`, optional `title`, `link` (CSS)    |

Every source also accepts `limit` (default 40) and `enabled: false`.

```yaml
- name: Plain HTML news page
  type: scrape
  url: https://example.com/news
  item: "article.post"
  title: "h2 a"
  link: "h2 a"
```

Items without a publication date (scraping) use the time they were first seen. Sitemap mode fetches up to 15 pages per run to stay polite.

## Config tab

Open the **Config** tab (a `⚠ N` badge shows how many sources failed on their last run).

- **Sources:** status per source, timestamps, entry counts and the error text (`HTTPError: 404 ...`, `no items found - check the CSS selectors`, timeouts, invalid feeds). An update that returns zero items counts as a failure, so dead feeds and broken selectors are visible instead of silent.
- **Log:** the last 150 events (14 days are kept), including a per-run summary and CISA KEV availability.
- **Static mode (GitHub Pages):** read-only, showing the status from the last build.
- **Self-hosted mode (`server.py`):** add a source (auto-detect feed, RSS URL, sitemap or HTML scrape), refresh one source or all, enable/disable, remove.

Sources added in the UI are stored in `feeds.local.yml` (machine-managed, git-ignored), which extends and overrides `feeds.yml` by source name. Built-in sources from `feeds.yml` can be disabled but not removed from the UI. Because the local file is not tracked, `git pull` never conflicts with your UI changes.

## Deployment

### Option A: GitHub Pages (public, static)

1. Push the repo to GitHub.
2. **Settings → Pages → Source: GitHub Actions**.
3. The workflow in `.github/workflows/update.yml` rebuilds and publishes the site every hour.

Read state is stored in the browser (`localStorage`) in this mode.

### Option B: Raspberry Pi (private, synced across devices)

Works on any Debian-based system (tested design target: Raspberry Pi OS, alongside Pi-hole).

```bash
sudo apt install -y python3-venv git
git clone https://github.com/FluffyFluffer/CTI-news.git
cd cyber-news-dashboard
bash deploy/install.sh
```

The installer creates a virtualenv, installs two systemd units and an hourly timer, runs a first build and starts the server on port `8080` (override with `PORT=9000 bash deploy/install.sh`).

| Service / timer                    | Purpose                                  |
|------------------------------------|------------------------------------------|
| `cyber-dashboard.service`          | web server + sync API                    |
| `cyber-dashboard-update.timer`     | hourly fetch and rebuild                 |

Useful commands:

```bash
systemctl status cyber-dashboard
journalctl -u cyber-dashboard-update -n 50     # last update run
sudo systemctl start cyber-dashboard-update    # refresh now
```

#### Access from your phone with Tailscale

Install [Tailscale](https://tailscale.com/) on the Pi and on your phone (same account). The phone can then reach the Pi from anywhere over an encrypted WireGuard tunnel, without opening any port on your router.

```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up
tailscale ip -4        # the Pi's Tailscale address
```

Then open `http://<tailscale-ip>:8080` (or `http://<pi-name>:8080` with MagicDNS) on the phone.

> **Do not port-forward 8080 to the internet and do not use Tailscale Funnel.** The server has no authentication by design; it is meant for your LAN and your tailnet only.

## Project layout

```
cyber_dashboard.py     collect -> enrich -> store -> render (also the CLI)
server.py              static file + read-state + source-management API (stdlib only)
feeds.yml              default sources (tracked in git)
feeds.local.yml        sources added/overridden in the UI (git-ignored, created on demand)
deploy/install.sh      Raspberry Pi installer (systemd)
.github/workflows/     hourly GitHub Pages build
```

### API

| Method | Path        | Body                                     | Result                |
|--------|-------------|------------------------------------------|-----------------------|
| GET    | `/api/read` |                                          | `{"read": [urls...]}` |
| POST   | `/api/read` | `{"urls": [...], "read": true\|false}`   | `{"ok": true}`        |

All POST endpoints require `Content-Type: application/json`, which forces a CORS preflight and prevents other websites from calling them.

| Method | Path                    | Body                                          | Purpose                            |
|--------|-------------------------|-----------------------------------------------|------------------------------------|
| GET    | `/api/config`           |                                               | sources, status, log, `updating`   |
| POST   | `/api/sources`          | `{url, type, name?, url_contains?, item?, title?, link?}` | add a source (`type`: `detect`, `rss`, `sitemap`, `scrape`) |
| POST   | `/api/sources/toggle`   | `{"name": "...", "enabled": true\|false}`     | enable / disable                   |
| POST   | `/api/sources/remove`   | `{"name": "..."}`                             | remove a UI-added source           |
| POST   | `/api/update`           | `{}` or `{"source": "..."}`                   | start an update in the background  |

## Security notes

The server has **no authentication**. It is meant for your LAN and your Tailscale network only. Never port-forward it and never use Tailscale Funnel. Built-in safeguards:

- **SSRF guard:** sources added from the UI must resolve to public addresses. Loopback, private, link-local, CGNAT (Tailscale) and `0.0.0.0` (Pi-hole-blocked) targets are rejected. Override with `ALLOW_PRIVATE_URLS=1` if you really need an internal source. Sources written by hand in `feeds.yml` are trusted and not checked.
- **Host header check (anti DNS-rebinding):** requests are accepted only for IP addresses, single-label names and the suffixes `.lan`, `.local`, `.home`, `.home.arpa`, `.ts.net`. For any other hostname set `ALLOWED_HOSTS=news.example.com,other.name` in the service environment.
- **JSON-only writes** (CORS preflight) and a 1 MB request limit.
- The write API can change your source list and trigger outbound requests, so keep access limited to devices you trust.

## Roadmap

- importance scoring (KEV, EPSS, ransomware mentions, number of sources covering a story)
- clustering duplicate stories from different outlets into a single card
- MITRE ATT&CK technique and threat-actor extraction
- optional LLM summaries
- tests for collectors with recorded fixtures

## Notes

- Respect each site's terms and `robots.txt`; the scraper and sitemap modes are meant for light, personal use.
- Headlines and summaries belong to their publishers. The dashboard stores short excerpts and always links to the original article.
