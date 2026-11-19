#!/usr/bin/env bash
# Installs the dashboard as systemd services on a Raspberry Pi (Debian/Raspberry Pi OS).
# Run as a NORMAL user (not root):  bash deploy/install.sh
set -euo pipefail

APP_DIR="$(cd "$(dirname "$0")/.." && pwd)"
RUN_USER="$(whoami)"
PORT="${PORT:-8080}"

if [ "$RUN_USER" = "root" ]; then
  echo "Run this as a normal user (without sudo). It will ask for sudo when needed."; exit 1
fi

echo "==> Creating virtualenv and installing dependencies"
python3 -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/pip" install --quiet -r "$APP_DIR/requirements.txt"

echo "==> Writing systemd units (user: $RUN_USER, dir: $APP_DIR, port: $PORT)"
sudo tee /etc/systemd/system/cyber-dashboard.service >/dev/null <<UNIT
[Unit]
Description=Cyber News Dashboard (web server)
After=network-online.target

[Service]
User=$RUN_USER
WorkingDirectory=$APP_DIR
ExecStart=$APP_DIR/.venv/bin/python server.py --port $PORT
Restart=on-failure

[Install]
WantedBy=multi-user.target
UNIT

sudo tee /etc/systemd/system/cyber-dashboard-update.service >/dev/null <<UNIT
[Unit]
Description=Cyber News Dashboard (fetch news and rebuild page)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=$RUN_USER
WorkingDirectory=$APP_DIR
ExecStart=$APP_DIR/.venv/bin/python cyber_dashboard.py
UNIT

sudo tee /etc/systemd/system/cyber-dashboard-update.timer >/dev/null <<UNIT
[Unit]
Description=Hourly refresh of Cyber News Dashboard

[Timer]
OnBootSec=2min
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
UNIT

echo "==> First build (fetching news, may take a minute)"
"$APP_DIR/.venv/bin/python" "$APP_DIR/cyber_dashboard.py" || echo "(some sources failed - see messages above)"

echo "==> Enabling services"
sudo systemctl daemon-reload
sudo systemctl enable --now cyber-dashboard.service cyber-dashboard-update.timer

IP="$(hostname -I | awk '{print $1}')"
echo
echo "Done. Open: http://$IP:$PORT"
