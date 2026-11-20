#!/usr/bin/env bash
# Installs the dashboard as a systemd service on a Raspberry Pi (Debian / Raspberry Pi OS).
# The server refreshes the news by itself; the interval is set in the Config tab.
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

echo "==> Writing systemd unit (user: $RUN_USER, dir: $APP_DIR, port: $PORT)"
sudo tee /etc/systemd/system/cyber-dashboard.service >/dev/null <<UNIT
[Unit]
Description=Cyber News Dashboard (web server + scheduler)
After=network-online.target
Wants=network-online.target

[Service]
User=$RUN_USER
WorkingDirectory=$APP_DIR
Environment=PYTHONUNBUFFERED=1
ExecStart=$APP_DIR/.venv/bin/python server.py --port $PORT
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

# Earlier versions used an hourly systemd timer; the server has its own scheduler now.
sudo systemctl disable --now cyber-dashboard-update.timer 2>/dev/null || true
sudo rm -f /etc/systemd/system/cyber-dashboard-update.timer /etc/systemd/system/cyber-dashboard-update.service

echo "==> First build (fetching news, may take a minute)"
"$APP_DIR/.venv/bin/python" "$APP_DIR/cyber_dashboard.py" || echo "(some sources failed - see the Config tab)"

echo "==> Starting the service"
sudo systemctl daemon-reload
sudo systemctl enable cyber-dashboard.service
sudo systemctl restart cyber-dashboard.service

IP="$(hostname -I | awk '{print $1}')"
echo
echo "Done. Open: http://$IP:$PORT"
echo "Set how often the news refresh in the Config tab."
