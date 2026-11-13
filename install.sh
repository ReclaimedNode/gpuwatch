#!/bin/sh
# gpuwatch installer - Linux (systemd) and macOS (LaunchDaemon).
#
#   sudo ./install.sh                              # agent only
#   sudo ./install.sh --hosts "192.168.1.50,192.168.1.51"   # also seed the dashboard's host list
#   sudo ./install.sh --port 9180 --interval 1
#   sudo ./install.sh --uninstall
set -e

DEST=/opt/gpuwatch
PORT=9180
INTERVAL=1
HOSTS=""
UNINSTALL=0
SRC="$(cd "$(dirname "$0")" && pwd)"

while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="$2"; shift 2 ;;
    --interval) INTERVAL="$2"; shift 2 ;;
    --hosts) HOSTS="$2"; shift 2 ;;
    --uninstall) UNINSTALL=1; shift ;;
    *) echo "unknown option: $1"; exit 1 ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then echo "run with sudo"; exit 1; fi

OS="$(uname -s)"
PLIST=/Library/LaunchDaemons/com.reclaimednode.gpuwatch.plist
UNIT=/etc/systemd/system/gpuwatch.service

if [ "$UNINSTALL" = 1 ]; then
  if [ "$OS" = Darwin ]; then
    launchctl bootout system "$PLIST" 2>/dev/null || true
    rm -f "$PLIST"
  else
    systemctl disable --now gpuwatch 2>/dev/null || true
    rm -f "$UNIT"; systemctl daemon-reload
  fi
  rm -rf "$DEST"
  echo "gpuwatch removed"; exit 0
fi

PY="$(command -v python3 || true)"
[ "$OS" = Darwin ] && PY=/usr/bin/python3
if [ -z "$PY" ] || ! "$PY" -c 'import sys; sys.exit(sys.version_info < (3, 8))' 2>/dev/null; then
  echo "python3 (3.8+) is required. On macOS run: xcode-select --install"; exit 1
fi

mkdir -p "$DEST"
cp "$SRC/gpuwatch.py" "$SRC/dashboard.html" "$DEST/"
chmod 755 "$DEST/gpuwatch.py"

ARGS="--port $PORT --interval $INTERVAL"
[ -n "$HOSTS" ] && ARGS="$ARGS --hosts $HOSTS"

if [ "$OS" = Darwin ]; then
  {
    echo '<?xml version="1.0" encoding="UTF-8"?>'
    echo '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
    echo '<plist version="1.0"><dict>'
    echo '  <key>Label</key><string>com.reclaimednode.gpuwatch</string>'
    echo '  <key>ProgramArguments</key><array>'
    echo "    <string>$PY</string><string>$DEST/gpuwatch.py</string>"
    for a in $ARGS; do echo "    <string>$a</string>"; done
    echo '  </array>'
    echo '  <key>RunAtLoad</key><true/>'
    echo '  <key>KeepAlive</key><true/>'
    echo '  <key>StandardOutPath</key><string>/var/log/gpuwatch.log</string>'
    echo '  <key>StandardErrorPath</key><string>/var/log/gpuwatch.log</string>'
    echo '</dict></plist>'
  } > "$PLIST"
  chmod 644 "$PLIST"
  launchctl bootout system "$PLIST" 2>/dev/null || true
  launchctl bootstrap system "$PLIST"
else
  cat > "$UNIT" <<EOF
[Unit]
Description=gpuwatch GPU stats agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$PY $DEST/gpuwatch.py $ARGS
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable gpuwatch >/dev/null 2>&1
  systemctl restart gpuwatch
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw allow "$PORT"/tcp >/dev/null && echo "opened $PORT/tcp in ufw"
  fi
fi

sleep 2
IP="$( (hostname -I 2>/dev/null || ipconfig getifaddr en0 2>/dev/null || echo localhost) | awk '{print $1}')"
if curl -fsS "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; then
  echo "gpuwatch running:  http://$IP:$PORT/"
else
  echo "installed, but the agent did not answer yet. Check: $( [ "$OS" = Darwin ] && echo 'tail /var/log/gpuwatch.log' || echo 'journalctl -u gpuwatch -n 30')"
fi
