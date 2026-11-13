#!/bin/sh
# Hand /data to the unprivileged "nobody" user, then run the hub as nobody.
set -e
PORT="${GPUWATCH_PORT:-9180}"
if [ "$(id -u)" = "0" ]; then
  mkdir -p /data
  chown -R 65534:65534 /data
  chmod 700 /data
  exec su-exec 65534:65534 python3 -u /app/gpuwatch.py --hub --state-dir /data --port "$PORT" "$@"
fi
exec python3 -u /app/gpuwatch.py --hub --state-dir /data --port "$PORT" "$@"
