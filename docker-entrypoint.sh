#!/bin/sh
# Single-image entrypoint: runs guacd (Guacamole proxy daemon) and the vsay backend
# in ONE container. guacd listens on loopback; the backend talks to it at
# 127.0.0.1:4822 and, since they now share a network namespace, guacd reaches the
# per-session RDP bridge the backend opens via 127.0.0.1 too (GUACD_HOST_GATEWAY).
set -e

# Locate guacd (path varies by image).
GUACD_BIN=""
for p in guacd /opt/guacamole/sbin/guacd /usr/local/sbin/guacd /usr/sbin/guacd /usr/bin/guacd; do
  if command -v "$p" >/dev/null 2>&1; then GUACD_BIN="$p"; break; fi
done
if [ -z "$GUACD_BIN" ]; then
  echo "[entrypoint] WARNING: guacd not found — remote desktop will not work" >&2
else
  echo "[entrypoint] starting guacd: $GUACD_BIN"
  # -f = foreground; run in the background so we can exec the backend as the main process.
  "$GUACD_BIN" -b 127.0.0.1 -L "${GUACD_LOG_LEVEL:-info}" -f &
fi

echo "[entrypoint] starting vsay backend"
cd /app
exec ./vsay-backend
