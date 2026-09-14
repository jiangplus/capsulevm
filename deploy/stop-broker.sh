#!/usr/bin/env bash
# 停止 Capable Broker(control + guest)。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUN="${CAPABLE_RUN_DIR:-$ROOT/.run}"
for name in control guest; do
  if [ -f "$RUN/$name.pid" ]; then
    kill "$(cat "$RUN/$name.pid")" 2>/dev/null || true
    rm -f "$RUN/$name.pid"
    echo "stopped $name"
  fi
done
rm -f "$RUN/control.sock" "$RUN/guest.sock"
