#!/usr/bin/env bash
# 启动 Capable Broker:两个独立 listener ——
#   control socket(0600,仅属主;可信编排者/capsh 连,可 mint)
#   guest   socket(0660;不可信客户端连,无 mint,workspace 受限)
# 各自独立的持久审计日志(每进程一条全局链,不能共享同一 log)。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/target/release/capable-rpc"
RUN="${CAPABLE_RUN_DIR:-$ROOT/.run}"
WS="${CAPABLE_WORKSPACE:-$RUN/workspace}"
mkdir -p "$RUN" "$WS"

[ -x "$BIN" ] || { echo "未找到 $BIN,请先运行 deploy/build.sh"; exit 1; }

CTRL_SOCK="$RUN/control.sock"
GUEST_SOCK="$RUN/guest.sock"

start() {
  local name="$1"; shift
  nohup "$BIN" "$@" >"$RUN/$name.log" 2>&1 &
  echo $! > "$RUN/$name.pid"
}

# control 面(可信,可 mint)
start control serve "$CTRL_SOCK" --trusted     --audit-log "$RUN/control-audit.log"
# guest 面(不可信,workspace 受限,无 mint)
start guest   serve "$GUEST_SOCK" --workspace "$WS" --audit-log "$RUN/guest-audit.log"

sleep 1
echo "Capable Broker 已启动:"
echo "  control: $CTRL_SOCK   (pid $(cat "$RUN/control.pid"), mode 0600)"
echo "  guest:   $GUEST_SOCK  (pid $(cat "$RUN/guest.pid"), mode 0660, workspace=$WS)"
echo "  审计:    $RUN/control-audit.log / $RUN/guest-audit.log"
echo
echo "用 capsh 连 control 面(可信编排):"
echo "  CAPSH_BROKER=$CTRL_SOCK $ROOT/capsh/_build/capsh <prog.capsh>"
