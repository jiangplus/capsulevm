#!/usr/bin/env bash
# Capable CI 门禁:一处跑齐所有安全回归 + 语言测试 + 红队黑盒对抗。
# 任一步失败即非零退出。用于本地 pre-commit / CI。
#
#   ./ci.sh            全量
#   ./ci.sh --quick    跳过 OCaml capsh(仅 Rust 侧)
set -euo pipefail
cd "$(dirname "$0")"

quick=0
[ "${1:-}" = "--quick" ] && quick=1

step() { printf '\n\033[1;36m== %s ==\033[0m\n' "$1"; }
ok()   { printf '\033[1;32m[ok]\033[0m %s\n' "$1"; }

step "1/4 Rust 构建(broker + rpc,零依赖)"
cargo build --workspace --quiet
ok "build"

step "2/4 Rust 安全回归(broker 单元 + proto)"
# 涵盖:openat2 fd-身份/根替换、guest 无 mint、审计 fail-closed/tamper、SSRF/注入、
#       C1 沙箱 fs 限制 + seccomp(socket/socketpair/io_uring/pidfd/ptrace 逐条被拒)+ uid drop fail-closed
cargo test --workspace --quiet --lib --bins
ok "unit + proto tests"

step "3/4 端到端黑盒(真实 serve 进程 + 真实 wire 协议)"
# redteam:伪造 ref / guest 自铸 / 路径逃逸 / 跨会话重放 / REVOKE 级联 / 超大帧 / symlink 换位
#          / HttpCap canonical / RPC→CommandCap→Landlock + verify-audit
# consent:L5 JIT consent 审批/拒绝端到端(请求方触发 CONSENT,审批者同 socket 批准→重放放行)
cargo test --workspace --quiet --tests
ok "redteam + consent e2e"

if [ "$quick" = "0" ]; then
  step "4/4 capsh 语言测试(OCaml:不可伪造 + quasi-literal 防注入 + 后端)"
  if command -v ocaml >/dev/null 2>&1 && command -v make >/dev/null 2>&1; then
    make -C capsh test >/dev/null
    ok "capsh test"
  else
    echo "[skip] 无 ocaml/make,跳过 capsh(用 --quick 显式跳过以静默此提示)"
  fi
else
  step "4/4 capsh 语言测试 —— 已由 --quick 跳过"
fi

printf '\n\033[1;32mCI 全绿。\033[0m\n'
