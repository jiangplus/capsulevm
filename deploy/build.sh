#!/usr/bin/env bash
# 构建 Capable 的可部署产物:Rust Broker(release)+ capsh 解释器。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "[build] cargo release (capable-rpc / capable-broker)..."
cargo build --release --offline -p capable-rpc

echo "[build] capsh 解释器..."
( cd capsh && make capsh >/dev/null )

echo "[build] 完成:"
echo "  Broker:  $ROOT/target/release/capable-rpc"
echo "  capsh:   $ROOT/capsh/_build/capsh"
