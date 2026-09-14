# Capable Rust 侧(L3 Broker + CapTP-lite RPC)

`capvm`/Broker 核心用 Rust(与 secure-exec 同栈、便于内嵌)。当前实现:

- **`capable-broker`**(lib):L3 能力 Broker。持有真实能力 registry;cap 引用是不可猜测、会话绑定的 token(不变量 14)。能力表示只活在这里,客户端只拿 opaque ref。实现:grant dir/sink/command、invoke read/list/exec/send、derive sub/readonly(单向衰减)、revoke(祖先链级联)、taint IFC(secret 拒外发)、路径越界拒绝(canonicalize containment,newton A2)、guest grant 受 workspace policy 约束 + 服务端污点(newton A1)、传输资源上限(帧上限/连接数/超时,newton A3)、**审计 hash-chain**(每步操作/拒绝记链;内存链=进程内完整性校验,`--audit-log` 落 append-only + anchor 尾截检测,newton A4;手写 SHA-256)。**纯 std,零依赖。**
> 诚实标注:审计对「能同时改写 log 与 anchor 的写者」不设防,完整 tamper-evidence 需外部签名(DSSE/Sigstore),列为后续;故不宣称 tamper-evident。
- **`capable-rpc`**(bin):CapTP-lite over Unix socket。length-prefixed 帧 + tab 文本 + base64 二进制;请求作用在能力引用上(能力传递 RPC)。每连接一个会话 → cap ref 会话绑定,跨会话不可重放。

## 跑

```sh
cargo test  -p capable-broker      # 4 个单测(grant/衰减/IFC/撤销级联/跨会话)
cargo run   -p capable-rpc -- demo # 端到端:起服务 + 客户端跑 7 段场景(真实 socket)
cargo run   -p capable-rpc -- serve /tmp/capable.sock   # 独立服务
```

## 协议(CapTP-lite,简版)

请求(tab 分隔,首字段 VERB);回复 `CAP\t<ref>` | `OK\t<taint>\t<b64>` | `ERR\t<msg>`:

```
GRANT_HTTP <scheme> <host> <port> <methods csv> <paths \x1f> <max_bytes>  -> CAP <ref>  (control-only)
INVOKE     <ref> http_get <path>           -> OK external <b64>  (SSRF/白名单/连接预解析 IP)
GRANT_DIR  <root> <ops csv> <taint>        -> CAP <ref>
GRANT_SINK <name>                          -> CAP <ref>
GRANT_CMD  <cwd_ref> <argv \x1f-joined>    -> CAP <ref>
DERIVE     <ref> sub <seg> | readonly      -> CAP <ref>
INVOKE     <ref> read|list <rel>           -> OK <taint> <b64>
INVOKE     <ref> exec                       -> OK yellow <b64>
INVOKE     <ref> send <taint> <b64>        -> OK | ERR(IFC)
REVOKE     <ref>                            -> OK
DESCRIBE   <ref>                            -> OK  <desc>
```

CapTP-lite 取 CapTP 概念子集:不可伪造会话绑定引用 + 请求作用于引用;暂用 lease/registry 替代分布式 GC、broker 中介替代三方 handoff(DESIGN §11.5.2)。

## 下一步

- 5b:让 OCaml capsh 走 socket 接到这个 Broker(替换 capsh 的进程内 Cap 为 RPC 客户端)。
- promise / eventual-send(为跨机器铺路)。
- 最终 capvm:把这套 registry/enforcement 落到改造后的 secure-exec kernel(cap-indexed 原生 ABI)。
