# capsh（OCaml）

capsh 语言运行时。落地 **D-encap**(能力的语言层强封装)与能力语义,并提供一个可跑的解释器。规范见 [../docs/capsh-language.md](../docs/capsh-language.md)。

> 状态:slice 1–4(语言)+ 5b(RPC 客户端)+ 5c(求值器可插后端)。**同一份 `.capsh` 可跑进程内 core 或远端 Rust Broker。**
> 尚缺:eventual-send/promise、完整 cap 目录(Http/Git/Db/…)、L5/L6、审计、capvm。

## 两种后端(同一门语言)

capsh 求值器对 `Backend` 函子参数化(`src/backend.ml`):
- 默认 **Backend_local**:进程内 `Cap`/`Broker`。`./_build/capsh prog.capsh`
- 设 **`CAPSH_BROKER=<sock>`** → **Backend_rpc**:走 CapTP-lite socket 到 Rust `capable-rpc` Broker。`make run-capsh-remote` 起 Rust 服务并跑同一份 `hello.capsh`(能力/枚举/IFC 全在 Rust 侧)。
capsh 只持 opaque ref;真实能力在后端。

## 构建与运行(纯 ocamlc,无需 dune/opam)

```sh
make run          # 跑 core demo(OCaml 直接调 Cap API)
make forge-check  # 断言「伪造能力」编译失败(证明不可伪造)
make capsh        # 构建 capsh 解释器 -> _build/capsh
make run-capsh    # 跑 examples/*.capsh
make test         # 以上全部
make clean
```

## slice 2:capsh 解释器

`_build/capsh <program.capsh>` —— 手写 lexer/parser(递归下降)/evaluator,把 core 接成语言:

- 两个宇宙:`VData`(带 taint)与 `VCap`(不可伪造);裸值不能当能力用。
- `grant dir "PATH" {read[,write][,secret]}` / `grant sink "NAME"` —— 唯一授权入口。
- 方法链衰减/使用:`repo.sub("src").readonly()`、`repo.read(path\`..\`)`、`out.send(data)`。
- **quasi-literal**:`path\`${x}.ml\`` —— 插值恒为数据;path 的每个插值必须是单一安全路径段(含 `/` 或 `..` 即拒),**从语法层杀死路径注入**(见 `examples/injection.capsh`)。
- **taint 信息流**:secret 污点数据流入 `send` 外发 sink 被运行期拒绝(见 `examples/hello.capsh` 末行)。

### slice 3:CommandCap + run

- `grant command sh\`echo hi\` { cwd: repo }` —— 一命令一卡(D9):固定 argv、cwd 绑定到一个 DirCap、env allowlist(剥离宿主环境)。
- `run(cmd)` —— 用 `execvpe` 直接执行 argv,**无 shell**;输出标 Yellow(本地确定性工具输出)。
- **shell 注入结构上不可能**:sh quasi 的 `${x}` 插值恒为【单个】argv 元素,含 `;`/`|`/空格也不切分、不解释——见 `examples/command.capsh` 第 2 段(`echo ${恶意串}` 原样打印,不执行)。

### slice 4:confine 区室 + spawn 委托

- `spawn "label" with { a: cap, ... } { body }` —— 子主体默认零权限:body 里【只】能看到显式委托的能力(经衰减,如 `repo.sub("src").readonly()`),外层其它变量/能力结构上不可达。
- `confine "label" with { ... } { body }` —— 信息流区室:同一区室**不能同时**持有敏感读(Secret 污点能力)与外发 sink;违反即结构性拒绝(`examples/confine.capsh` 末段)。

示例:`hello.capsh`(grant→读→衰减→secret→confinement)、`injection.capsh`(path 注入被拒)、`command.capsh`(shell 注入不可能)、`confine.capsh`(区室隔离 + 敏感读/外发 分离)。

## 这一片证明了什么

| 论点 | 落地 | demo 段 |
|---|---|---|
| **能力不可伪造(不变量 14)** | `Cap.t` 是 abstract type,签名外无法构造/匹配/序列化 | `forge_fail.ml` **编译失败** |
| 脚本层无法铸造 | `script_layer.ml` 拿到的窄签名 `ScriptCap` 无 `Trusted`/minter | 类型相等但无铸造入口 |
| 指名即授权(不变量 2) | `read` 只收 `dir t` + 相对路径;裸字符串是 `string` 不是能力 | §1、forge (2) |
| 越界拒绝 | 绝对路径 / `..` 穿越 → `Capability_violation` | §2 |
| 衰减单向 | `sub` / `read_only` 返回更窄新 cap,`parent` 指向原 cap | §3 |
| taint 信息流 confinement | secret 污点数据流入外发 sink 被拒 | §4 |
| declassify 需能力 | `declassify` 需 `declassifier`(Broker 颁发),Agent 不能自铸 | §5 |
| 可撤销 forwarder + 级联 | `make_revocable` / `revoke`;`active` 走祖先链 | §6 |

## 文件

```
src/taint.ml         运行期 taint 标签 + 信息流(D-taint:运行期起步)
src/cap.mli          能力对外签名(abstract type = 不可伪造的来源)★
src/cap.ml           能力实现(表示隐藏;TCB)
src/broker.ml        最小 Broker:持有唯一 minter,grant 是唯一授权入口
src/script_layer.ml  模拟不可信脚本层:窄签名,无铸造能力
src/demo.ml          可运行 demo
src/forge_fail.ml    反向测试:伪造必须编译失败
```

## TCB 边界(诚实说明)

abstract type 只挡 **capsh 脚本层**伪造。TCB = OCaml 求值器 + `Cap`/`Broker`(能看到表示、持有 minter)。恶意**原生 OCaml 模块**仍能 `Obj.magic`(lint 禁止);任意**原生 guest 二进制**不走此封装,由 capvm 的 cap-indexed syscall + L1 OS 沙箱兜底。两层各管一段(D2 分层)。
