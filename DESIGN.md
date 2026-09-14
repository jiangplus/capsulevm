# Capable 设计方案 v0.1

> 一个基于 Object Capability（OCap / Model 4）的 VM 运行环境 + capability-native shell（`capsh`）。
> 复用 agentos / secure-exec 的 V8-isolate 微 VM 执行基座，替换其权限语义层。

本文是 task #2 的具体设计方案。依据 `/home/ubuntu/capo/design/` 三份文档（secure-agent-harness-report / ocap-shell-vm-design / ocap-security-model-evaluation-framework）与 agentos 深扫结论综合而成。

---

## 0. 定位与目标

### 0.1 是什么

Capable 提供两样东西：

1. **capvm（Capable VM）**：一个 OCap-native 的代码执行运行时。guest 代码（工具、命令、子任务）默认零权限，只能通过**能力句柄（cap handle）**访问外部世界；不存在「用字符串路径 open 文件」这类 ambient authority 接口。
2. **capsh（Capable Shell）**：一个 capability-native 的交互 shell / 脚本语言，作为用户与 Agent 操作 capability 的界面。它不是 Bash 的语法补丁，而是 capvm 上的 capability object runtime 的前端。

两者共享同一个 **Capability Broker** 作为唯一授权入口。

### 0.2 与设计文档的关系

- 落地 `secure-agent-harness-report.md` 的 **6 层参考架构**（L1 OS 沙箱 → L6 Human Control Plane）、**16 条不变量**、**M0–M4 路线图**、**D1–D15 决策**。
- 落地 `ocap-shell-vm-design.md` 的 **cap-indexed syscall 设计**、**capshell 语法**、**prepare/commit 写入**、**PipeValue（bytes + provenance + taint）**。
- 用 `ocap-security-model-evaluation-framework.md` 的**红线门禁 + 量化评分 + 红队用例**作为验收标准与 CI 回归。

### 0.3 与 agentos / secure-exec 的关系（复用 vs 替换）

agentos 深扫结论：它是一个「TS SDK + ACP agent 层」建立在 secure-exec（Rust V8-isolate kernel + sidecar）之上；隔离基座优秀，但权限模型是**对 6 个命名 scope（fs/network/childProcess/process/env/binding）的 deny-by-default 策略**，参数仍是路径/host 字符串——即评估框架里的 **Model 1.5–2**，不是 Model 4。

Capable 的策略：

| 层 | agentos / secure-exec 现状 | Capable 的动作 |
|---|---|---|
| L1 OS 沙箱 | V8 isolate + 128MiB heap cap + CPU watchdog；sidecar 进程 | **复用**（Linux 上再补 Landlock+seccomp+uid-drop，参考 smolvm 的 host-side hardening） |
| L2 Tool membrane / kernel VFS | 每个 guest syscall 经 kernel，openat2 RESOLVE_BENEATH 路径约束 | **复用 kernel 中介**，但把 syscall 入口从「路径参数」改为「cap handle 参数」 |
| L3 权限语义 | 6-scope deny-by-default 策略（Model 1.5–2） | **替换**为 Capability Broker：不可伪造引用 + registry + 衰减/委托/撤销 + facet 链 |
| L4 Agent 编排 | ACP 会话、session/prompt | **复用 ACP**，但工具 schema 改为由持有的 cap 集动态生成 |
| L5 Policy Engine | 无（策略是静态 config） | **新增** |
| L6 Human Control Plane | inspector UI（调试用） | **新增** capability 侧边栏 / 授权弹窗 / 委托图 / 撤销 / 审计回放 |

一句话：**Capable = agentos 的隔离基座 + 设计文档要求的 Model 4 能力语义层 + capsh 前端**。

---

## 1. 核心设计约束

### 1.1 三条铁律（来自 ocap-shell-vm-design §10）

```text
路径不是权限。       (裸字符串路径/URL/命令名只能触发授权申请，不能直接访问)
命令名不是权限。     (命令由 CommandCap 指定固定 argv 模板，不经 $PATH 解析)
子进程不继承权限。   (新主体默认零权限，只能接收衰减后的委托)
```

### 1.2 16 条不变量（全量采纳，见 report §3）

实现必须保持全部 16 条不变量。其中对 Capable 架构影响最大的四条（也是最易滑坡的点）单列：

- **不变量 14（Model 4 地基）**：cap 真实引用密码学不可伪造、不可猜测、脱离 Broker registry 无法调用；显示 ID 仅为占位符，泄露 ≠ 授权。→ 决定 §4.2 的 cap handle 实现。
- **不变量 15（防 Model 3 钥匙）**：凭据类 cap 只暴露「执行某受限操作」的能力，绝不把可重放凭据本身交给 guest。→ 决定 §6 CredentialCap 与 §4.4 facet。
- **不变量 9（无环境权限）**：worker 默认剥离 env / 云凭据 / SSH agent / cookie / keychain / metadata / DB 连接 / MQ / process table / 用户 home（完整 11 类）。
- **不变量 16（防自我说服）**：Agent 自身中间推理结论视同红色来源，不能作为高危动作的唯一授权依据。

### 1.3 采纳的决策（D1–D15，见 §13）

Capable 全量采纳 report §14 的推荐结论。关键：D1→Model 4 HMAC 绑定；D2→分层（普通 cap 应用层 + 凭据类语言层强封装）；D9→CommandCap 一命令一卡动态颁发；D12→无人值守禁止红/黄升绿；D13→四条跨平台沙箱基线。

---

## 2. 总体架构

```text
┌──────────────────────────────────────────────────────────────────┐
│ L6  Human Control Plane        capable-ui / capsh 交互层            │
│     资源选择 · 授权弹窗 · capability 侧边栏 · 委托图 · 撤销 · 审计回放  │
├──────────────────────────────────────────────────────────────────┤
│ L5  Policy Engine              capable-policy                       │
│     颁发策略 · 风险分级 · 来源标记规则 · 审批规则 · 待人工确认队列      │
├──────────────────────────────────────────────────────────────────┤
│ L4  Agent Orchestrator         复用 agentos ACP + 动态 tool schema  │
│     task context · Agent 生命周期 · 子 Agent 委托 · 结果合并          │
├──────────────────────────────────────────────────────────────────┤
│ L3  Capability Broker          capable-broker  ★ 核心新增           │
│     registry · 不可伪造 handle · facet 链 · 衰减/撤销/配额/委托链      │
├──────────────────────────────────────────────────────────────────┤
│ L2  Tool Membrane + Helpers    复用 secure-exec kernel + 受限 helper │
│     cap-indexed syscall 入口 · 文件/命令/网络/Git/DB/浏览器/凭据代理   │
├──────────────────────────────────────────────────────────────────┤
│ L1  OS Sandbox                 复用 V8 isolate + Landlock/seccomp    │
│     进程内隔离 · 无 home · 默认无网 · 资源上限 · 结构兜底             │
└──────────────────────────────────────────────────────────────────┘
```

L5 与 L6 是两个组件（D8）：L5 可无人值守运行，L6 只是它的人机前端，消费 L5 的「待人工确认队列」。

调用路径：

```text
用户输入 / @引用 / 工具结果（附来源标签 + taint）
  → capsh / Agent（只看到当前 cap 集派生的 tool schema）
  → Capability Broker（校验 scope/生命周期/来源链/风险，必要时问 L5→L6）
  → capvm kernel（cap-indexed syscall，经 revocable forwarder facet 调真实资源）
  → Restricted Helper / Proxy（动态资源受限代理，自带 limit API）
  → OS Sandbox（结构兜底）
```

### 2.1 组件与仓库布局（规划）

```text
capable/
├── DESIGN.md / README.md / CHANGELOG.md
├── docs/                      # 分册设计
│   ├── syscall-abi.md         # capvm cap-indexed syscall ABI（后续）
│   ├── capsh-language.md      # capsh 语言规范（后续）
│   ├── cap-catalog.md         # capability 类型目录详表（后续）
│   └── eval-scorecard.md      # OCap 评估自评卡（后续）
├── crates/ 或 packages/       # 实现（尚未开始）
│   ├── capable-broker/        # L3 Broker：registry / handle / facet
│   ├── capable-capvm/          # L1-L2：改造后的 secure-exec kernel（cap-indexed 原生 ABI）
│   ├── capable-policy/        # L5 Policy Engine
│   ├── capable-helpers/       # L2 受限 helper（net/git/db/browser/cred）
│   ├── capable-rpc/           # 能力传递 RPC（CapTP-lite）：本地 socket + 远程 TCP/vsock
│   ├── capsh/                 # capsh 求值器与交互前端（OCaml）
│   └── capable-ui/            # L6 Human Control Plane
└── tests/redteam/             # §11 红队回归集（进 CI）
```

技术栈（已定，见 §16 决策）：**capvm / Broker / helpers 用 Rust**（capvm 直接改造 secure-exec kernel，需同栈内嵌 V8/sidecar）；**capsh 语言前端 + 求值器 + 类型/IFC 检查用 OCaml**（迭代快；abstract type = 语言级不可伪造引用，GADT/phantom type = 编译期 taint）；两者走带类型的 IPC/FFI 边界通信；UI 复用 agentos inspector 思路。

---

## 3. capvm — OCap VM 运行时

### 3.1 与 agentos 的接口改造

secure-exec 的 kernel 已经中介每个 guest syscall，并做 `openat2 RESOLVE_BENEATH` 路径约束。Capable **直接改造 secure-exec kernel**（已定决策，见 §16 D-capvm）：把 syscall 的**资源指名方式从字符串改为 cap 句柄索引**，让 cap-indexed 成为内核**原生 ABI**，而非在其上加一层翻译 shim。取舍：更纯粹（能力语义是内核第一等公民，无 shim 的双重记账/绕过风险），代价是需 fork / 深改 secure-exec 并与上游分叉；因此 capvm 工作量高于原「shim 起步」估计，M0/M1 需相应排期。

传统（agentos/secure-exec 现状，仍是字符串指名 + scope 策略）：

```text
open("/repo/src/main.ts", O_RDONLY)     // 路径字符串 + kernel 查 fs 权限策略
fetch("https://api.x.com/v1/models")    // URL 字符串 + kernel 查 network allowlist
```

Capable capvm（cap-indexed，指名即授权）：

```text
cap_read(cap_idx, "src/main.ts")        // cap_idx 是进程 cap_table 的槽位；相对路径
cap_connect(http_cap_idx, request)      // http_cap 自带 origin/method/path/配额
```

### 3.2 cap-indexed syscall ABI（对照 ocap-shell-vm-design §6）

每个 capvm 进程持有自己的 **capability table**（C-list，仿 Unix fd 表，但不可伪造、不可跨进程凭空构造）：

```text
Process {
  subject_id
  cap_table: [opaque handle]        // guest 只见槽位索引，不见真实引用
  memory
  stdin / stdout / stderr: PipeValue // 见 §7.2
}
```

核心 syscall（guest ABI，全部以 cap_idx 为资源指名）：

```text
cap_read(cap_idx, rel_path) -> PipeValue        // DirCap/FileCap
cap_list(cap_idx, rel_path) -> entries
cap_prepare_write(dir_cap_idx, rel_path, diff) -> write_patch_cap_idx   // 产出一次性 cap
cap_commit(write_patch_cap_idx)                 // 用一次性 WritePatchCap，绑定 diff hash
cap_delete(delete_cap_idx)
cap_connect(http_cap_idx, request) -> PipeValue // 经 net helper，taint=红
cap_send(message_cap_idx, message)              // 外发 sink
cap_exec(command_cap_idx) -> exit_status        // 固定 argv 模板，非 $PATH
cap_delegate(target_subject, attenuated_cap_idx)-> ok   // 委托前必须先衰减
cap_derive(cap_idx, attenuation) -> new_cap_idx // 衰减派生新 cap（单向，D10=A）
cap_revoke(cap_idx)
cap_request(descriptor) -> pending              // 向 Broker 申请未持有的 cap（触发 consent）
```

**guest 不能凭空创建 cap**，只能：(1) 接收启动时注入的 cap；(2) 向 Broker `cap_request`；(3) 从已有 cap `cap_derive` 衰减；(4) 接收父主体 `cap_delegate`。这四条正是 ocap-shell-vm-design §6 的约束。

### 3.3 handle ≠ 字符串（不变量 8/14）

- guest 侧 `cap_idx` 只是**进程本地槽位号**（像 fd=3），换个进程 / 会话无意义。
- Broker 侧真实引用是**不可伪造对象**（§4.2）。
- 显示给 LLM/日志的是占位符 `<cap:project_read_src>`，与 subject/session 绑定，脱离 registry 上下文失效。
- 这样即使 cap_idx 或占位 ID 被写进 prompt / 日志并重放，也**调不动**（红队用例：cap id 写日志后重放 → 脱离上下文不可调用）。

### 3.4 复用 secure-exec 的哪些机制

- **V8 isolate per execution + heap/CPU 上限**：直接作为 L1 结构兜底（一个被注入的 guest 最坏也只能耗尽自己 isolate）。
- **kernel 全中介 + RESOLVE_BENEATH**：作为 cap_read/cap_write 落地时的 L2 底层实现——DirCap 的 root fd + 相对路径正好映射到 openat2 RESOLVE_BENEATH。
- **sidecar 作为唯一 TCB**：Broker registry 与真实 cap 引用都活在 sidecar（宿主可信侧），guest isolate 永远拿不到真实引用——这天然满足不变量 14/15。

---

## 4. Capability Broker（L3，核心）

Broker 是应用层权限的唯一入口（report §4.1）。职责：维护 registry、动态生成 tool schema、校验每次调用、处理衰减/委托/撤销/过期、打 taint、触发 consent、生成审计事件、阻止 cap 序列化外泄。

### 4.1 Capability 数据结构（report §5.1）

```text
Capability {
  id: opaque                 // 密码学不可猜测，与 subject/session 绑定（不变量 14）
  type: dir|file|write_patch|delete|command|http|message|git|service|db
        |sheet|credential|llm_budget|subagent
  subject: subject_id
  operations: read|write|delete|exec|get|post|send|push|...
  scope: 路径 glob / origin+path / 命令模板 / API 资源 / 行过滤器
  lifetime: once | task | session | ttl | usage_count
  quota: bytes / requests / tokens / rate
  provenance: 谁在何时为何颁发 + source_chain
  delegation: none | attenuable | broker_only
  taint_policy: 输出如何打标
  revoker: active | revoked | expired
  audit: trace_id, parent_cap_id, issued_at, use_count, last_used_at
}
```

### 4.2 不可伪造 handle（D1=B，不变量 14）

真实引用不是「查表键」，而是绑定上下文的对象：

```text
display_id = "cap:" + short_name                       // 给人/LLM 看，可泄露无害
handle_token = HMAC(session_key, cap_content || subject || session_id)
真实调用校验：Broker 收到 (subject, session, cap_idx) → 查进程 cap_table 的内部对象引用
             → 校验该对象的 handle_token 与当前 (subject, session) 匹配且未撤销
```

要点（钉死在结构侧，避免滑成 Model 2 记账表）：

- `session_key` 每会话随机，≥128bit；LLM 无法枚举/拼接构造合法 token。
- cap 内部对象引用**只存在于 Broker/sidecar 进程内存**，从不出现在 guest 地址空间、prompt、env、URL、日志。
- guest 只能用**本进程 cap_table 槽位**发起调用；跨 subject / 跨 session 的 cap_idx 无意义 → 天然阻断重放。

### 4.3 facet 链（衰减 / 撤销 / 审计 / 限流 / taint 同一套机制，report §5.4）

```text
guest cap_idx → [ Facet 链 ] → 真实资源
                 ├─ RevokerFacet    撤销（断链即 ENOTCAPABLE）
                 ├─ AuditFacet      记录每次调用（审计不依赖资源配合）
                 ├─ RateLimitFacet  配额 / 限流
                 ├─ ReadOnlyFacet   只读投影
                 └─ TaintFacet      给输出打来源标签
```

每个 facet 都是「持有下游引用 + 拦截调用 + 加一层策略」的普通对象。衰减 = 在链上插一个更严的 facet 并产出新句柄。

### 4.4 衰减 / 委托 / 撤销

- **衰减（cap_derive）**：`.scope()` / `.read_only()` / `.limit_rate()` 链式收窄，派生 cap 内部持有祖先引用；单向不可逆（D10=A：「原地收窄」对外呈现为「撤销旧 + 发更窄新」）。
- **委托（cap_delegate）**：子主体默认零权限；父只能转交自己已有 cap 的衰减版；委托前展示委托图；禁止经 prompt/日志/env/子 Agent 自然语言输出等通道传递。
- **撤销（Redell 1974 转发器）**：`guest → ForwardingFacet → Revoker → 真实资源`。撤销后 guest 手中 cap_idx 仍在，调用返回 `ENOTCAPABLE`。三性质：可传递（撤父级联撤子）、不改子的 C-list、纯用户态（调用前逐级检查祖先链有无已撤销节点）。

### 4.5 动态 tool schema（不变量 1，M1 核心）

Broker 由「当前持有的 cap 集」生成 Agent 可见的 tool schema：

- 无 `HttpCap` → schema 里根本没有 `http_get` 工具。
- 无 `WritePatchCap` → 写入工具不出现，或只出现「申请写权限」的元工具。
- cap 撤销后，**下一轮**对话 schema 立即更新（在现有 LLM tool-calling API 上就是按持有集裁剪 tools 数组）。
- 工具参数一律 `cap_ref + 相对路径 / 受限参数`，绝不接受裸绝对路径 / 裸 URL / 任意命令字符串。

### 4.6 可解释拒绝

```text
Capability violation:
  operation: read_file
  requested: ../.env
  held:      DirCap(/repo/src/**, read)
  reason:    path escapes capability root
  next:      申请 FileCap(/repo/.env, read) 或跳过继续
```

---

## 5. capsh — capability-native shell

capsh 是 capvm 上的 capability object runtime 的交互界面与编程模型（ocap-shell-vm-design §1）。

> **完整语言规范见 [docs/capsh-language.md](./docs/capsh-language.md)**（v0.1）。capsh 被设计成一门真正的 capability 语言（致敬 E 语言的对象能力谱系），核心特性:数据/能力两个宇宙、能力即对象引用 + 衰减靠方法链、**quasi-literal 从语法层杀死注入**、taint-aware 信息流在类型层强制 confinement、eventual send + promise 并发、revocable forwarder 一等撤销、prepare/commit 事务、confine 区室。用 **OCaml** 实现(§16 决策)。本节只给概览。

### 5.1 值 与 capability 分离

```sh
let p = "../.ssh/id_rsa"          # 普通字符串
read $p                           # 拒绝：字符串不是 FileCap

let src = grant dir "./src" read  # 申请 DirCap（触发 consent）
read $src "main.ts"               # 允许：DirCap + 相对路径
```

capability 是不可伪造对象，不能被打印成可重放 token、不能写日志、不能字符串拼接构造、不能跨 session 复用。

### 5.2 去掉 cwd/PATH/env 的安全语义

```sh
let repo    = grant dir "." read,write
let npm_test = grant command ["npm","test"] cwd=$repo network=none once
run $npm_test
```

`CommandCap` 指定：argv 模板、cwd capability、env allowlist、network policy、fs caps、timeout、lifetime。命令不经 `$PATH` 解析（D9=B：一命令一卡动态颁发）。

### 5.3 文件系统：prepare / commit 写入

```sh
let patch = prepare_write $repo "src/main.ts" < diff.patch  # 产出一次性 WritePatchCap
commit $patch                                               # 绑定 diff hash + 目标 + 生命周期
```

### 5.4 网络：origin-scoped

```sh
let api = grant http "https://api.example.com" methods=[GET] paths=["/v1/*"] ttl=10m
http_get $api "/v1/models"
```

`HttpCap` 限制 origin/path/method/字节上限/rate/lifetime/taint；POST/Webhook/邮件/IM/PR 发布/DB 写属外发 sink，需更强 consent。

### 5.5 子任务 / 子 Agent（默认零权限 + 衰减委托）

```sh
spawn task "lint auth module" {
  caps = [
    repo.scope("src/auth").read_only(),
    llm_budget.split(0.2)
  ]
}
```

无显式 delegate 的 cap 子任务拿不到；父只能委托自己 cap 的衰减版；子输出至少标红；父 cap 撤销后派生 cap 级联失效。

### 5.6 兼容旧命令（legacy_run）

```sh
legacy_run ["make","test"] with {
  cwd = repo.read_write()
  network = none
  env = ["PATH", "HOME=/sandbox"]
  timeout = 60s
}
```

旧程序在 capvm 沙箱内跑，只看到映射进去的资源。明确拒绝：绝对路径、真实 home、任意 env、默认网络、SSH agent/keychain、process table、继承的 DB/MQ 连接。

### 5.7 consent 交互（不是 Allow/Deny，而是 cap 颁发）

```text
Agent wants:
  CommandCap ["npm","install"]
  cwd:        ./project
  network:    registry.npmjs.org only
  filesystem: ./project read/write
  lifetime:   once
  source chain: 用户请求 → package.json
  NOT granted: 无 home / 无任意网络 / 不暴露 token 值
按钮：[允许一次] [本任务同范围] [缩小范围] [拒绝]
```

---

## 6. Capability 类型目录（report §5.2）

| 类型 | 关键字段 | 设计要点 |
|---|---|---|
| `DirCap` | root fd、include/exclude glob、rights | 只接受相对路径，`deny_parent_escape`；`.env`/私钥/`.git/hooks` 默认排除 |
| `FileCap` | 文件引用、rights、max_bytes | `@file` 默认形态，只读一次或本任务只读 |
| `WritePatchCap` | 目标路径、diff_hash、once | 写入唯一通道：先出 diff → 确认后颁发 → hash 绑定内容 |
| `CommandCap` | 固定 argv 模板、cwd、env allowlist、timeout、network | 代替任意 shell；**一命令一卡动态颁发**（D9），带孤岛检测验收 |
| `HttpCap` | methods/origins/paths/字节上限/rate、taint=红 | 禁 private network；读过敏感文件的主体不发此卡；外发 sink |
| `MessageCap` | channel（topic/收件人/webhook）、direction、size、rate | 与 HttpCap 同为外发 sink，**独立列出**（D14）以免 confinement 漏检 |
| `GitCap` | ops 白名单（status/diff/add/commit vs push 分开）、protected_paths、固定 remote | push/PR 单独一次性授权 |
| `ServiceCap` | provider、scopes、object_scope、rate | OAuth token 留 Harness，Agent 只拿受限操作面（facet） |
| `SheetCap` | sheet_id、range、read/write | ServiceCap 特化，避免为读几行授出整张表 |
| `DbCap` | 视图/表、query 模板、row limit、write 模式 | 写走变更集确认，永不给任意 SQL |
| `CredentialCap` | provider、profile、允许操作、ttl | **值不进 prompt/日志/子上下文**；SSH/cookie 拆专用命名（不变量 15） |
| `LLMCap` | model、token_budget、并发上限 | 子 Agent 拿预算切片，防资源耗尽 |
| `SubagentCap` | 可委托 cap 子集、输出 taint | 派生子主体的能力，默认零权限 |

破坏性命令一律模板化为具名窄 cap：`DeleteCap(path=…, recursive, once)`、`GitPushCap(remote, branch, force=false, once)`、`PackageInstallCap(manager, cwd, once)`。

**孤岛检测验收**：每定义一个 cap 类型都问「用户想要其中最小操作时，是否被迫连带获得其他操作？」若是则粒度不合格，需拆分（防重蹈 `CAP_NET_ADMIN` 覆辙）。

---

## 7. 信任标签与信息流控制

### 7.1 三色信任（report §6.1）

| 标签 | 含义 | 来源 | 默认语义 |
|---|---|---|---|
| 绿 | 可信命令 | 用户直接输入、用户显式确认 | 可驱动行动 |
| 黄 | 半可信事实 | 本地确定性工具输出（git status、测试结果） | 可作事实参考，不单独授权破坏性动作 |
| 红 | 不可信数据 | 网页/API/剪贴板/邮件/Issue/README/子 Agent 输出/**Agent 自身推理结论** | 只当数据，永不当命令 |

规则：红色里的「指令」永远是字符串；`@` 交付只给 authority 不给 trust；红/黄升绿必须用户显式确认并记 `trust.upgraded`；**无人值守场景禁止任何自动升绿**（D12=A）。

### 7.2 PipeValue：带 provenance + taint 的管道

```text
PipeValue { bytes, provenance, taint }   # taint ∈ {local_secret, project_code, external_untrusted, agent_generated}
```

外发 sink 调用前检查输入 taint；含 `local_secret` 的数据外发必须显式 declassification，由用户/策略授予，Agent 自己不能决定。Agent 间默认传 schema 化结构而非自由文本（自由文本是隐藏指令最佳载体）。

### 7.3 区室化 confinement（report §6.4，进程级落地）

硬规则——禁止同一主体同时持有：

```text
FileReadCap(敏感) + 任意外发 sink（HttpCap POST / MessageCap send / DbCap 写 / GitPushCap）
```

进程级落地（Capsicum fork + cap_enter 范式，映射到 capvm 的 isolate 拆分）：

```text
主进程
  ├─ spawn Reader isolate：pre-open 敏感 DirCap → 无 HttpCap/MessageCap
  ├─ spawn Network isolate：pre-open HttpCap → 无敏感 DirCap
  └─ Broker 中介：两者间只传 schema 化结构（非自由文本），可审计
```

capvm 里「isolate 拆分 + Broker 只发对应 cap 集」等价于 `cap_enter()` 之后连 open() 都失败——把最小权限从「Agent 逻辑级」细化到「isolate 进程级」。

### 7.4 受限 helper 内部协议（Casper 范式，不变量 10）

```text
cap_<name>()   helper 入口（guest 侧调用）
command_func   操作分发
limit_func     ★ 对本通道二次限制（origin/method/字节配额）—— 即「helper 自带 limit API」
```

---

## 8. Policy Engine（L5）与 Human Control Plane（L6）

### 8.1 L5 Policy Engine（可无人值守）

- 输入：cap 申请（type/scope/operation/lifetime/source_chain/risk）。
- 输出：自动颁发 / 自动拒绝 / 入「待人工确认队列」。
- 风险分级 **5 级**（D5）：极低（读普通文件，自动执行）/ 低（改文件，展示 diff）/ 中（网络 GET、越界读、装依赖，首次确认）/ 高（shell、删除、越界写、网络 POST，每次确认+来源链）/ 极高（密钥/push/生产变更/改 git 历史，键入确认词+一次性 cap；资金/密钥导出/不可逆外发另加带外二次确认 D6）。
- 无人值守硬约束：红/黄不可升绿（D12）；确需处理红色内容并据此行动的任务必须有人在环。

### 8.2 L6 Human Control Plane

- 六个自然动作（report §8）：① 启动目录即会话根（默认只读，写走 diff）；② `@` 交付额外资源（默认只读、本任务）；③ 越界 JIT 授权（弹窗展示 cap 类型/scope/理由「Agent 声称」/来源链/NOT granted/生命周期，按钮 [允许一次][本任务同范围][缩小范围][拒绝]，绝不 Allow all）；④ 给数据不给权限（「只粘 profile 名」「只分享选中 10 行」）；⑤ 侧边栏实时可见+一键撤销（展示**实际用过**的权限）；⑥ 子 Agent 先看委托图。
- 「永久允许」重定义为**持久授权规则**（D4）：进 registry、显示在侧边栏、可一键撤销、强制季度复核；禁止黑洞式永久放行。

---

## 9. Restricted Helpers（L2）与 OS 沙箱基线（L1）

### 9.1 受限 helper（动态资源）

网络 / 浏览器 / DB / 凭据走受限 helper（本地代理，实现 origin/method/字节配额），helper 自带 `limit_func`。「先窄后关」初始化纪律：helper 启动时短暂持有初始化能力，构造完受限通道后立即释放，之后被注入也无法再开新通道。

参考 nono-proxy 的成熟实现（DNS-rebinding TOCTOU 关闭、cloud-metadata/link-local 恒拒、phantom-token / nonce credential 注入）——nono 在这块几乎就是 Capable 网络 helper 的现成蓝本。

### 9.2 跨平台 OS 沙箱四条最低基线（D13）

所有平台的 L1 实现必须同时达到，否则验收标注「应用层拒绝可用，OS 兜底降级」，不谎称双层防护：

1. 文件系统限制在授予目录（无 home、无越界）。
2. 网络默认拒绝。
3. 不继承凭据 / agent / cookie。
4. 资源上限（cgroup / rlimit / timeout）。

平台映射：Linux = V8 isolate + Landlock + seccomp + user namespace + uid-drop（抄 smolvm 的 host-side hardening）；macOS = Seatbelt profile（抄 nono 的 Seatbelt S-expression）；跨平台 = per-tool worker isolate + 本地网络代理。

---

## 10. 威胁模型映射（report §1.3 → Capable 结构对策）

| 威胁 | Capable 结构对策 |
|---|---|
| Prompt injection | 红色内容只作数据；处理不可信输入的 isolate 不持有外发/写 cap |
| 委托混淆问题（1988 编译器 ≡ 2024 injection） | designation=authority：cap-indexed syscall，裸字符串不是权限 |
| 数据外泄 | confinement：敏感读与任意外发 cap 区室分离（§7.3） |
| 权限横向扩张 | shell 是显式 CommandCap，默认不颁发任意 shell |
| 子 Agent 失控 | 默认零权限，只接收衰减委托 |
| 持久化逃逸 | `.git/hooks`/`.env`/发布配置默认排除在 DirCap 覆盖外 |
| 凭据窃取 | 环境剥离（不变量 9）；CredentialCap facet，值不进 prompt（不变量 15） |
| 撤销失效/重放 | forwarder facet 撤销级联；handle 脱离上下文不可调用（不变量 14） |
| 资源耗尽 | cap 携带 quota/TTL/次数；LLMCap 预算切片 |
| **工具实现自身有漏洞** | L1 OS 沙箱独立兜底（无 home/无网/seccomp），与语义层正交 |

---

## 11. 与 agentos 的具体复用/替换清单

| agentos / secure-exec 资产 | Capable 处置 |
|---|---|
| V8 isolate per execution + heap/CPU 上限 | 复用为 L1 |
| kernel 全中介 + openat2 RESOLVE_BENEATH | 复用为 cap_read/cap_write 的 L2 底层 |
| sidecar 作为唯一 TCB（BARE/ACP over stdio） | 复用；Broker registry 与真实 cap 引用活在 sidecar |
| ACP（session/prompt/事件流） | 复用为 L4；tool schema 改为 cap 动态生成 |
| host-tool / ToolKit（agentos-{name} CLI binding） | 演进为 CommandCap/ServiceCap 的对象引用形态 |
| 6-scope deny-by-default 权限（fs/net/childProcess/process/env/binding） | **替换**为 Capability Broker（Model 4） |
| mount plugins（host_dir/s3/gdrive/sandbox_agent/js_bridge） | 复用为 DirCap/ServiceCap 的后端 |
| inspector UI | 演进为 L6 capability 侧边栏/委托图 |
| （新增）| Policy Engine（L5）、facet 链、taint/provenance、prepare/commit、consent、审计八阶段状态机 |

---

## 11.5 Capable RPC（CapTP-lite）

Capable 需要一个 RPC 面(决策 D-rpc):供外部客户端 / Agent / 别的机器驱动它,并作为 capsh(OCaml)↔ capvm/Broker(Rust)之间的边界。

**核心约束:RPC 本身必须是 capability-secure**——不能在线上重新引入 ambient authority(不能提供「按路径读任意文件」这种方法)。所以 Capable RPC 是一个**能力传递协议**,不是普通请求/响应 API。

### 11.5.1 语义(CapTP 的概念子集)

- **连接即最小权限**:握手后客户端只拿到一个 **bootstrap 能力**(powerbox / workspace 根),其余一切不可达——要更多能力只能 `grant`(触发 consent)或对已持有能力衰减。
- **方法都作用在能力引用上**:`invoke(cap, verb, args) -> value | promise`、`derive(cap, attenuation) -> cap`、`grant(descriptor) -> cap`、`delegate(cap → target_session)`、`revoke(cap)`、`spawn(task, [caps]) -> session|promise`、`prepare(...) -> patch_cap` / `commit(patch_cap)`,以及审计流订阅。
- **线上能力引用 = 会话绑定的不可伪造 token**(HMAC,不变量 14):换连接 / 换会话即失效 → **不是可复制重放的 bearer**(不变量 15)。参数里可以带能力引用,实现能力传递。
- **promise + eventual send**:方法可返回 promise 引用,支持 pipelining(在 promise resolve 前就对它继续发消息)——这是 capsh `<-` 与 §8 并发在 RPC 层的落地。

### 11.5.2 为什么是「CapTP-lite」而不是纯 FFI 或纯 CapTP(决策 D-ipc)

| 方案 | 优 | 劣 | 结论 |
|---|---|---|---|
| 裸 FFI(OCaml↔Rust C ABI) | 同进程最快、无序列化 | OCaml GC 与 Rust 耦合、易碎;**给不了跨进程/跨机器能力传递** | 仅将来测出热点再局部用 |
| 纯 CapTP | 正好为「能力+eventual send 上网」而生 | 完整实现重(分布式 GC、三方 handoff) | 起步过重 |
| **CapTP-lite(采用)** | 拿 CapTP 80% 价值、一小部分复杂度 | 需自定义一个小协议 | ✅ |

CapTP-lite = **不可伪造会话绑定引用 + promise + eventual send**,但:

- 用 **lease / TTL 回收**替代分布式 GC(能力本就带 lifetime,天然契合);
- 用 **broker 中介**替代三方 handoff(引入他方能力先经 broker 路由);
- 传输:**本地 capsh↔Rust 走 Unix socket**(而非裸 FFI —— 顺带拿进程隔离:capsh 崩了不拖垮 Broker/TCB),**跨机器走 TCP/vsock**;两者同一份协议、同一套语义。
- 消息编码复用基座风格(BARE/CBOR)。

留清晰升级路径:将来确需分布式 GC / 三方 handoff,可平滑演进为完整 CapTP。

---

## 12. 里程碑路线图（M0–M4，report §10 适配）

每个里程碑独立产生安全收益。

- **M0 — Workspace 边界 + OS 沙箱兜底（最大收益项）**
  - 内容：capsh 启动目录即根 DirCap；workspace 外应用层拒绝 + OS 层不可达（复用 secure-exec isolate + Linux Landlock/seccomp）；敏感文件默认排除；写走 diff→一次性 WritePatchCap；worker 环境剥离（env 清空、无默认凭据、无 home、默认无网）。
  - 验收：红队「读 ~/.ssh/id_rsa」「`../` 穿越」「shell 读环境凭据」全部双层拒绝；爆炸半径 = 当前项目目录。
- **M1 — Capability Registry + 动态 tool schema + Model 4 handle**
  - 内容：Broker registry；tool schema 由 cap 集生成；工具参数改 `cap_ref + 相对路径`；cap id HMAC 不可猜测且绑 subject/session（不变量 14）；可解释拒绝。
  - 验收：无 HttpCap 时 fetch 工具不在 schema；撤销后下一轮 schema 更新；LLM 无法构造 ID 调未持有 cap；cap id 写日志后重放调不动。
- **M2 — 三色标签 + 来源链 + 高危 prepare/commit**
  - 内容：上下文块带来源标签；风险 5 级引擎；prepare/commit 分离；窄 cap 库（CommandCap/GitCap/WritePatchCap/DeleteCap）；JIT 弹窗 + 侧边栏。
  - 验收：README 里的 `curl|sh` 触发来源链确认而非静默执行；push 需一次性 GitPushCap；侧边栏撤销即时生效。
- **M3 — 受限 helper + 区室化 + 子 Agent 委托**
  - 内容：网络/浏览器/DB/凭据走受限 helper（带 limit API，抄 nono-proxy）；spawn 强制 delegate、默认零权限、展示委托图；「敏感读+任意外发」检测与 isolate 拆分（fork+cap_enter 范式）；taint 传播 + declassification。
  - 验收：Fetcher 区室被注入无法写库；Writer 区室被骗无法外发；子 Agent 伪造用户指令当红色数据。
- **M4 — 全链路审计 + 评估闭环**
  - 内容：trace id 串联八阶段状态机；Timeline/Graph/SourceChain 三视图；红队集进 CI；按评估框架季度自评。
  - 验收：任意写入可反查「由哪个授权导致」；CI 红队场景全绿。

M0 单独实施即可把爆炸半径从「整个用户账号」缩到「当前项目目录」。

---

## 13. 采纳的决策（D1–D15）

| # | 问题 | Capable 采纳 |
|---|---|---|
| D1 | Registry: Model 4 vs 记账 | **B** HMAC 不可猜测 + 上下文绑定（§4.2，地基无折中） |
| D2 | 不可序列化: 应用层 vs 运行时强制 | **C** 分层：普通 cap 应用层 + scanner；CredentialCap 走语言层强封装 |
| D3 | POLP vs POLA | **A** 主用 POLP，术语表注明 OCap 语境更精确说法是 POLA |
| D4 | 「永久允许」档位 | **B** 重定义为持久授权规则（登记+可见+可撤销+季度复核） |
| D5 | 风险 4 vs 5 级 | **A** 5 级（§8.1） |
| D6 | 极高风险 2FA | **B** 仅最顶格（资金/密钥导出/生产/不可逆外发）带外确认 |
| D7 | 初始 cap: 零权限 JIT vs 观察 | **C** 自研工具零权限 JIT；存量/第三方走 ktrace 式观察自举 |
| D8 | L5/L6 独立 vs 合一 | **A** 独立，L6 是 L5 前端 |
| D9 | CommandCap 动态 vs 静态 | **B** 一命令一卡动态颁发 + 孤岛检测 |
| D10 | 已发放 cap 可逆二次收窄 | **A** 语义单向；helper 内部允许 cap_rights_limit 式优化 |
| D11 | 学习式放行 | **A** 默认不做；最多逐字节相同命令模板重放 |
| D12 | 无人值守自动降级 | **A** 禁止，无人值守 = 不可升绿（硬约束） |
| D13 | 跨平台沙箱基线 | **B** 四条最低基线（§9.2） |
| D14 | MessageCap 独立 | **B** 独立，进外发 sink 清单 |
| D15 | ambient 剥离清单 | **B** 完整 11 类（含 DB/MQ/process table） |

---

## 14. OCap 七属性自评目标（report §13.2）

诚实标注：Broker 是应用层校验，不引入语言运行时强制的项现实落在 **2 分（有旁路）**而非 3 分。一个诚实标 2 分的设计远比虚标 3 分的安全。

| 属性 | 机制 | M0 后 | M4 后目标 |
|---|---|---|---|
| A 指名即授权 | cap-indexed syscall、裸路径只触发申请 | 1 | 3 |
| B 动态主体创建 | 每任务/子 Agent 独立主体，默认零权限 | 1 | 3 |
| C 主体聚合权限视图 | registry 唯一权威 + 侧边栏 | 1 | 3 |
| D 无环境权限 | 环境剥离 + isolate 沙箱 | 2 | 3 |
| E 权限可组合 | 窄 cap 库、facet 链、衰减链 | 1 | 3 |
| F 受控委托通道 | Broker/fd/IPC，禁 prompt/日志通道 | 1 | 3 |
| G 动态资源创建 | 工厂 cap + helper 颁发精确 cap | 0 | 2–3 |

**红线一票否决**（任何时刻不允许出现，优先于总分）：任意 shell 常驻工具、进程可读用户 home、网络默认全开、凭据自动进执行环境、子 Agent 继承父权限、工具全量固定暴露、bearer token 可复制重放、撤销只在 UI 层生效。

---

## 15. 工程约定

- **CHANGELOG**：每次有意义的变更追加到 `CHANGELOG.md`（Keep a Changelog 格式）。
- **git commit**：大的变更（新增设计分册、确定关键选型、里程碑实现）单独 commit，message 说明「what + why」。
- **分册拆分**：`docs/capsh-language.md`（capsh 语言规范，**已完成 v0.1**）；后续拆出 `syscall-abi.md`（capvm ABI 细节）、`cap-catalog.md`（每个 cap 类型的完整字段与孤岛检测结论）、`eval-scorecard.md`（评估框架自评产物）。
- **红队集**：`tests/redteam/` 承载评估框架 §4 与 report §11 的用例，作为 CI 门禁。

---

## 16. 决策与开放问题

### 16.1 已定决策（jiangplus 2026-07-07 拍板）

- **D-lang（capsh 实现语言）→ OCaml**。capsh 语言前端 + 求值器 + 类型/IFC 检查用 OCaml；capvm/Broker 核心保持 Rust；两者走带类型的 IPC/FFI 边界。理由:写解释器是 OCaml 主场、迭代快;abstract type = 语言级不可伪造引用(直接兜住不变量 14);GADT/phantom type = 编译期 taint(落地 §6 IFC)。详见 docs/capsh-language.md。
- **D-capvm（capvm 落地方式）→ 改造 secure-exec kernel**。cap-indexed 作为内核原生 ABI,不加翻译 shim。取舍见 §3.1。
- **D-audit（审计防篡改）→ 采用 / 借鉴 nono 方案**。append-only NDJSON + 逐事件滚动 hash-chain + Merkle leaf/root（包含证明）+ DSSE/Sigstore 签名 attestation。tamper-evidence 的意义:审计是问责根基,即使日志存储被攻破,任何插入/删除/修改都可被检测(hash-chain/Merkle)且可追责(签名);capsule「审计跑在 guest 内、guest root 可篡改」是反例。审计写入侧必须在可信宿主(sidecar),不落在 guest。

- **D-encap（语言层强封装形态）→ OCaml abstract type（capsh 侧）**。能力类型在 `.mli` 里抽象、不导出构造子 → capsh 脚本结构上无法构造/匹配/序列化/`Obj.magic` 伪造能力;唯一来源是 Broker 绑定。phantom 种类 + generative-functor 会话 brand + sealer/unsealer 三加成。诚实边界:只挡 capsh 层,原生 OCaml 模块与任意 guest 二进制分别由 TCB 纪律与 L1 沙箱兜底。详见 docs/capsh-language.md §2.3。
- **D-rpc（Capable 需要 RPC）→ 能力传递 RPC**。见 §11.5。连接即最小权限、方法作用在能力引用上、线上引用为会话绑定不可伪造 token、promise + eventual send。（Codar workspace 集成暂不做,但 RPC 先具备。）
- **D-ipc（capsh↔Rust 边界 + 跨机器）→ CapTP-lite over socket**。见 §11.5.2。非裸 FFI、非完整 CapTP;lease 替代分布式 GC、broker 中介替代三方 handoff;本地 Unix socket、远程 TCP/vsock。
- **D-taint（taint/IFC 强度）→ 运行期标签起步,GADT 暂不上**。见 docs/capsh-language.md §6。运行期强制 + declassify 需能力 + confine 区室足够 M0–M3;GADT 编译期化记为「IFC 维度 2→3 分」的后续可选。

### 16.2 仍开放（待评审）

1. 与 Codar / Slock 现有 workspace 隔离的集成点（Capable 作为 Codar 的 workspace 运行时？）——暂不做,待团队对齐。
2. quasi parser 集合是否可扩展（helper 注册自定义安全模板，如 `k8s`…``）。
3. 与 ACP / 现有 tool-calling API 的桥接：capsh 程序如何暴露为 Agent 可调用的动态 tool schema。
