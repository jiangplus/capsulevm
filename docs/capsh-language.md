# capsh 语言规范 v0.1

> capsh(Capable Shell)—— 一门 capability-native 的 shell / 脚本语言,
> 作为用户与 Agent 在 Capable 上操作 capability 的界面与编程模型。
> 运行在 capvm 之上,唯一授权入口是 Capability Broker。

本文是 DESIGN.md §5 的展开。设计谱系:**E 语言**(Mark Miller 等)的对象能力模型 + Capsicum 的 pre-open/cap_enter + 本仓库 design 文档的 16 条不变量。

---

## 0. 设计目标:为什么要一门新语言,而不是 Bash 补丁

POSIX shell 的每一个默认值都是 ambient authority:路径是字符串、命令从 `$PATH` 查、env 默认继承、子进程默认继承 fd、网络和 home 默认可见。在这种语义上做安全等于逆着语言的每一条默认值打补丁。

capsh 反过来:**默认值即最小权限**。语言层结构性地保证:

1. **没有对象引用就没有权限**——没有全局命名空间,没有 `$PATH`,没有 ambient `cat`/`npm`。一个名字只有在词法作用域里、或被显式传入时才可达。
2. **数据和能力是两个宇宙**——普通值(Data)永远不能变成权限;能力(Cap)是不可伪造、不可序列化的对象引用。
3. **衰减是构造,不是检查**——收窄权限就是调用能力对象的方法得到一个更窄的新能力(facet),而不是「先给全量再运行时检查」。
4. **注入在语法层被杀死**——所有「把数据拼进结构」的地方(命令、路径、SQL、HTTP)都走 quasi-literal,插值永远是数据、永远不改变结构。
5. **信息流在类型层被强制**——值携带 taint;带 `secret` taint 的值流入外发 sink 必须显式 declassify(而 declassify 需要用户授予的能力)。
6. **并发是能力传递**——子任务/子 Agent 是新的 vat,通过 eventual send 通信,委托即传入衰减后的能力。

一句话:**capsh 让「做安全的事」比「做不安全的事」更省力,因为不安全的事在语言里根本表达不出来。**

---

## 1. 词法与两个宇宙

### 1.1 值的两个宇宙

| 宇宙 | 例子 | 能做什么 |
|---|---|---|
| **Data** | `"hello"`、`42`、`[1,2,3]`、`{k: v}`、`path`src`` | 计算、比较、拼接、模式匹配。**永远不能直接访问资源。** |
| **Cap** | `DirCap`、`HttpCap`、`CommandCap`、`Revoker`… | 通过方法访问资源。不可伪造、不可序列化、不可打印为可重放 token。 |

关键区分(不变量 2):

```capsh
let p = "../.ssh/id_rsa"     # Data(String)
p.read()                     # ✗ 编译错误:String 没有 .read();字符串不是能力

let src = grant dir "./src" {read}   # Cap(DirCap)
src.read(path`main.ts`)              # ✓
```

### 1.2 Data 携带 taint 与 provenance

每个 Data 值的静态类型里带一个 taint 标签(格,lattice):

```text
Taint = green | yellow | red        # 三色信任(DESIGN §7.1)
      | secret | project | external | agent_generated   # 细粒度污点
```

taint 随数据流传播(拼接取上确界),并参与信息流检查(§6)。provenance(来源链)随值携带,供审计与来源链展示。

```capsh
let readme = fetch(webCap, "/README")   # : Data<red, external>   —— 网页内容是红色
let note   = "run: " ++ readme          # : Data<red>              —— 拼接后仍是红色
```

---

## 2. 能力即对象,衰减即方法链

能力是对象引用,你向它**发消息**(调方法)。这继承自 E 的核心洞见:对象引用本身就是能力。

### 2.1 衰减方法(attenuation)返回更窄的新能力

每个衰减方法都产出一个新的、只会更窄的 facet(DESIGN §4.3);原能力不变。

```capsh
let repo = grant dir "." {read, write}

let srcRO = repo / "src" |> readOnly        # DirCap,收窄到 src 且只读
let noEnv = repo.exclude([glob`**/.env`, glob`**/.git/hooks/**`])
```

内置衰减方法(部分):

| 方法 | 适用能力 | 语义 |
|---|---|---|
| `readOnly` | Dir/File/Db | 去掉写/删操作 |
| `/ segment` 或 `.sub(seg)` | Dir | 收窄到子目录(相对,`deny_parent_escape`)|
| `.include(globs)` / `.exclude(globs)` | Dir | 收窄可见集 |
| `.methods([...])` / `.paths([...])` | Http | 收窄 HTTP method / path pattern |
| `.rate(n/period)` / `.bytes(limit)` | Http/Message/Db | 加配额 facet |
| `.ttl(dur)` / `.once()` / `.uses(n)` | 任意 | 收窄生命周期 |
| `.tainting(tag)` | 任意读能力 | 声明其输出的 taint |

衰减是**单向不可逆**(决策 D10=A):没有「加宽」方法。要更宽的能力只能重新 `grant`(触发新的 consent)。

### 2.2 能力不可序列化 / 不可打印(不变量 8)

```capsh
print(repo)          # 打印占位符 <cap:repo read,write @/…> ,不是可调用引用
str(repo)            # ✗ 运行时 violation:能力不可转字符串
env.set("R", repo)   # ✗ 能力不能进 env
```

真实引用只活在 Broker/sidecar 进程内;capsh 侧持有的是本地句柄(像 fd 槽位),换会话/换主体即失效(不变量 14)。

### 2.3 语言层强封装:OCaml abstract type(决策 D2 = capsh 侧)

不变量 14(不可伪造)与不变量 8(不可序列化)在 capsh 里不是靠运行时检查,而是靠 **OCaml 的 abstract type 结构性保证**。

capsh 求值器用 OCaml 实现,能力类型在 `.mli` 签名里声明为**抽象类型**,不导出任何构造子:

```ocaml
(* cap.mli —— 对外签名,表示被隐藏 *)
module Cap : sig
  type 'k t                       (* 能力,种类由 phantom 参数 'k 标注;抽象:外部无法构造 *)
  type dir  type file  type http  type command   (* phantom 种类标签 *)

  (* 对外只暴露「使用」与「衰减」,没有 val make : … -> 'k t *)
  val read      : dir t -> Path.rel -> Bytes.tainted
  val sub       : dir t -> Path.seg -> dir t       (* 衰减:返回更窄的新能力 *)
  val read_only : dir t -> dir t
  (* … *)
end
```

因为 `type 'k t` 在签名里抽象,`Cap` 模块**之外**的代码(包括 agent 生成的 capsh 脚本)结构上做不到:

- **构造**一个 `Cap.t`——没有构造子、没有记录/变体字面量可用;
- 对它**模式匹配**——看不到表示;
- **序列化**它——`Marshal` 无结构可抓,且约定禁用;
- **`Obj.magic` 伪造**——`unsafe`,由 lint 在 TCB 边界禁止。

于是**获得能力的唯一途径 = 从 Broker 绑定拿**:`grant`(powerbox)、启动注入的根、或对已持有能力衰减。类型系统本身成为不变量 14/8 的编译期强制。

三个加成:

1. **phantom 参数 `'k` 编码种类**:`read : dir t -> …` 结构上拒收 `http t`;衰减方法的类型保持/收窄种类。
2. **generative functor 铸会话 brand**:每会话用 `module F() : sig type brand … end` 生成一个新抽象类型,会话 A 的能力与会话 B **类型都不兼容** → 「脱离 registry 上下文失效」在类型层成立,不仅是运行时校验。
3. **sealer/unsealer(Morris 1973;E 用它做权限放大)**:用闭包 + 抽象类型(或局部 exception)实现一对 seal/unseal;真实凭据被 seal,只有 CredentialCap helper 持 unsealer 能开 → 落地不变量 15(凭据值不交给 Agent)。

**诚实边界(必须写清)**:abstract type 只挡 **capsh 层代码**伪造能力;一个恶意的**原生 OCaml 模块**仍能 `Obj.magic` / `Marshal` 绕过。因此:

- TCB = OCaml 求值器 + Broker 绑定模块;capsh 脚本是被求值的**不可信层**,只能用暴露的 Cap API。
- 任意**原生 guest 二进制**(不是 capsh 脚本)不走这条封装,仍由 capvm 的 cap-indexed syscall + L1 OS 沙箱兜底(DESIGN §3、§9)。

两层各管一段(D2 = 分层):语言层封装管 capsh 编排层,OS/VM 层管任意原生代码。把强封装放在 capsh 侧,正是因为 OCaml 的类型抽象是**静态且完全的**(编译期、无遗漏),比 Hardened JS Compartment 的运行时 membrane 更省力、更强。

---

## 3. 语法总览(EBNF 摘要)

```ebnf
program     = { statement } ;
statement   = binding | expr | control | spawn | confine | prepareCommit ;
binding     = "let" pattern [":" type] "=" expr ;
expr        = literal | quasi | name | call | method | pipe | grant | matchExpr ;
pipe        = expr "|>" expr ;                 (* 值/能力管道,携带 provenance+taint *)
call        = name "(" [ args ] ")" ;
method      = expr "." name [ "(" [ args ] ")" ] ;
grant       = "grant" capType dataArg [ block ] ;   (* 唯一新增权限入口,触发 consent *)
quasi       = ident "`" quasiBody "`" ;        (* 注入安全模板:sh / path / glob / sql / url *)
spawn       = "spawn" ( "task" | "agent" ) stringLit block ;
confine     = "confine" block ;                (* 区室,见 §7 *)
prepareCommit = "prepare" expr "as" name | "commit" name ;
control     = "if" | "match" | "for" | "try" ;
pattern     = name | tuplePat | recordPat ;    (* 支持解构,含 (cap, revoker) *)
```

capsh 是**表达式语言**(每个语句有值),静态可选类型标注,动态检查兜底。

---

## 4. Quasi-literal:从语法层杀死注入(核心创新)

E 的 quasi-literal 用于安全模板;capsh 把它作为「命令/路径/URL/SQL 不是字符串拼接」的强制手段。quasi 的插值 `${x}` **永远是数据,永远不改变模板结构**。

```capsh
let name = userInput()                       # Data<red>
let f    = path`src/${name}.ts`              # PathTemplate:${name} 只能是一个路径段,
                                             # 不能是 "../etc/passwd" —— 解析器拒绝分隔符
repo.read(f)

let t = sh`npm test`                         # CommandTemplate:固定 argv 结构
let i = sh`npm install ${pkg}`               # ${pkg} 是一个 argv 元素,不是可注入的 shell 串
run grant command t {cwd: repo, network: none}
```

每种 quasi 有自己的 parser 与约束:

| quasi | 产物 | 拒绝什么 |
|---|---|---|
| `path`…`` | PathTemplate | `..`、绝对路径、插值里含分隔符 |
| `glob`…`` | GlobPattern | 逃逸出授予根的模式 |
| `sh`…`` | CommandTemplate | 插值改变 argv 结构;不存在 shell 元字符解释(无 `\|`、`;`、`$()` )|
| `url`…`` | UrlTemplate | 插值改变 origin/scheme;private network |
| `sql`…`` | QueryTemplate | 插值出现在标识符/关键字位置(只能进值位)|

**要点**:capsh 里根本没有「把一个字符串当命令跑」的原语。`run` 只接受 `CommandCap`,而 `CommandCap` 只能由 `sh` quasi 模板 + `grant command` 构造。这就是不变量 2 的语法级落地。

---

## 5. grant / powerbox:唯一的新增授权入口

`grant` 是与 Broker「powerbox」的交互——获取**当前尚未持有、也无法从已持有能力衰减得到**的新权限。它一定触发 consent(L5/L6),并把结果作为不可伪造对象返回。

```capsh
let net = grant http "https://api.example.com" {
  methods: [GET],
  paths:   [path`/v1/*`],
  ttl:     10m,
}
```

- 能从已有能力衰减得到的,**不要** grant——直接 `derive`(方法链),不打扰用户。
- `grant` 的 block 就是一次 consent 请求的结构化内容(类型/scope/operations/lifetime),UI 据此渲染弹窗,按钮为 `[允许一次][本任务同范围][缩小范围][拒绝]`(DESIGN §8.2),绝无 "Allow all"。
- 无人值守场景:powerbox 由 L5 Policy Engine 按策略应答;红/黄内容不能触发升绿(决策 D12)。

---

## 6. 信息流:taint-aware,语言层强制 confinement

capsh 把「敏感读 + 任意外发」的危险组合从「靠 Agent 自觉」提升为**语言层结构约束**。

> **实现节奏(决策 D-taint,jiangplus 2026-07-07):运行期 taint 标签起步,GADT 编译期 IFC 暂不上。** 每个 Data/PipeValue 携带运行期 taint 标签,外发 sink 调用前运行期检查并拒绝 `secret→sink`(下面 `✗` 标注的检查 M0–M3 先落在运行期)。运行期强制 + declassify 需能力 + confine 区室,已足够覆盖 confinement 红队用例。把 taint/IFC 升到 GADT 编译期类型(下面标「编译期」处)记为**后续可选**——仅当需要「任何路径都不可能泄」的静态保证(而非「发生即拦」的动态检测)时才付出 GADT 的代价(类型推断变难、报错变差)。这对应评估框架里「把 IFC 维度从 2 分升 3 分」,诚实标注不虚标。

### 6.1 外发 sink 的类型签名带 taint 约束

外发能力(HttpCap.post / MessageCap.send / DbCap.write / GitPushCap)的方法签名要求输入 taint ≤ 某上界;`secret` 数据流入被拒:

```capsh
let secret = grant file ".env" {read} |> (.read())   # Data<secret>
net.post("/collect", secret)      # ✗ IFC violation:secret 不能流入外发 sink
```

### 6.2 declassify 需要能力,Agent 自己不能批准

```capsh
# declassify 本身是一个能力,只能由用户/策略颁发(不变量:Agent 不能自我 declassify)
let dc = grant declassify {of: secret, to: net, reason: "上报去敏摘要"}
net.post("/collect", declassify(dc, summary(secret)))   # ✓ 且记 trust.upgraded 审计
```

### 6.3 confine 区室(compartment)—— fork+cap_enter 的语言形态

`confine` 创建一个词法区室:区室内的代码**只能看到显式传入的能力**,且静态规则禁止同一区室同时持有敏感读能力与外发 sink(DESIGN §7.3)。

```capsh
let sensitive = repo / "secrets" |> readOnly
let outbound  = net

confine {
  reader with [sensitive] {          # Reader 区室:有敏感读,无外发
    let data = sensitive.read(path`token.json`)
    yield schema(data)               # 只能通过 schema 化结构 yield 出去
  }
  sender with [outbound] {           # Sender 区室:有外发,无敏感读
    outbound.post("/report", $in)    # $in 是上一区室 yield 的 schema 结构
  }
}
# ✗ 若把 [sensitive, outbound] 放进同一个 with,编译期即报 confinement 冲突
```

区室在 capvm 里落地为独立 isolate + Broker 只发对应 cap 集,等价于 `cap_enter()` 之后连 open 都失败。

---

## 7. prepare / commit:破坏性操作两阶段

写、删、push 等有副作用操作必须两阶段:prepare 产出预览 + 一次性能力,commit 消费它(DESIGN §5.3、不变量 6)。

```capsh
let patch = prepare repo.write(path`src/main.ts`, newContent) as p
show(patch.diff)              # 展示 diff,绑定 diff hash
commit p                      # 用一次性 WritePatchCap;用完即焚,再 commit 报 already-consumed
```

`commit` 的能力生命周期恒为 `once`,scope 绑定内容 hash + 目标路径。极高风险(push/生产/密钥导出)在 commit 前叠加带外二次确认(决策 D6)。

---

## 8. 并发:eventual send、promise、子 Agent 委托

capsh 的并发模型借鉴 E:子任务/子 Agent 是独立 vat,通过**eventual send**(`<-`)通信,结果是 promise,可 pipeline。委托即在 spawn 时传入衰减后的能力。

### 8.1 spawn:默认零权限 + 显式衰减委托

```capsh
let sub = spawn agent "审查 auth 模块" {
  delegate: [
    repo / "src/auth" |> readOnly,     # 只读 auth 子树
    llm.budget(0.2),                    # 20% token 预算
  ]
  # 未列出的能力,子 Agent 结构上拿不到:不能写、不能联网、不能 shell
}
```

- 无 `delegate` 项 → 子 Agent 零权限。
- 父只能委托自己已有能力的衰减版(委托不能扩大)。
- 委托前 UI 展示委托图;子 Agent 输出 taint 至少 `red`(不变量 16 同理:视同不可信)。
- 父能力撤销 → 派生给子的能力级联失效(§9)。

### 8.2 eventual send 与 promise

```capsh
let result <- sub.review(schema(diff))      # eventual send:非阻塞,返回 promise
let summary <- result.summary()             # promise pipelining:无需等 result 落地即可继续编排
when summary -> s {                          # promise resolve 回调
  show(s)
}
```

eventual send 天然契合分布式(子 Agent 可能在别的 capvm / 别的机器),也避免同步阻塞下的重入攻击面。

---

## 9. 撤销:revocable forwarder 一等公民

撤销是 Redell 1974 转发器方案的直接语言化(DESIGN §4.4):任何能力都能包一层可撤销 forwarder。

```capsh
let (netF, revoker) = makeRevocable(net)     # 返回 forwarder facet + 撤销器
sub.giveNetwork(netF)                         # 把 forwarder 交给子 Agent
# …
revoker.revoke()                              # 断链;子 Agent 手里 netF 仍在,但调用返回 ENOTCAPABLE
```

三性质:撤销可传递(撤上游级联撤下游)、不改对方的能力表、纯用户态(调用前逐级检查祖先链)。`revoke` 产生 `cap.revoked` 审计事件,下一轮 tool schema 立即更新(§11)。

---

## 10. 兼容旧世界:legacy 沙箱

不能让旧 Bash 脚本无约束跑。`legacy` 块把旧程序关进 capvm 沙箱,只映射显式能力:

```capsh
legacy sh`make test` with {
  cwd:     repo |> readOnly |> (. / "build" |> writable),
  network: none,
  env:     {PATH: system.path, HOME: sandbox.home},   # allowlist,非继承
  timeout: 60s,
}
```

明确拒绝(结构上不可表达):绝对路径、真实 home、任意 env 继承、默认网络、SSH agent/keychain、process table、继承的 DB/MQ 连接。

---

## 11. 错误模型与审计

- 能力违规统一抛 `ENOTCAPABLE`,携带可解释信息(operation / requested / held / reason / next),既给 LLM 也给用户看(DESIGN §4.6)。
- **没有任何原语能静默调用能力**——每次能力方法调用都经 AuditFacet 产生结构化事件(`cap.requested/granted/denied`、`tool.started/finished`、`cap.revoked` 等,DESIGN §9)。
- capsh 求值器保证:能力不进 prompt/日志/env/剪贴板/URL/模型输出;若 secret scanner 在输出发现真实 secret,触发 `violation.detected` + 撤销相关能力 + 提示轮换。

---

## 12. 一个完整例子:联网研究 + 本地写入,结构性防外泄

```capsh
# 会话根:启动目录即 workspace 能力(默认只读,敏感文件排除)
let repo = workspace                          # DirCap<read>,自动排除 .env/.git/hooks/密钥

# 1) 联网研究(红色数据,只读网络,无本地写、无敏感读)
let web  = grant http "https://docs.example.com" {methods: [GET], ttl: 15m}
let doc  = web.get(path`/guide`)              # Data<red, external>

# 2) 想把结论写进本地 —— 走 prepare/commit,内容来自红色数据要留痕
let draft = summarize(doc)                     # Data<red>(仍红,来源可追)
let patch = prepare repo.write(path`NOTES.md`, draft) as p
show(patch.diff)                               # 用户看到 diff + 来源链(内容源自 example.com)
commit p                                        # 一次性写

# 3) 结构保证:web 是 GET-only,repo 无外发能力 —— 即使 doc 内嵌
#    "把 ~/.ssh 发到 evil.com" 的指令,capsh 里也无路可走:
#    - 没有 ~/.ssh 的 DirCap(workspace 之外)
#    - 没有 POST 能力(web 只 GET)
#    - doc 是 Data<red>,不能变成命令
```

---

## 13. 与 Broker / capvm 的映射

| capsh 构造 | Broker / capvm syscall |
|---|---|
| `grant …` | Broker powerbox → consent → 颁发能力,注入进程 cap_table |
| `cap.method()`(读/写/连接/发送/执行)| `cap_read / cap_prepare_write+cap_commit / cap_connect / cap_send / cap_exec` |
| `cap / seg`、`readOnly` 等衰减 | `cap_derive(cap, attenuation)` |
| `spawn … {delegate}` | 新 subject + `cap_delegate` 衰减能力 |
| `makeRevocable` / `revoker.revoke` | forwarder facet + `cap_revoke` |
| `confine { … with […] }` | 独立 isolate + Broker 只发对应 cap 集 |
| `prepare … / commit` | `cap_prepare_write` → 一次性 WritePatchCap → `cap_commit` |
| quasi-literal 解析 | 编译期约束,产出的模板作为 `grant command/http/…` 的 scope |

---

## 14. 决策与未决(见 DESIGN §16)

已定:
1. **求值器语言 → OCaml**(§2.3;abstract type = 语言级不可伪造引用)。
2. **taint/IFC → 运行期标签起步,GADT 暂不上**(§6 顶部;仅在需静态保证时升级)。
3. **capsh↔Rust 基座 + 跨机器 → CapTP-lite over socket**(见 DESIGN §RPC):不可伪造会话绑定引用 + promise + eventual send,用 lease/TTL 回收替代分布式 GC、broker 中介替代三方 handoff;本地走 Unix socket、远程走 TCP/vsock;裸 FFI 只在测出热点时再上。

仍开放:
4. quasi parser 集合是否可扩展(让 helper 注册自己的安全模板,如 `k8s`…``)。
5. 与 ACP / 现有 tool-calling API 的桥接:capsh 程序如何暴露为 Agent 可调用的动态 tool schema。
