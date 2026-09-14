# 评估:用 fish-shell 重新设计 capsh

> 背景:jiangplus 希望 capsh 在**语法和使用方式上接近现有 shell**(而非当前这门 OCaml DSL)。
> 本文评估以 [fish-shell](https://github.com/fish-shell/fish-shell)(近年已从 C++ **全量重写为 Rust**)
> 为基座重做 capsh 的可行性与取舍。结论基于对 fish 源码 choke point 的实地勘查。

---

## TL;DR

- **值得做,而且比想象的可行。** fish 满足"接近现有 shell"的诉求(干净、成熟、交互 UX 好),且**与我们的 Broker 同为 Rust** —— 可**深改而非旁挂 shim**。
- **关键发现:fish 的 parser 完全无副作用,所有 ambient authority 只经约 6 个单点 choke point。** 因此可以**保留 fish 的 tokenizer/AST/语法/交互 UX,只替换这 6 个"把语法变成真实副作用"的点**,让它们改走 Broker 的能力解析。这正是"复用隔离/执行基座 + 替换权限语义层"(DESIGN §0.3)的另一条落地路径。
- **保留现有资产**:newton 已复审通过的 **L3 Broker + 能力模型 + L5 consent + capvm ABI 原样保留**。fish 版 capsh 只替换**前端语言**,像现在的 OCaml capsh 一样经 CapTP-lite 连同一个 Broker。**"用 fish 重设计 capsh" ≈ 换前端,不动后端。**
- **三个真实代价**:① **GPL-2.0**(fish 是 GPL-2.0-only,fork 即 copyleft,影响产品许可);② 与上游 fish 的**长期分叉维护**;③ **哲学张力** —— "熟悉的 shell UX"恰恰**默认就是 ambient authority**(`$PATH`、`~`、glob、env 继承),把它们改成 Model-4 语义会**改变部分熟悉行为**,需要产品决策。

---

## 1. fish 为什么契合"接近现有 shell"

- 语法干净、可读、`function…end` / `set -l x` / `for x in …; …; end` / `if set -q VAR` / `and`/`or` 连接 / `$argv` / `(cmd)` 命令替换 / `|` 管道 —— 用户已会,学习曲线远低于当前 OCaml DSL capsh。
- **无 word-splitting**(不像 bash 把 `$var` 再拆词)—— 这**天然消一大类注入**,与 capsh 的 quasi-literal 目标同向。
- 一流交互体验:autosuggestion、语法高亮、补全 —— 对"人 + Agent 共用的 shell"很有价值。
- **Rust 同栈**(edition 2024,workspace `crates/*` + 主 crate `src/`)—— 与 `capable-broker` 同语言,可直接内嵌/深改,不必跨 FFI。

## 2. 为什么架构上可行:无副作用 parser + 6 个单点 choke

fish 的**解析完全无 I/O**(`tokenizer.rs`、`ast.rs::parse`、`parse_tree.rs` 产出纯 AST);`parse_execution.rs` 把 AST 降为**声明式**的 Job/Process 图(`RedirectionSpec`、export array 先声明、最后一刻才解析成真实 fd/open)。所有"把语法变成真实副作用"的动作只经这几处单点:

| # | ambient authority | fish 单点位置 | 现状语义(Model 1.5–2) |
|---|---|---|---|
| 1 | 外部命令执行 | `exec.rs::exec_external_command` + `fork_exec/{postfork,spawn}.rs`(唯一 `fork`/`execve`/`posix_spawn` 处)| 任意程序,env 由 `export_array` 全量注入 |
| 2 | 文件打开/重定向 | `fds.rs::open_cloexec`(唯一 `nix::open` 包装),经 `io.rs::append_from_specs` | 任意绝对/相对路径 `open()` |
| 3 | 命令名解析 | `path.rs::path_get_path_core`(唯一 `access(X_OK)` 处)| `$PATH` 搜索(ambient `cat`/`npm`)|
| 4 | 通配符/枚举 | `wildcard.rs::open_dir`(唯一 readdir 处)| 任意目录 glob |
| 5 | env 传给子进程 | `env::export_array`(唯一产出子进程 `envv` 处)| 全量继承 |
| 6 | 命令替换回执行 | `expand.rs::expand_cmdsubst → exec_subshell_for_expand` | `$(...)` 直接回到 fork/exec |

> 勘查确认:**替换这 ~6 点即可把执行层改成 capability-mediated,而复用 tokenizer/AST/降级**。唯一要注意的耦合:展开(`expand.rs`)会经命令替换**回到执行**,故替换执行层必须同时拦 `exec_subshell_for_expand`,不能只拦顶层 job。

## 3. 映射:每个 choke → capsh 能力语义

把 fish 的 6 个 ambient 点改接到我们已有的 Broker 能力(全部 newton 复审过):

| fish choke | 改为 | 复用的 Capable 机制 |
|---|---|---|
| ① 外部 exec | 命令名解析为**词法作用域内的 CommandCap**,否则失败(无 ambient 执行)| `grant_command`(一命令一卡、固定 argv)+ C1 L1 沙箱(Landlock/seccomp)+ L5 consent |
| ② 文件 open | 路径解析为 **DirCap/FileCap** 上的相对访问 | Broker `read/list` + openat2 RESOLVE_BENEATH + 持有 fd anchor |
| ③ `$PATH` 解析 | **取消 `$PATH` 搜索**;命令必须是被 grant/传入的 CommandCap | 能力注册表(会话绑定不可伪造 ref)|
| ④ glob | 只在 DirCap 授权域内枚举 | `list_at`(fd anchor)|
| ⑤ env→子进程 | **剥离继承**,只给 CommandCap 声明的 allowlist | grant_command 现已 PATH-only + C1 close_range |
| ⑥ 命令替换 | 子表达式同样零权限 + 只用传入能力 | capvm C-list / spawn 区室语义 |
| 网络(fish 无原语,靠外部工具)| 只经 **HttpCap** | net.rs SSRF/注入防护 + seccomp 默认禁网 |

**保留现在 capsh 的语义**(grant/衰减/quasi-literal/taint-IFC/spawn-confine),用 fish 语法**表面**表达:`grant`/衰减做成 builtin + 一个不可伪造的**能力值类型**(fish 变量宇宙里新增 Cap 宇宙,数据永不变权限)。

## 4. 核心张力:熟悉的 shell UX ⟂ Model-4

"接近现有 shell" 与 "无 ambient authority" 有**真实冲突**,需产品决策:

- **`$PATH` / 裸命令**:真正的 shell 里 `cat foo` 从 `$PATH` 找 `cat`。Model-4 下 `cat` 必须是作用域里的 CommandCap,否则失败。→ *折中*:提供一个"标准工具集" profile(启动即 grant 一批常见只读工具的 CommandCap),让 `ls`/`cat` 等开箱可用,但仍是能力、可撤销/可衰减,而非 ambient。
- **`~` / 绝对路径 / env 继承**:默认不可见。→ 需要显式 grant 或 profile 注入。
- **交互随手性**:shell 用户习惯"随手 open 任意文件/跑任意命令"。capsh 会在**首次触达新资源时触发 grant/consent**(L5 已实现 JIT consent)—— 这既是安全卖点,也是 UX 摩擦点,要靠 profile + 好的 consent UI 缓解。

一句话:**fish 给你熟悉的语法与手感;但"熟悉的默认权限"必须换成能力。** 能换多少而不失手感,是这次设计的核心权衡。

## 5. 方案对比

- **A. Fork fish + cap-mediate 执行层(推荐)**:保留 parser/语法/UX,替换 §2 的 6 个 choke,接到现有 Broker;grant/衰减/taint 做成 builtin + Cap 值类型。**最贴合双目标**(shell 熟悉 + Model-4 强制)。代价:跨 exec/expand/env/io 深改、GPL-2.0、上游分叉。
- **B. 自研 parser + fish-like 表面语法**(把现 OCaml capsh 换皮成 shell 风格):完全掌控、保留 OCaml abstract-type 的语言级不可伪造保证;但要自己实现一个 shell 前端,永远不如真 fish 完整/熟悉,工作量在前端。
- **C. 不改的 fish 前端 + Broker 后端(纯 shim)**:最快,但 fish 保留全部 ambient 默认 —— 等于"逆着每条默认值打补丁",正是 capsh 设计文档反对的。**不推荐**。

**推荐 A**,并把现有 **OCaml capsh 留作参考语义 / 测试 oracle**(它的类型级 IFC 断言可当 fish 版的 golden 对照)。**Broker 不变**(Backend_rpc 只是 socket 协议,不关心前端是 OCaml 还是 fish)。

## 6. 实务考量

- **许可**:fish = **GPL-2.0-only**(+ LGPL/MIT/PSF 局部)。fork 出的 capsh 将是 GPL-2.0 衍生作品 —— 若 Capable 要闭源/商用发行,这是硬约束;Broker(我们自有)可与之进程分离(GPL 边界落在前端二进制)。**需先定许可策略再动手。**
- **上游分叉**:替换 6 个 choke 是**侵入式**改动(exec/expand/env/io/path/wildcard),与上游 rebase 成本高;建议只在这几个 choke 做**接口切口**(trait 注入),把 cap-mediation 逻辑放我们自己的 crate,尽量少改 fish 本体以便 rebase。
- **工作量(粗估)**:切 6 个 choke + Cap 值类型 + grant/衰减 builtin + 接 Broker ≈ 一个中型里程碑(数周),**远小于**从零写一门完整 shell;但**大于**当前 OCaml capsh 的增量。
- **保留/复用**:L3 Broker、能力模型、C1 沙箱、L5 consent、capvm ABI、net SSRF —— **全部原样复用**。

## 7. 建议的分阶段落地

1. **M0 决策**:许可策略(GPL 是否可接受)+ "标准工具集 profile"的边界(哪些裸命令开箱可用)。
2. **M1 切口**:在 fish 的 6 个 choke 处引入 trait 注入点(`CommandResolver`/`FileOpener`/`PathResolver`/`DirEnumerator`/`EnvProvider`/`SubExec`),默认实现=原生 fish(保证可回归),cap 实现=接 Broker。
3. **M2 Cap 宇宙**:在 fish 变量系统里加不可伪造 Cap 值类型 + `grant`/衰减 builtin;数据永不变权限(沿用现 capsh 两宇宙 + quasi-literal)。
4. **M3 taint/IFC + consent**:值带 taint,secret→sink 拒;高风险动作走 L5 JIT consent(已实现,直接接)。
5. **M4 对照**:用现 OCaml capsh 的示例(hello/injection/command/confine)作 golden,fish 版必须给出同样的允许/拒绝结论。

---

## 结论

用 fish 重设计 capsh **可行且方向正确**:它一次满足"语法接近现有 shell"和"Rust 同栈深改",而其**无副作用 parser + 6 个单点 choke** 的架构,让"复用前端、替换权限语义"成为工程上可控的事。真正要拍板的是**许可(GPL-2.0)**与**UX 取舍**(多少熟悉的 ambient 默认换成能力)。后端(Broker/能力模型/沙箱/consent/capvm)**一律不动**,这把风险主要收敛在前端。
