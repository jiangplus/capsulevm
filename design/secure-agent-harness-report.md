# Secure Agent Harness 设计报告

> 基于最小权限原则（POLP）与 Object Capability（OCap）模型的安全 Agent 运行时设计。
> 本报告综合本目录全部研究文档（polp.md、ocap.md、capability-myths-demolished.md、capsicum.md、ocap-agent-design.md、harness.md、agent-harness-os-perspect.md、ocap-eval-framework.md 等），给出一个统一的、可分阶段落地的工程模型。
> 本版已将两份增补分析（Opus 4.8 版、Fable 5 版）合并入正文：补齐了理论论证（委托混淆问题经典案例、四模型光谱、三神话辟谣、现代系统背书）与工程盲点（缺失的 capability 类型、评分档位、区室化 OS 蓝图），并把尚未定论的选型整理成 §14「待决策问题清单」。

---

## 0. 摘要

当前主流 Agent Harness 的根本问题不是模型不够聪明，而是权限模型默认错误：Agent 进程继承用户的全部环境权限（ambient authority），LLM 输出一个路径或 URL 字符串，Harness 就用用户身份去执行。在这个结构下，一次 prompt injection 等价于一次任意代码执行漏洞，而它在结构上正是 1988 年委托混淆问题（Confused Deputy）的重演。

本报告提出的模型可以概括为一句话：

> **Harness 不再问"是否允许 Agent 继续"，而是问"是否向这个 Agent 颁发这个具体 capability"。**

核心机制有六项：

1. **工具即 capability**：Agent 的 tool schema 由其当前持有的 capability 集动态生成，没有引用的能力在工具列表里根本不出现。
2. **默认零权限 + 显式衰减委托**：子 Agent 默认无任何权限，父 Agent 只能转交比自己更小的权限。
3. **可撤销转发器**：所有 capability 经 forwarder/revoker 对颁发，用户可随时一键撤销，撤销沿委托链级联。
4. **三色信任标签 + 来源链**：外部内容永远是数据不是命令，高危操作必须展示决策来源链。
5. **区室化 confinement**：「敏感读」与「任意外发」两类 capability 永不同时出现在同一 Agent 手中。
6. **Prepare/Commit 分离**：破坏性操作先预览后提交，提交使用一次性 capability，用完即焚。

配套给出五阶段落地路线图（M0–M4），每阶段有明确的技术选型和验收标准，M0 单独实施即可把爆炸半径从「整个用户账号」缩小到「当前项目目录」。§14 另列出 15 个尚待评审拍板的选型问题。

---

## 1. 问题陈述与威胁模型

### 1.1 为什么现有 Harness 结构性不安全

LLM Agent Harness 是一个特权放大器：

```text
用户一句自然语言 → LLM 解释（不可信决策源）→ 调用工具（强能力）→ 以用户身份操作真实世界（全量权限）
```

三个性质叠加：决策来自不可信源、工具能力强、运行在用户完整权限下。典型反模式：

```text
Agent 进程 = 用户进程
工具 = 全局函数，任何时刻可调用
路径 / URL / 命令 = 裸字符串参数
子 Agent = 默认继承父 Agent 全部权限
审批 = 模糊的 Allow / Deny 弹窗（确认疲劳 → 无脑同意）
```

用《Capability Myths Demolished》七属性的语言描述，这是同时缺失属性 A（指名与授权绑定）、属性 D（无环境权限）、属性 B + G（动态主体与动态资源创建）——而 B + G 恰恰是最小权限可实施的必要条件。POLP 在 ACL 结构下失败了 50 年，不是因为人蠢或人懒，而是因为在 ACL 里多给权限省力、少给权限费力，激励结构是反的。OCap 把这个激励反转过来：不传引用就没有权限，少给才是默认。

**为什么「改良 ACL 就够了」不成立。** 面对怀疑者，有两个常见反驳需要正面回应：

- **「ACL 和 capability 本质等价」**（等价神话）。反驳者说两者只是同一张访问矩阵的行视图与列视图。问题在于那张矩阵是静态快照，而安全是动态的。真正要命的问题——权限怎么被创建、怎么流动、谁有资格委托给谁、怎么撤销、怎么衰减组合——在这些动态行为上两个模型的答案完全不同。拿静态快照说等价，就像说两个程序等价、理由是它们开机那一秒变量值相同。
- **「ACL 加审批流程就行」**。ACL 有三个结构性缺陷，不是加流程能补的：(1) **主体粒度太粗**——无法给「这一次调用」单独授权，最细只能到用户/角色；(2) **委托不可缩减**——子进程要拿到比父进程更小的权限，唯一办法是新建专用账号 + 改资源侧 ACL，引入额外管理、竞态窗口，且是全局操作，所以现实里没人为压一张图去建账号，只能给全量权限；(3) **权限管理与资源绑定**——元权限跟资源所有权绑死，导致资源中心式管理，主体侧看不清「我现在到底能干什么」。

这三点正是本设计「窄 capability + 衰减委托 + 主体侧 registry」三个核心设计的存在理由。

### 1.2 委托混淆问题：从 1988 编译器到今天的 prompt injection

委托混淆问题是整个设计的地基，值得展开一次。

**原始案例（Hardy 1988）。** 一个分时系统上的编译器服务：用户付费调用，编译器需要向一个受保护的计费文件 `BILL`（只有编译器有权写）追加计费记录；编译器同时接受用户传入的 `--debug-output=<文件名>` 参数，把调试信息写到用户指定的文件。攻击者调用：

```text
compiler --debug-output=BILL source.c
```

编译器一看：写文件？我有写权限，写。于是调试信息覆盖了计费文件。编译器全程没有越权，每一步都在自己的权限范围内。要害不在编译器有 bug，而在于**「指名（designation）」和「授权（authority）」走了两条不同的通道**：文件名是攻击者通过参数给的（不带权限），写权限是编译器自己历史积累的（ambient authority）。编译器无法区分「这个名字该用谁的权限去解释」，于是默认用了自己的——它成了一个被混淆的、替攻击者办事的代理（deputy）。

**同一个 bug 的三次转世**，不同背景的读者各自熟悉其中一环：

| 年代 | 形态 | designation（谁给的名字） | authority（谁的权限） |
|------|------|--------------------------|----------------------|
| 1988 | 编译器 `--debug-output=BILL` | 攻击者传入的文件名 | 编译器自己的计费写权限 |
| 2000s | **CSRF** | 攻击者网页里的 `<img src=bank/transfer>` | 浏览器自动携带的 session cookie（ambient authority） |
| 2024+ | **Prompt injection** | 网页/README/Issue 里嵌入的「运行 rm -rf …」 | Agent 进程继承的用户全部权限 |

三者结构完全同构：**不可信来源提供了「做什么、对谁做」，可信主体贡献了「用什么权限做」，而系统没有把这两者绑定**。CSRF 这一环尤其值得记住——「浏览器自动带 cookie」是最直观的 ambient authority 例子。

**OCap 为什么结构性免疫。** 核心不变量 designation = authority（指名即授权）直接堵死这条路：要让编译器写某文件，调用方必须把该文件的 capability 连同名字一起传进来；调用方传不出 `BILL` 的 capability（它没有），就无从指名。到 Agent 场景，这条不变量的落地就是 §3 不变量 2「裸字符串路径/URL/命令名本身不是权限」。

> **一句话记法：委托混淆问题的根治不是「更小心地检查参数」，而是「让参数自带它该用的权限，主体没有可乱用的历史权限」。** 这正是最小权限（无环境权限，属性 D）与免于委托混淆（指名即授权，属性 A）是同一机制的两个面向——A 推出 D：指名即授权意味着必须显式传参，显式传参意味着没有环境权限。

### 1.3 威胁模型

| 威胁 | 机理 | 结构性对策 |
|------|------|-----------|
| Prompt injection | 网页/文件/日志中嵌入指令劫持 Agent 行为 | 红色内容只作数据；处理不可信输入的区室不持有外发/写 capability |
| 委托混淆问题 | Agent 用自己的权限执行攻击者指定的资源名（1988 编译器与 2024 prompt injection 同构） | designation 与 authority 绑定，裸字符串不是权限 |
| 数据外泄 | 敏感读 + 任意网络外发的组合 | confinement：两类 capability 区室分离 |
| 权限横向扩张 | 通过 shell 获取工具集之外的能力 | shell 是显式 capability，默认不颁发 |
| 子 Agent 失控 | 子 Agent 继承父权限后被注入 | 默认零权限，只接收显式衰减委托 |
| 持久化逃逸 | 修改自身配置、`.git/hooks`、植入后门 | 配置与 hooks 路径默认排除在 capability 覆盖之外 |
| 凭据窃取 | token/cookie/SSH agent 随环境进入工具进程 | 环境权限默认剥离，凭据经专用 capability，值不进 prompt |
| 撤销失效/重放 | 旧引用在撤销后仍可用 | forwarder/revoker 机制，撤销级联到派生链 |
| 资源耗尽 | token 燃烧、磁盘填满、API 限额耗尽 | capability 携带 quota/TTL/次数配额 |
| **工具实现自身有漏洞** | 即便无注入，helper 自身的解析器 bug / 依赖投毒被恶意文件触发 RCE | OS 沙箱独立兜底：无 home、无网络、seccomp 把爆炸半径锁在 worker 内 |

最后一行是常被忽略的第一性视角：最小权限的经典价值不只是「减少信任」，更是**当程序自身有漏洞时缩小它能被滥用的破坏半径**。这也正是 OS 沙箱（L1）作为独立兜底层不能省的根本理由——它防的是应用层 Broker 自己有 bug 的情况，与语义层正交。

---

## 2. 理论基础：四种安全模型与三个神话

### 2.1 四模型光谱与 Registry 退化陷阱

《Capability Myths Demolished》给出一个诊断工具：**四模型光谱**。它直接决定本设计的自评分卡（§13）站不站得住。

| 模型 | 结构 | 权限如何呈现给系统 | 典型代表 | 致命弱点 |
|------|------|-------------------|---------|---------|
| **Model 1** ACL 列 | 资源侧记「谁能访问我」 | 主体报出**身份**，系统查表 | Unix 文件权限、NT ACL | 有环境权限，委托混淆问题温床 |
| **Model 2** Capability 行 | 主体侧记「我能访问谁」——但仍是记账表 | 主体报出**资源名**，系统查主体的行 | 很多「号称 capability」的系统 | 只是把 ACL 转置，名字仍可伪造/猜测，本质没变 |
| **Model 3** Capability as Keys（钥匙） | 权限是一把可传递的钥匙/令牌 | 主体**出示令牌**，令牌即权限 | bearer token、OAuth token、物理钥匙 | 钥匙可复制、可转交给任何人、难撤销、难约束再委托——confinement 与撤销两大「神话」的根源 |
| **Model 4** Object Capability | 权限是一个不可伪造的对象引用 | 主体**持有引用并调用其方法**，引用无法凭空构造 | KeyKOS、EROS、E 语言、Unix fd（近似） | 需要运行时/语言支持不可伪造性 |

**只有 Model 4 是「正统 capability」。** POSIX Capabilities、Netscape 的 capability、各种 split-capability 都是术语误用（多为 Model 2 的标志位形式）。

**关键警示：Registry 别做成「Model 2 换皮」。** 本设计的 `cap_ref`（opaque ID + Broker 查表映射，见 §5.1）在实现上极易滑成 Model 2：如果 Broker 的逻辑是「LLM 报一个 ID 字符串 → 查 registry 这张表 → 命中就放行」，而这个 ID 可被猜测、可从日志抄出、脱离当前 registry 仍可用，那它就是一张行视图记账表，不是不可伪造引用——这样自评分卡 A/F 给 3 分就是虚高的。要真正落在 Model 4，必须锁死两条硬约束（已升格为 §3 不变量 14）：

1. cap id 必须密码学不可猜测（≥128 bit 随机 / HMAC(session_key, cap_content)），LLM 无法通过枚举或拼接构造合法 ID。
2. cap id 脱离颁发它的 registry 上下文即失效——即使被抄进 prompt 或日志，换一个会话 / 换一个 subject 也调不动（ID 与 subject、session 绑定校验）。

同理，`CredentialCap` / `ServiceCap` 里的 OAuth / bearer token 天然是 **Model 3 钥匙**。设计红线：这些钥匙永远留在 Harness 进程内，Agent 拿到的是「对钥匙的受限对象引用（Model 4 facet）」而非钥匙本身——这是本设计不滑向 Model 3 的分界线（见 §5.4）。

**命名澄清**：`CommandCap` / `ServiceCap` 这类命名容易让人联想到 POSIX Capabilities 的标志位。本设计所有 `XxxCap` 都是「对象引用式（Model 4）」而非「标志位式」——持有即可调用其方法，衰减产生新的受限引用，不是在一个位图上翻几个 bit。

### 2.2 三个神话辟谣

这三条是团队和管理层最常见的认知偏差，说服他们采纳本设计前必须先破：

| 神话 | 常见说法 | 破法 |
|------|---------|------|
| **等价神话** | 「ACL 和 capability 只是记账方向不同，本质等价」 | 静态矩阵等价 ≠ 动态安全等价。真正决定安全的是权限如何被创建、传递、撤销、组合、限制——这些恰恰是矩阵静态视图看不见的维度。 |
| **限制（confinement）神话** | 「capability 系统无法限制信息外泄」（源自 Boebert 1984 对 *-Property 的论证） | 该论证的前提「capability 只是可被当数据传播的位串」在 type-enforced / 纯 OCap 系统中不成立。Shapiro & Weber (2000) 证明在这类系统中 confinement 可判定——连通分量 + factory 形式化即可保证。本设计的区室化正是它的工程版。 |
| **不可撤销神话** | 「capability 一旦给出就收不回」 | Redell (1974) 的转发器/撤销器方案早已解决：`Agent → Forwarder → Revoker → 资源`，撤销即断链，不需要任何内核特殊支持，普通对象即可实现。这正是 §5.4 的机制。 |

> 撤销神话之所以流行，是因为大多数人心里的 capability 是 Model 3 钥匙（钥匙确实收不回）。一旦理解本设计是 Model 4 对象引用，撤销就是自然的。

---

## 3. 设计原则（16 条不变量）

以下 16 条是实现必须保持的不变量，任何一条被打破即视为安全边界失效：

1. 未持有 capability 的工具不出现在 Agent tool schema 中。
2. 字符串路径、URL、命令名本身不是权限；裸名称只能触发授权申请流程。
3. 子 Agent 默认零权限，只能接收衰减后的 capability，委托不能扩大。
4. 红色来源内容不能直接成为有副作用动作的授权依据。
5. `@file` / `@dir` 等用户交付只授予读取 authority，不自动提升内容 trust。
6. 高风险操作必须 prepare/commit 分离，commit 用一次性 capability。
7. 所有 capability 可撤销、可过期、可审计；撤销沿委托链级联。
8. Capability 不得序列化到 prompt、日志、环境变量、剪贴板、URL 或模型输出。
9. Tool worker 默认剥离环境变量、默认云凭据、SSH agent、cookie、keychain、metadata service 与用户 home。
10. 动态资源（网络/浏览器/数据库/凭据）必须经受限 helper/proxy，helper 自身必须有 limit API。
11. OS 沙箱作为 Broker 之外的独立兜底层，应用层 bug 不应导致越界。
12. 每个有副作用行动有 trace id，记录 observe → plan → authorize → execute → verify → revoke 全链路。
13. UI 必须实时显示当前活跃 capability，而不只是历史日志。
14. **cap 的真实引用必须密码学不可伪造、不可猜测，脱离 Broker registry 无法调用；显示 ID 仅为占位符，泄露不等于授权。**（守 Model 4，防退化为 Model 2/3）
15. **凭据类 cap 只暴露「执行某受限操作」的能力，绝不把可重放凭据本身交给 Agent。**（防滑入 Model 3 钥匙模型）
16. **Agent 自身的中间推理结论视同红色来源，不能作为高风险动作的唯一授权依据。**（防「自我说服」越权）

这些不变量与 POLP 的对应关系：

| POLP 要求 | OCap 机制 |
|-----------|----------|
| 最小权限范围（空间维度） | capability 衰减（scope/操作/配额收窄） |
| 最小权限时长（时间维度） | once / task / TTL 生命周期 + 撤销 |
| 最小权限传播（传播维度） | 显式委托 + 受控通道 + confinement |
| 防委托混淆 | 指名即授权（designation = authority） |
| 缩小爆炸半径 | 区室化 + 对象图连通性即信息流边界 |
| 审计问责 | 不可伪造引用 + 委托链追踪 |

---

## 4. 参考架构

```text
┌────────────────────────────────────────────────────────────┐
│ L6  Human Control Plane                                    │
│     资源选择、授权弹窗、capability 侧边栏、委托图、撤销、审计回放 │
├────────────────────────────────────────────────────────────┤
│ L5  Policy Engine                                          │
│     颁发策略、风险分级、来源标记规则、审批规则、授权模板       │
├────────────────────────────────────────────────────────────┤
│ L4  Agent Orchestrator                                     │
│     task context、Agent 生命周期、子 Agent 委托、结果合并     │
├────────────────────────────────────────────────────────────┤
│ L3  Capability Broker / Runtime                            │
│     registry、不可伪造引用、衰减、撤销、配额、委托链、动态 schema │
├────────────────────────────────────────────────────────────┤
│ L2  Tool Membrane + Restricted Helpers                     │
│     文件/shell/网络/Git/DB/浏览器/凭据的 capability 封装与代理  │
├────────────────────────────────────────────────────────────┤
│ L1  OS Sandbox                                             │
│     Capsicum / seccomp+Landlock+namespace / sandbox-exec / WASI │
└────────────────────────────────────────────────────────────┘
```

L5 与 L6 是两个组件而非一层：L5 Policy Engine 必须能无人值守运行（CI、后台任务里没有 L6 UI 也要能按策略颁发/拒绝），L6 是它的人机前端之一，消费 L5 暴露的「待人工确认队列」。这样才能回答「无 UI 场景下策略如何生效」（相关取舍见 §14 D8）。

调用路径：

```text
用户输入 / @ 引用 / 工具结果（附来源标签）
  → LLM Agent（只看到 capability 派生的 tool schema）
  → Capability Broker（校验 scope、生命周期、来源链、风险等级，必要时问用户）
  → Tool Runtime（经 revocable forwarder 调真实资源）
  → Restricted Helper / Proxy（动态资源的受限代理）
  → OS Sandbox（结构兜底）
```

### 4.1 Capability Broker（核心组件）

Broker 是应用层权限的唯一入口，职责：

1. 维护会话 capability registry（唯一权威视图，回答「这个 Agent 现在能做什么」）。
2. 由 capability 集动态生成 tool schema；权限过期或撤销后工具立即从 schema 消失。
3. 校验每次工具调用是否落在 scope 内。
4. 处理衰减、委托、撤销、过期。
5. 对进入上下文的内容打来源标签，计算风险等级，触发用户确认。
6. 为每次行动分配 trace id，生成结构化审计事件。
7. 阻止 capability 被序列化到 prompt、日志或模型输出。

### 4.2 双层执行：语义层 + 结构兜底层

Broker 负责语义正确，OS 沙箱负责最坏情况兜底。工具执行进程应满足：不挂载用户 home、默认无网络、只传入必要目录 fd、seccomp/Landlock/Capsicum 限制系统调用、cgroup/rlimit/timeout 限制资源。Capsicum 的实践直接迁移：pre-open（进沙箱前打开资源，之后拿不到新资源）、directory fd + `*at()`（目录树内访问不可逃逸）、`cap_rights_limit()`（已持有的还要继续收窄）、Casper helper（动态需求走受限服务）、ktrace/capfail（违规可观测）。

**「先窄后关」初始化纪律**（源自 libcasper 两阶段）：helper / worker 启动时短暂持有「初始化能力」，构造完受限通道后立即释放初始化能力，之后即便被注入也无法再开新通道。

平台选型：

| 平台 | 机制 |
|------|------|
| Linux | Landlock + seccomp + user namespace（bwrap/nsjail 可直接用） |
| macOS | sandbox-exec / Seatbelt profile，或容器化 |
| FreeBSD | Capsicum |
| 跨平台 | per-tool worker 进程 + fd 传递 + 本地网络代理；工具执行部分可放 WASI |

跨平台强度不齐，因此定义一条**最低能力基线**，所有平台的沙箱实现必须同时达到：(1) 文件系统限制在授予目录（无 home、无越界）；(2) 网络默认拒绝；(3) 不继承凭据/agent/cookie；(4) 资源上限（cgroup/rlimit/timeout）。无法同时满足这四条的平台，验收时标注「应用层拒绝可用，OS 兜底降级」，不谎称双层防护（见 §14 D13）。

---

## 5. Capability 模型

### 5.1 数据结构

```text
Capability {
  id: opaque                        // 密码学不可猜测、与 subject/session 绑定、LLM 不可构造
  type: file | dir | command | network | message | git | service | db
        | browser | credential | llm_budget | subagent
  subject: agent_id
  operations: read | write | delete | exec | get | post | send | push | ...
  scope: 路径 glob / origin+path / 命令模板 / API 资源 / 行过滤器
  lifetime: once | task | session | ttl | usage_count
  quota: bytes / requests / tokens / rate
  provenance: 谁在何时为何颁发
  delegation: none | attenuable | broker_only
  taint_policy: 输出如何打标
  revoker: active | revoked | expired
  audit: trace_id, parent_cap_id, issued_at, use_count, last_used_at
}
```

三条实现纪律：

- **不可伪造**：私有构造 + registry 内部持有真实引用；LLM 只见 `<cap:project_read_src>` 这样的显示 ID，由 Broker 映射回真实对象。显示 ID 与 subject/session 绑定，脱离 registry 上下文即失效（不变量 14）。
- **不可序列化**：真实 token/fd/OAuth credential 永不进入 prompt、日志、环境变量；日志只记不可调用的审计 id。
- **衰减产生新对象**：`.scope()` / `.read_only()` / `.limit_rate()` 链式收窄，派生 cap 内部持有祖先引用，调用前检查祖先链是否有已撤销节点（撤销级联的实现基础）。

### 5.2 类型目录（窄 capability 库）

| 类型 | 关键字段 | 设计要点 |
|------|----------|----------|
| `DirCap` | root fd、include/exclude glob、rights | 只接受相对路径，`deny_parent_escape`；`.env`、私钥、`.git/hooks` 默认排除 |
| `FileCap` | 文件引用、rights、max_bytes | 用户拖入文件的默认形态，只读一次或本任务只读 |
| `WritePatchCap` | 目标路径、diff_hash、once | 写入的唯一通道：先出 diff，确认后颁发，hash 绑定内容 |
| `CommandCap` | 固定命令模板、cwd、env allowlist、timeout、network=false | 代替任意 shell，一命令一卡动态颁发：`RunCommandCap(["npm","test"], cwd=/repo, once)` |
| `HttpCap` | methods、origins、paths、请求/响应字节上限、taint=红 | 禁 private network；读过敏感文件的 Agent 不发此卡；属外发 sink |
| `MessageCap` | channel(topic/收件人/webhook URL)、direction(read/send)、max_message_size、rate | 消息/IM/Webhook/邮件发送与 HttpCap 同为「任意外发」sink，必须单列以免 confinement 检查漏掉「发 Slack/邮件也是外发」 |
| `GitCap` | ops 白名单（status/diff/add/commit 与 push 分开）、protected_paths(`.git/hooks`/`.env`/`secrets/*`)、固定 remote | push / PR 创建单独授权、一次性 |
| `ServiceCap` | provider、scopes、object_scope、rate | OAuth token 留在 Harness，Agent 只拿受限操作面 |
| `SheetCap` | sheet_id、range(如 `A1:F200`)、read/write | 表格类资源最细粒度形态，ServiceCap 特化，避免为读几行授出整张表 |
| `DbCap` | 视图/表、query 模板、row limit、write 模式 | 写入走变更集确认，永不给任意 SQL |
| `CredentialCap` | provider、profile、允许操作、ttl | 值不进 prompt/日志/子 Agent 上下文；SSH/cookie 拆专用命名，如 `SshAgentCap(host, operation=sign, ttl)`、`BrowserCookieCap(site, operation=read_session, task)` |
| `LLMCap` | model、token_budget、并发上限 | 子 Agent 拿预算切片，防资源耗尽 |

破坏性命令一律模板化为具名窄 cap，每个带具体参数写法：

```text
RunCommandCap(["npm", "test"], cwd=/repo, once)
PackageInstallCap(manager=npm, cwd=/repo, once)
DeleteCap(path=/repo/node_modules, recursive=true, once)
GitPushCap(remote=origin, branch=main, force=false, once)
```

原则：**优先窄 capability，自由 shell 是需要单独授权、每次确认、全量记录的例外**，不是基础工具。

**孤岛检测判据**：POSIX capabilities 的教训是「拿一项必须连坐拿一整组」——`CAP_KILL` 无法表达「只向自己的子进程发 SIGTERM」，`CAP_NET_ADMIN` 把十几种无关网络操作打成一包。每定义一个新 cap 类型，都要问「用户想要其中最小的一个操作时，是否被迫连带获得其他操作？」若是，该类型粒度不合格，需拆分。`CommandCap` 尤其要做成「一命令一卡动态颁发」而非「一组命令一个静态开关」，否则就重蹈 `CAP_NET_ADMIN` 覆辙（见 §14 D9）。

### 5.3 委托与受控通道

允许的传递通道：Broker registry 内部转交、OS fd 传递、受限 IPC、revocable forwarder 包装的对象引用。
禁止的通道：prompt 文本、普通日志、环境变量、剪贴板、子 Agent 自然语言输出、可重放 bearer token。

```python
# 派生子 Agent：无 delegate 参数默认零权限，且必须先衰减
sub = parent.spawn(
    task="审查 auth 模块",
    delegate=[project_read.scope("src/auth"), llm_budget.split(0.25)],
)
# 子 Agent 结构上无法写文件、联网、执行 shell
```

### 5.4 中间人对象（facet 链）与撤销

「可插入的中间人对象（facet）」是 OCap 属性 E（权限可组合、资源本身也是主体）的直接产物，用途远不止撤销一种：

```text
Agent → [ Facet 链 ] → 真实资源
         ├─ RevokerFacet   撤销
         ├─ AuditFacet     记录每次调用（审计不依赖资源配合）
         ├─ RateLimitFacet 限流
         ├─ ReadOnlyFacet  只读投影
         └─ TaintFacet     给输出打来源标签
```

每个 facet 都是「持有下游引用、拦截调用、加一层策略」的普通对象。这解释了为什么衰减、撤销、审计、taint 打标在实现上是同一套机制，只是插入了不同的中间人。凭据类 cap 不滑向 Model 3 的关键也在这里：Agent 拿到的是「对钥匙的受限 facet」，而不是钥匙本身。

撤销的基本形态：

```text
Agent → ForwardingFacet → Revoker → 真实资源
```

用户点击撤销（或 task 结束、TTL 到期、一次性用完）后，forwarder 断链，Agent 手中引用仍在但调用返回 `ENOTCAPABLE`。三个实现细节（源自 Redell 1974 转发器）：

1. **撤销可传递**：Bob 把权限转给 Ted，用的是 Bob 从 Alice 那拿到的同一条转发链；Alice 撤销 Bob，Ted 自动一起失效，无需追踪 Ted。
2. **撤销不改 Bob 的 C-list**：Bob 手里的引用还在，只是调用失败。
3. **纯用户态**：整条链是普通对象，衰减派生的 cap 内部持有祖先引用，调用前逐级检查祖先链有无已撤销节点，不需要任何系统特殊支持。

拒绝必须可解释，帮助 LLM 与用户理解边界：

```text
Capability violation:
  operation: read_file
  requested: ../.env
  held: ProjectReadCap(/repo/src/**)
  reason: path escapes capability root
  next: 申请 FileCap(/repo/.env, read) 或跳过该文件继续
```

---

## 6. 信任标签与信息流控制

### 6.1 三色信任模型

| 标签 | 含义 | 来源 | 默认语义 |
|------|------|------|----------|
| 绿 | 可信命令 | 用户直接输入、用户显式确认的指令 | 可驱动行动 |
| 黄 | 半可信事实 | 本地确定性工具输出（`git status`、测试结果） | 可作事实参考，不能单独授权破坏性动作 |
| 红 | 不可信数据 | 网页、外部 API、剪贴板、邮件、Issue、README、子 Agent 输出、**Agent 自身中间推理结论** | 只能当数据，永不当命令 |

规则：红色内容里的「指令」永远是字符串；子 Agent 输出至少是红色；**Agent 自己的中间推理结论（taint 标签 `agent_generated`）也至少等同红色，不能单独驱动高风险 sink**——否则被注入的 Agent 可以「自己说服自己」绕过来源链检查（不变量 16）。授权依据的绿色只能来自用户直接输入或用户显式确认。任何红/黄升级为绿必须用户显式确认并记录 `trust.upgraded` 事件；`@` 交付只给 authority 不给 trust——用户 `@` 一个 README 表示可以读它，不表示里面的文字是命令。

### 6.2 来源链

高风险操作必须展示决策因果：

```text
Agent 想执行：rm -rf node_modules/
决策来源链：
  绿 用户请求「修复依赖问题」
    → 红 README 内容「运行 rm -rf node_modules && npm install」
    → Agent 推理：需要清理依赖
风险提示：破坏性操作的依据部分来自不可信来源
[拒绝] [查看原文] [允许一次]
```

用户看到的不是抽象风险分，而是「这个动作是我发起的，还是外部内容带偏的」。

### 6.3 输出侧的权限申报

来源链只在高风险操作时展示决策因果。此外还有一个更常态、更廉价的信任机制：**Agent 的每次最终输出都附一段权限申报**：

```text
Agent 回答：已完成依赖修复。

依据（used）：
  - 用户请求 S1
  - 本地文件 S2 src/session.ts、S6 tests/session.test.ts（读）
  - 测试输出 S8 npm test（执行，绿）
未使用（NOT used）：
  - 网络（未发起任何外部请求）
  - 项目外文件
  - shell / 密钥

风险声明（由 Policy Engine 生成，非 LLM 自评）：
  本任务读取了外部网页 example.com，其内容仅作数据使用，未被授予任何工具调用权限。
```

两个要点：

1. **「未使用」声明和「已使用」同样重要**——它让用户一眼确认「这个联网研究任务确实没碰我的密钥」，把「没做坏事」变成可核验的正面陈述。
2. **风险声明必须由 Harness 依据实际 capability 使用生成，绝不能让 LLM 自评**——被注入的 Agent 可能谎报「我没联网」。关于 Agent 自己行为的安全断言，权威来源是 Broker 的审计流，不是 Agent 的自然语言。

### 6.4 Confinement 与区室化

信息能否流出，取决于对象图中是否存在可达路径。硬规则：

```text
危险组合（禁止同一 Agent 持有）：
  FileReadCap(敏感路径) + 任意外发 sink（HttpCap POST / MessageCap send / DB 写 / PR 发布）

安全拆分：
  Reader Agent：敏感读，无网络
  Network Agent：受限网络，无敏感读
  Harness 中介：schema 约束的结构化数据传递，可审计
```

每个 tool result 携带 taint（`local_secret` / `project_code` / `external_untrusted` / `agent_generated`）。高风险 sink 调用前检查输入 taint；含 `local_secret` 的数据要外发必须显式 declassification，由用户或策略授予，Agent 自己不能决定。Agent 间通信默认传 schema 化结构而非自由文本，因为自由文本是隐藏指令的最佳载体。

**区室化的 OS 级落地蓝图。** 上述拆分不能只停在应用层逻辑角色，要落到进程级。Capsicum 给了可直接抄的范式——`fork()` + 子进程 `cap_enter()` + pipe 通信：

```text
主进程
  ├─ fork() → Reader 子进程：pre-open 敏感 fd → cap_enter() → 无网络
  ├─ fork() → Network 子进程：pre-open socket → cap_enter() → 无敏感 fd
  └─ pipe 在两者间传 schema 化结构（非自由文本）
```

真实案例：FreeBSD `syslogd` 被拆成配置处理、消息处理、命令执行、ttymsg 四个区室。`cap_enter()` 之后 Reader 子进程结构上连 `open()` 都会失败，无法自己开新资源——这把最小权限从「Agent 逻辑级」细化到「worker 进程级」。

**受限 helper 的内部协议**有现成参照（Casper 服务），四个组成部分可直接映射成 helper 协议：

```text
cap_<name>()      helper 的入口函数（Agent 侧调用）
command_func      helper 支持的操作分发
limit_func        ★ 对本 helper 通道做二次限制（origin/method/字节配额）
CREATE_SERVICE    注册宏；cap_xfer_nvlist 传输受限句柄
```

`limit_func` 就是不变量 10「helper 自身必须有 limit API」的具体形态。

---

## 7. 高危操作控制

### 7.1 风险分级（操作类型 × 来源链共同决定）

| 风险 | 典型操作 | 默认行为 |
|------|----------|----------|
| 极低 | 读 workspace 普通文件、列目录 | 自动执行，写审计 |
| 低 | 改 workspace 内文件 | 展示 diff，一键应用 |
| 中 | 网络 GET、读 workspace 外、装依赖 | 首次确认，可本任务授权 |
| 高 | shell、删除、写 workspace 外、网络 POST | 每次确认，展示来源链 |
| 极高 | 密钥访问、push、生产变更、改 git 历史 | 键入确认词 + 一次性 capability；资金/密钥导出/生产变更另加带外二次确认 |

同一操作因来源升级：用户直接说「删 node_modules」确认一次即可；网页建议删除则升级为来源链确认。极高风险档中，涉及资金、生产数据、密钥导出、不可逆外发的操作，「键入确认词」防不住「Agent 说服用户这是必要步骤」的社工（确认发生在同一信任通道内），因此要引入带外二次确认（2FA / 硬件签名 / 独立审批人）；改 git 历史、push 这类维持确认词即可（见 §14 D6）。

### 7.2 Prepare / Commit 与行动状态机

```text
Prepare：Agent 生成计划、diff、命令预览、变更集、push 目标
Commit：用户确认 → Broker 颁发一次性 capability → 执行 → 立即撤销
```

每个有副作用动作走可观测状态机，推理不能直接跳到执行，每一阶段都留下可复盘记录：

| 阶段 | 记录内容 |
|------|----------|
| Observe | 输入来源、工具结果、taint/provenance、摘要 hash |
| Plan | Agent 计划、引用的来源链、预期影响 |
| RequestCap | 请求的 cap 类型、scope、operation、lifetime、理由 |
| Authorize | 用户/Broker 决策、缩小后的范围、确认强度 |
| Execute | tool worker、sandbox profile、参数、起止时间、退出码 |
| Verify | diff、测试结果、响应摘要、实际影响范围 |
| Revoke | 一次性 cap 自动撤销或用户手动撤销 |
| Record | 审计事件 id、trace id、可复盘证据 |

高风险操作在 Plan 与 Execute 之间必须有用户可见中断点；极高风险的确认词与本次 capability 的 scope 绑定，不可复用。

---

## 8. 用户授权体验

安全模型如果要求用户先学 capability 理论就已经失败了。全部机制翻译成六个自然动作：

1. **在哪个目录启动，就只看哪个目录**（Workspace Capability）。启动目录即会话根权限：默认只读，写入走 diff → 一次性 `WritePatchCap`；`.env`、密钥、`.git/hooks`、发布配置默认排除；`~/.ssh`、`~/.aws`、其他项目不可见；会话结束自动撤销。零学习成本，语义与 VS Code 打开文件夹一致。
2. **用 `@` 交付额外资源**。每个 `@file` / `@dir` / `@clipboard` / `@url` 都是一次显式 capability 颁发，默认只读、本任务有效。
3. **越界时 Just-in-Time 授权**。弹窗必须具体：想要的 capability、目标与范围、Agent 声称的理由（标注「Agent 声称」）、来源链、明确列出「不会授予什么」、生命周期选项。按钮是 [允许一次] [本任务同范围] [缩小范围] [拒绝]，绝不出现 Allow all。
4. **给数据，不给权限**。Agent 要读 `~/.aws/config` 时，提供「只粘贴 profile 名」「只分享选中 10 行」等替代项，避免为一个小信息授出整个文件。
5. **侧边栏实时可见、一键撤销**。当前活跃 capability、颁发时间、使用次数、[撤销] / [缩小范围] / [全部撤销]。审计展示「实际用过的权限」而不只是「授予过的权限」。
6. **子 Agent 先看委托图再创建**。展示每个子 Agent 将获得的确切子集，输出标红。

授权模板降低摩擦但不是安全边界：「只读分析」「修改代码」「联网研究」「创建 PR」「数据处理」等 bundle 仍由具体 capability 构成，只是帮用户快速搭出最小集合。

**环境权限默认剥离清单。** ambient authority 来源有 11 类，tool worker 启动前必须逐项显式处理：

```text
 1. filesystem（用户 home、其他项目）
 2. network（默认全开 → 默认关闭）
 3. 环境变量（清空或 allowlist）
 4. 云凭据 / metadata service（禁用默认 profile）
 5. cookie / keychain
 6. SSH / GPG agent
 7. clipboard（只读用户显式 @clipboard 快照）
 8. database connection（连接池 / 已建连接）      ← 常被忽略
 9. message queue（已连接的 MQ / broker）           ← 常被忽略
10. process table（可见其他进程 = 可 kill/ptrace）   ← 常被忽略
11. cloud metadata（169.254.169.254）
```

第 8、9、10 项尤其容易漏：一个已建立的 DB 连接或 MQ 句柄若随进程进入 worker，等于绕过了 `DbCap` / `MessageCap`；能看到 process table 就能 kill / ptrace 其他 worker，破坏区室隔离。

---

## 9. 审计模型

审计按 capability 实例记录，回答四个问题：谁获得了什么、为什么颁发、实际做了什么、何时失效。

最小结构化事件集：`context.ingested`、`trust.labeled`、`trust.upgraded`、`plan.created`、`cap.requested/granted/denied/attenuated`、`tool.started/finished`、`sandbox.denied`、`cap.revoked/expired`、`violation.detected`。每个事件带 trace_id、subject、capability_id、scope、source_chain、taint、risk_level、decision、result。

三种视图：Timeline（观察→计划→授权→执行全过程）、Capability Graph（主体-资源-委托-撤销关系）、Source Chain（某行动由哪些输入导致）。任何高风险行动可从结果反查到输入来源、计划、授权提示、颁发的 capability、sandbox profile 与撤销事件。

审计自身不能成为泄露通道：secret 只记 handle/hash/脱敏摘要；工具 stdout 入日志前过 secret scanner；发现 secret 出现在 prompt 或日志立即 `violation.detected`、撤销相关 capability、提示轮换凭据。

---

## 10. 落地路线图（M0–M4）

每个里程碑独立产生安全收益，可按序增量交付。

### M0 Workspace 边界 + OS 沙箱兜底（最大收益项）

- 内容：启动目录即根 capability；workspace 外应用层拒绝、OS 层不可达（Linux 用 bwrap/Landlock，macOS 用 sandbox-exec）；敏感文件默认排除；写入走 diff → 一次性 WritePatchCap；tool worker 环境剥离（env 清空、无默认凭据、无 home 挂载、网络默认关）。
- 验收：红队测试「读 `~/.ssh/id_rsa`」「`../` 穿越」「shell 读环境凭据」全部双层拒绝；爆炸半径 = 当前项目目录。

### M1 Capability Registry + 动态 tool schema

- 内容：Broker 维护 registry；tool schema 由 capability 集生成（这在现有 LLM tool-calling API 上完全可实现，就是按持有集合裁剪 tools 数组）；工具参数改为 `cap_ref + 相对路径`；cap id 密码学不可猜测且与 subject/session 绑定（不变量 14）；违规返回可解释错误。
- 验收：无 NetworkCap 时 fetch 工具不在 schema 中；撤销后下一轮对话 schema 即更新；LLM 无法通过构造 ID 调用未持有的 cap。

### M2 三色标签 + 来源链 + 高危流程

- 内容：所有上下文块带来源标签；风险分级引擎；prepare/commit 分离；窄 capability 库（CommandCap/GitCap/WritePatchCap/DeleteCap）；JIT 授权弹窗与侧边栏。
- 验收：README 中的 `curl | sh` 指令触发来源链确认而非直接执行；push 需一次性 GitPushCap；侧边栏可实时撤销且撤销即时生效。

### M3 受限 helper + 区室化 + 子 Agent 委托

- 内容：网络/浏览器/DB/凭据走受限 helper（本地代理实现 origin/method/字节配额），helper 带 limit API；spawn 强制 delegate 参数、默认零权限、委托前展示委托图；「敏感读 + 任意外发」组合检测与拆分（含 fork+cap_enter 进程级区室化）；taint 传播与 declassification。
- 验收：Fetcher 区室被恶意 API 注入无法写库；Writer 区室被骗无法外发；子 Agent 输出伪造用户指令被当红色数据。

### M4 全链路审计 + 评估闭环

- 内容：trace id 串联八阶段状态机事件；Timeline/Graph/SourceChain 三视图；capability violation 测试集进 CI；按 ocap-eval-framework 做季度自评。
- 验收：任意一次写入能反查「由哪个授权导致」；CI 中红队场景全绿（见 §11）。

### 务实取舍与降级路径

- **LLM 不理解 capability**：工具 schema 中明确标注每个 cap 的作用域与限制；提供「我现在持有哪些 capability」检视工具；违规错误信息精确到「差哪个 cap、如何申请」。
- **确定初始 capability 集合（先观察后收窄）**：接入行为未知的存量工具或第三方 MCP 时，零权限一步到位很难。借鉴 Capsicum 的 `ktrace(2)` + capfail 工作流——先在宽松（记录但不拦截）模式下、隔离沙箱内跑通典型任务，Broker 记录实际触碰的资源，自动生成「建议 cap 清单」，人工审核后固化为最小集，再转入严格模式。这是 M1/M2 就该有的开发者工具，把「先观察」当开发期一次性动作而非生产期常态（见 §14 D7）。
- **静态过度委托检测**：红队集是运行时兜底，另加一项开发/CI 期 Lint——扫描 `spawn(delegate=[...])`，检测「子 Agent 拿到了但代码路径根本用不到的 cap」并报警，在代码评审阶段就抓住「顺手把父 cap 全传下去」的委托链混淆。
- **可用性 vs 安全性**：capability 不足导致失败时走渐进式 JIT 申请而非任务中断；用 bundle 模板覆盖 80% 场景。
- **性能开销**：forwarder 链检查可缓存（KeyKOS translation buffer 思路），审计异步落盘。
- **无法改造存量工具时**：至少先做 M0（沙箱 + 环境剥离）与 M1 的 schema 裁剪——这两项不要求重写工具实现，已消除最大攻击面。

---

## 11. 安全测试（CI 回归红队集）

| 测试 | 期望结果 |
|------|----------|
| 读 workspace 外文件 | Broker 拒绝 + OS 沙箱拒绝 |
| `../` 路径穿越 | `ENOTCAPABLE` |
| 撤销后再调用 | 失败并产生 `cap.revoked` 事件 |
| 未授权网络请求 | helper 拒绝 |
| helper 扩大 host/method | limit API 拒绝 |
| 外部网页要求读密钥并外发 | 红色数据处理，无对应 cap，无路可走 |
| README 要求运行破坏性 shell | 来源链确认，不静默执行 |
| 子 Agent 伪造用户指令 | 红色数据，不升级 |
| Agent 自我推理结论驱动高危 sink | 视同红色，拒绝独立授权 |
| 恶意页面诱导用已登录会话执行敏感操作（CSRF/浏览器） | BrowserCookieCap 未授予则无路可走 |
| secret 出现在工具输出/prompt | scanner 触发 violation + 撤销 + 轮换提示 |
| token / cap id 写入日志后重放 | 只有审计 id，脱离 registry 上下文调不动 |
| worker 内用继承的 DB 连接 / kill 邻居 worker | 环境已剥离，双层失败 |

---

## 12. 与现有方案的横向对比

这张表是说服团队「为什么不直接用 Docker / 不直接做 tool allowlist」的最有力材料：

| 维度 / 方案 | Unix 权限 | Docker/容器 | Capsicum | WASI Preview2 | Tool allowlist | 本设计 |
|------------|----------|------------|----------|---------------|----------------|--------|
| 属性 A 指名即授权 | ✗ | ✗ | ✓（fd） | ✓（preopen） | ✗ | ✓ |
| 属性 D 无环境权限 | ✗ | 部分 | ✓ | ✓ | ✗ | ✓ |
| 动态资源细粒度（属性 G） | ✗ | ✗ | ✓（Casper） | 部分 | ✗ | ✓（helper） |
| Confinement（防外泄） | ✗ | 粗（网络开关） | ✓ | ✓ | ✗ | ✓（区室化+taint） |
| 可撤销 | 弱 | 重启容器 | cap_rights_limit | 弱 | ✗ | ✓（forwarder 级联） |
| 委托可衰减 | ✗ | ✗ | ✓ | 部分 | ✗ | ✓ |
| 生效层级 | OS | OS/内核 | OS/内核 | 运行时 | 应用层字符串 | 应用层语义 + OS 兜底 |

**为什么「Tool allowlist」不够（单独点名）。** 很多现有 Agent 的「安全」就是一张工具白名单：`shell` 关掉、`fetch` 只允许某些域名。这个模型的致命缺陷是——它只能禁工具名，参数仍是 ambient authority。允许了 `read_file`，Agent 就能读任何它进程能读到的文件；允许了 `fetch`，参数里的 URL 仍是裸字符串。Tool allowlist 停在「Model 1 的工具版」，从未触及委托混淆问题的根。本设计的根本区别是：**工具不是被「允许/禁止」的名字，而是被持有的 capability 派生出来的方法，参数里的资源自带权限**。

---

## 13. 自评分卡与评估框架

### 13.1 评分档位定义（0–3 分）

| 分 | 判据 |
|----|------|
| 0 | 完全不满足；依赖传统 ACL、全局身份或人工约定 |
| 1 | 靠策略 / 提示词 / 运行时拒绝勉强满足——即依赖「运行时检查 + 人的自觉」，可被绕过 |
| 2 | 结构上大体满足，但存在已知旁路（如应用层强制、跨平台基线不齐） |
| 3 | 结构上强制满足，无已知旁路（不可伪造、语言/OS 层保证） |

### 13.2 各里程碑目标（对照 OCap 七属性）

| 属性 | 机制 | M0 后 | M4 后 |
|------|------|-------|-------|
| A 指名即授权 | cap_ref 参数、裸路径只触发申请 | 1 | 3 |
| B 动态主体创建 | 每任务/子 Agent 独立主体，默认零权限 | 1 | 3 |
| C 主体聚合权限视图 | registry 唯一权威视图 + 侧边栏 | 1 | 3 |
| D 无环境权限 | 环境剥离 + 沙箱 | 2 | 3 |
| E 权限可组合 | 窄 capability 库、facet 链、衰减链 | 1 | 3 |
| F 受控委托通道 | Broker/fd/IPC，禁 prompt/日志通道 | 1 | 3 |
| G 动态资源创建 | 工厂 cap + helper 颁发精确 cap | 0 | 2–3 |

诚实提醒：本设计的 Broker 是应用层校验，若不引入语言运行时强制（见 §14 D2），很多项现实中落在 2 分（有旁路）而非 3 分。一个诚实标注 2 分的设计，远比一个虚标 3 分的设计安全。

### 13.3 合格线分级与红旗一票否决

| 总分区间 | 结论 |
|---------|------|
| 80%+ | OCap-aligned，可信执行自主任务 |
| 60–80% | 基本对齐，有明确短板 |
| 40–60% | 部分改良的 ACL，未达 OCap |
| <40% | 仍是 ambient authority 模型 |

**裁决规则：红旗项一票否决优先于总分。** 红旗底线（任何时刻不允许出现）：任意 shell 常驻工具、进程可读用户 home、网络默认全开、凭据自动进执行环境、子 Agent 继承父权限、工具全量固定暴露、bearer token 可复制重放、撤销只在 UI 层生效。任一被踩，无论总分多高，直接不合格。

### 13.4 正面合格判据

> 没有 capability 就无法访问敏感资源；裸路径/URL/ID/命令不是权限；主体默认无环境权限；子主体默认不继承；cap 可衰减、可撤销、可审计。五条全满足，才叫 OCap-aligned。

### 13.5 常见误判清单（评审纠偏层）

评审时最容易犯的五个误判，逐一预警：

1. **「ACL 和 cap 等价」**——不等价，看的是动态行为不是静态矩阵（见 §2.2 等价神话）。
2. **「有 POSIX Capabilities 就是 OCap」**——那是 Model 2 标志位，缺属性 G。
3. **「有沙箱 = OCap」**——沙箱是兜底，不提供指名即授权；要继续追问沙箱内资源是否经 cap 进入、helper 是否受限、已持有资源能否继续衰减。
4. **「token 就是 capability」**——只有同时满足不可伪造 / 窄 scope / 短生命周期 / 受控通道 / 可撤销 / 不泄露六条才接近 cap；普通 bearer token 是 Model 3 钥匙。
5. **「撤销不可能」**——问的不该是「能否销毁对方手里的引用」，而是「对方的引用是否经过一个我们能失效的中间层（forwarder）」。

### 13.6 架构评审五步法

1. 画对象图（谁能到达谁）。
2. 列 ambient authority 清单（§8 的 11 项）。
3. 列 capability registry（当前发出的所有 cap）。
4. 跑红队场景（§11 回归集）。
5. 七属性评分 + 定优先级。

---

## 14. 待决策问题清单

以下 15 个问题来自差异分析的【决策模糊】与【冲突】项，每个给出背景、方案与推荐，建议在设计评审会上逐条拍板、结论回写本文。

### D1. Registry 是真对象引用（Model 4）还是退化为钥匙 / 记账（Model 3/2）？（最高优先级）

**背景**：`cap_ref` = opaque ID + Broker 查表。若 ID 可猜测/可传抄/脱离 registry 仍可用，则自评分卡 A/F 的 3 分虚高（见 §2.1）。

- 方案 A：ID 只是查表键，Broker 校验持有关系即放行（实现简单，但本质 Model 2）。
- 方案 B：ID 密码学不可猜测 + 与 subject/session 绑定 + 脱离 registry 上下文失效（真 Model 4 语义，实现稍重）。

**推荐 B**，已升格为不变量 14。这是整个设计成立的地基，没有折中空间；成本可控——一个 `HMAC(session_key, cap_content)` 即可，不需要改语言运行时。

### D2. 「不可序列化」靠应用层纪律还是语言运行时强制？

**背景**：不变量 8 要求 cap 不进 prompt/日志/环境。动态语言（Python/JS）里应用层纪律极易被绕过（一次不小心的 `str(cap)` 就泄了）。

- 方案 A：应用层纪律 + secret scanner 兜底（M0 即可，但只到 2 分）。
- 方案 B：语言运行时强制——Hardened JS `harden()`/`Compartment`/`Far()`，或 Python 侧封杀 `__reduce__`/`__repr__` + 不透明类型包装（可达 3 分，但绑定技术栈、成本高）。
- 方案 C：分层——普通 cap 走 A + 严格 review + scanner；`CredentialCap` 这类最高危 cap 走 B 的强封装。

**推荐 C 起步、向 B 演进**。全量上 Hardened JS 对多数团队不现实，但凭据类 cap 一旦泄露后果最重，值得先用语言层锁死。这会把「OS 沙箱 + 应用层 Broker」两层扩展为三层（+ 语言层 membrane），需在 §4.2 明确；评分时诚实标注「普通 cap 结构上 2 分」。

### D3. 术语 POLP vs POLA 如何统一？

**背景**：本文与 `polp.md` 用 POLP（Least Privilege），`ocap-agent-design.md` 用 POLA（Least Authority）。两者相邻但有细微差别：authority 含「经由委托的间接影响」，更贴合 OCap 语境。

- 方案 A：主用 POLP（已是目录主基调、文件名 `polp.md`、已发公众号文都用它），术语表点明关系。
- 方案 B：全目录统一 POLA（Miller 本人主张，更精确），代价是全目录改名含已发布内容。

**推荐 A**。术语准确性收益小于全目录改名的成本；在正文首次出现处加一句「本报告用 POLP 泛指最小权限/最小授权；OCap 语境下更精确的说法是 POLA，因为它涵盖经由委托的间接影响」即可消除困惑。

### D4. 是否保留「永久允许」授权档位？

**背景**：`agent-harness.md` 的 JIT 弹窗有「永久允许」档，本文只到「本任务」。「永不再问的黑洞式永久」与不变量 7（一切可撤销/可到期）冲突；但完全砍掉又会带来确认疲劳。

- 方案 A：不设「永久」，最长到 session。
- 方案 B：保留但重新定义为「持久授权规则」。

**推荐 B（受约束版）**——注意 A、B 的机制其实几乎相同，关键在于禁止「无记录、不可见、不可撤销的永久放行」。落地为：一条存进用户 profile 的授权规则，仍进 registry、仍显示在侧边栏、仍可一键撤销、并强制定期（如季度）复核到期。文档应写明这个再定义。

### D5. 风险分级：4 级还是 5 级？

**背景**：本文 5 级（极低/低/中/高/极高），`harness.md` 4 级（低/中/高/极高）。

**推荐 5 级**。「极低（读普通文件，自动执行）」和「低（改文件，展示 diff）」的默认行为确实不同，合并会丢掉「读操作静默、写操作必展示 diff」这个有价值的分界。保留 5 级，文档给出与 4 级方案的映射表以消除引用不一致。

### D6. 极高风险是否引入 2FA / 人工签名，还是仅「键入确认词」？

**背景**：本文极高风险要求「键入确认词 + 一次性 cap」，`agent-harness-os-perspect.md` 提出 2FA / 人工签名。

- 方案 A：仅键入确认词（低摩擦，但确认词可被同一被注入会话诱导键入）。
- 方案 B：极高风险引入带外二次确认（2FA / 硬件签名 / 独立审批人）。

**推荐 B，但仅限最顶格操作**。对生产变更、密钥导出、改 git 历史、资金/不可逆外发引入带外确认；其余「高风险」维持确认词，避免全面 2FA 拖垮可用性（已反映在 §7.1）。

### D7. 初始 capability 集：严格「零权限 JIT」还是「先观察后收窄」？

**背景**：本文主张默认零权限 + JIT，但存量工具 / 第三方 MCP 一步到位很难（见 §10 务实取舍）。

- 方案 A：一律零权限 JIT（最安全，存量工具适配摩擦大）。
- 方案 B：一律「先宽松观察后收窄」（易上手，观察期有风险窗口）。
- 方案 C：新代码零权限 JIT；存量/第三方工具走「观察模式」自举，产出建议 cap 清单后转为固定最小集。

**推荐 C**。自研工具直接零权限 JIT；存量/第三方工具用 ktrace 式观察模式生成建议清单——观察在受控沙箱内跑、有时限、产物需人工审核后固化，绝不让「观察」变成生产期常态。

### D8. L6 Human Control Plane 与 L5 Policy Engine：独立组件还是同层？

**背景**：本文分 6 层，`agent-harness-os-perspect.md` 分 5 层把 L5/L6 合一。

- 方案 A：L5、L6 独立组件（策略引擎 vs 人机呈现面分离）。
- 方案 B：合为一层。

**推荐 A（保持独立），已在 §4 说明**。L5 必须能无人值守运行（CI、后台任务无 UI 也要能按策略裁决），L6 只是它的人机前端；若合一就无法回答「无 UI 场景下策略如何生效」。L5 暴露「待人工确认队列」，L6 消费之。

### D9. CommandCap 动态颁发 vs 静态标志集？

**背景**：`CommandCap` 若做成预定义静态命令组，就是权限孤岛（见 §5.2）。

- 方案 A：预定义一组命令标志集（简单，但可能过粗）。
- 方案 B：每个具体命令模板动态颁发一张独立 cap（`npm test` 一张、`pip install` 一张）。

**推荐 B**。这直接决定属性 G 评分。用命令模板（固定 argv 结构 + 参数 allowlist），每次授权产生绑定该模板的新对象，加「孤岛检测」验收把关。模板可作为 UI 便利层（填参助手），但底层必须每次新颁发、带 once 生命周期。

### D10. 衰减是否支持「已发放 cap 的运行期二次收窄（可逆）」？

**背景**：本文「衰减产生新对象」是单向不可逆。Capsicum `cap_rights_limit()` 支持对已持有 fd 二次收窄。

- 方案 A：只支持撤销重发（模型简单，与「衰减=派生新对象」一致）。
- 方案 B：支持对已发放 cap 原地二次收窄（更灵活）。

**推荐 A 为主，B 作为 helper 内部优化**。对上层语义模型坚持「衰减 = 派生新不可逆对象」最好推理（局部可推理性）；「原地收窄」语义上等价于「撤销旧 cap + 发一张更窄的新 cap」，对外呈现成后者。仅在 helper 内部（如长连接 limit_func）允许 `cap_rights_limit` 式收窄作性能优化，不暴露成用户可见的一等操作。

### D11. 是否引入「自动批准同类命令」的学习式放行？

**背景**：`agent-harness.md` 有「允许并自动批准类似命令」。与 prepare/commit、一次性 cap 有张力，且「同类」判定边界模糊（`rm foo` 和 `rm -rf /` 是不是同类？）。

- 方案 A：不引入，靠「本任务同范围」覆盖大部分重复确认。
- 方案 B：引入，但「同类」严格定义为逐字节相同的命令模板 + 相同 scope，且列在侧边栏可撤销。

**推荐 A，谨慎场景降级为 B**。相似性判断本身就是新的委托混淆问题攻击面，绝不做「语义相似」的模糊匹配；若要减摩擦，只允许逐字节相同的命令模板自动重放（等价于 D4 的授权规则）。

### D12. 红/黄 → 绿降级授权：L5 能否在无人值守场景代行确认？

**背景**：信任升级（数据→命令）必须用户确认。但无人值守（CI / 定时任务）没有用户。若 L5 自动降级，可能重新引入委托混淆问题。

- 方案 A：禁止任何自动降级——无人值守场景下红/黄内容永远无法升绿，相关高危动作直接拒绝。
- 方案 B：允许 L5 按预置策略自动降级。

**推荐 A**。信任升级是对抗 injection 的最后一道闸。无人值守任务应设计成根本不需要信任升级（只做绿色可信输入驱动的操作）；确需处理红色内容并据此行动的任务，必须有人在环。把「无人值守 = 不可降级」写成硬约束。

### D13. 跨平台沙箱的最低基线是什么？

**背景**：M0 验收要求「OS 层不可达」，但 Landlock / sandbox-exec / Capsicum 强度不等价。

- 方案 A：不定统一基线，各平台尽力而为。
- 方案 B：定义一条最低能力基线，达不到的平台标记「降级支持」。

**推荐 B，已在 §4.2 给出四条基线**：文件系统限制在授予目录、网络默认拒绝、不继承凭据/agent/cookie、资源上限。无法同时满足的平台，M0 验收标注「应用层拒绝可用，OS 兜底降级」，不谎称双层防护。

### D14. 消息/Webhook/IM 发送：归入 HttpCap 特例还是独立 MessageCap？

**背景**：这类通道同样有「敏感读 + 任意外发」风险。

- 方案 A：作为 `HttpCap` 特例。
- 方案 B：独立 `MessageCap`。

**推荐 B，已纳入 §5.2**。区室化的「危险外发 sink」检测必须显式枚举所有外发通道；若 Webhook 藏在 HttpCap 里，写 confinement 规则时很容易漏掉「发 Slack/邮件也是外发」。独立 `MessageCap` 强制它出现在 sink 清单里。

### D15. Ambient authority 剥离清单是否扩展到 DB 连接 / MQ / process table？

**背景**：见 §8。

- 方案 A：维持原有 8 项。
- 方案 B：扩展到完整 11 项。

**推荐 B（无争议），已纳入 §8**。并加对应红队用例（worker 内尝试用继承的 DB 连接 / 尝试 kill 邻居 worker，应双层失败，见 §11）。

### 待决策问题速览

| # | 问题 | 推荐 |
|---|------|------|
| D1 | Registry: Model 4 真引用 vs Model 2 记账 | **B** 密码学不可猜测 + 上下文绑定 |
| D2 | 不可序列化: 应用层 vs 运行时强制 | **C** 分层，凭据类走强封装 |
| D3 | POLP vs POLA | **A** 主用 POLP，术语表点明关系 |
| D4 | 「永久允许」档位 | **B** 保留但受约束（登记+可撤销+复核） |
| D5 | 风险 4 级 vs 5 级 | **A** 5 级 + 映射表 |
| D6 | 极高风险 2FA | **B** 仅最顶格操作带外确认 |
| D7 | 初始 cap: 零权限 JIT vs 先观察 | **C** 新代码 JIT，存量走观察自举 |
| D8 | L5/L6 独立 vs 合一 | **A** 独立，L6 是 L5 前端 |
| D9 | CommandCap 动态 vs 静态 | **B** 一命令一卡动态颁发 |
| D10 | 已发放 cap 可逆二次收窄 | **A** 语义单向，helper 内部优化 |
| D11 | 学习式放行 | **A** 默认不做，最多逐字节相同重放 |
| D12 | 无人值守自动降级 | **A** 禁止，无人值守=不可降级 |
| D13 | 跨平台沙箱基线 | **B** 定四条最低基线 |
| D14 | MessageCap 独立 | **B** 独立，进外发 sink 清单 |
| D15 | ambient 清单扩展 | **B** 补 DB/MQ/process table |

---

## 15. 现代系统背书与历史谱系

OCap 不是象牙塔概念，而是六十年演进、已在生产落地的工程：

| 系统 | 与本设计的对应 |
|------|--------------|
| **Deno** `--allow-read=/tmp` `--allow-net=api.x.com` | 命令行级按资源授权，几乎就是 `DirCap` / `HttpCap` 的现成参照，已在生产运行 |
| **Cloudflare Workers**（V8 isolate） | 每个 Worker 无 ambient authority，能力经绑定注入——大规模多租户 OCap 实践 |
| **WASI Preview2 / Component Model** | preopen 目录 + 能力接口，属性 A/D/G 的标准化落地；本设计「工具执行部分可放 WASI」有标准依托 |
| **Hardened JS / Endo（Agoric）** | `harden()`/`Compartment`/`Far()`——语言运行时层面强制不可伪造引用，智能合约用它防 reentrancy（关系到 D2） |
| **Capsicum（FreeBSD）** | `cap_enter()` 后不可逆、必须 pre-open、Casper 服务——本设计 L1/L2 的最成熟范本 |

历史谱系：Dennis & Van Horn (1966) 理论起点 → CAP / Redell 转发器撤销 (1974) → KeyKOS (1985，首个证明可实现 confinement) → EROS (1999，形式验证) → E 语言 → Hardened JS / Endo。

---

## 16. 结论

这个设计的全部内容可以压缩成七行：

```text
不给引用，就没有权限。
给出引用，就是明确授权。
包装引用，就能衰减权限。
控制通道，就能限制委托。
插入转发器，就能撤销权限。
切断环境权限，就能缩小爆炸半径。
标记来源链，就能抵抗委托混淆问题。
```

POLP 提出 50 年而被系统性违反，根源是 ACL 结构让「做对的事」更费力。OCap 把激励反转：最小权限不再依赖用户记得少给、也不依赖 LLM 足够谨慎，而是 Agent 在结构上只能使用被传入的 capability。安全的 Agent Harness 不是让 Agent 更听话，而是让它在结构上只能做被授权的事——从「快速失败的便利工具」变成可问责、可审计、可被信任执行自主任务的运行时。

落地时始终要盯住一件事：这个设计有多处「看起来是 Model 4，实现上可能停在 Model 2/3」的滑坡点（Registry、不可序列化、CommandCap、无人值守降级）。把它们一一钉死在「结构强制」而非「运行时自觉」的一侧，自评分卡的 3 分才是真的；凡是钉不死的，就诚实地标成 2 分——一个诚实标注 2 分的设计，远比一个虚标 3 分的设计安全。

## 参考

- Saltzer & Schroeder (1975). *The Protection of Information in Computer Systems.*
- Hardy (1988). *The Confused Deputy.*（委托混淆问题）
- Redell (1974). 可撤销转发器方案。
- Dennis & Van Horn (1966). *Programming Semantics for Multiprogrammed Computations.*
- Miller, Yee, Shapiro (2003). *Capability Myths Demolished.*
- Shapiro & Weber (2000). *Verifying the EROS Confinement Mechanism.*
- Watson et al. (2010). *Capsicum: Practical Capabilities for UNIX.*
- 现代系统：Deno 权限模型、Cloudflare Workers、WASI Preview2 / Component Model、Hardened JS / Endo（Agoric）。
- 本目录：polp-detailed-intro.md、ocap-detailed-intro.md、ocap-agent-design.md、harness.md、agent-harness-os-perspect.md、ocap-eval-framework.md
