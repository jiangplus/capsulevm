# capsh 与 capvm 的关系及结合方式

> 本文说明 capsh(语言前端)、capable-broker(L3 能力 Broker)、capvm(L1–L2 执行内核)三者的
> 职责边界、结合点,以及**当前实际接线状态**(与设计意图的差距)。
> 依据:[DESIGN.md](../DESIGN.md) §2/§3/§11.5、[capvm-report.md](capvm-report.md)、
> [syscall-abi.md](syscall-abi.md)、[capsh-language.md](capsh-language.md) §13。
> 状态:capsh↔Broker 与 capvm↔Broker 已实现;**capsh↔capvm 尚未接线**,capvm↔V8 未做(见 §4)。

---

## 0. 一句话

**capsh 是语言前端,capvm 是执行内核,两者不直接对话 —— 中间隔着 Broker,能力的真身只活在 Broker 里。**

```text
capsh (OCaml)                    ← 语言层:人/Agent 写的程序
   │  CapTP-lite over Unix socket(CAPSH_BROKER=<sock>)
   ▼
capable-broker (Rust)            ← L3:唯一持有真实能力的地方
   │  同 crate 内函数调用
   ▼
capvm (crates/capable-broker/src/capvm.rs)   ← L1–L2:cap-indexed syscall + C-list
   │
   ▼
openat2 RESOLVE_BENEATH / Landlock / seccomp ← 真实资源
```

---

## 1. 三者分工

| | capsh | Broker | capvm |
|---|---|---|---|
| **是什么** | 语言 + 求值器 | 能力注册表 | 进程内核 ABI |
| **谁用它** | 人类 / 可信编排器 | 谁都不直接用 | 不可信 guest 代码 |
| **能力长什么样** | OCaml abstract type `Cap.t` | 真身(持 `dir_fd`、parent 链、taint) | `usize` 句柄 |
| **不可伪造靠什么** | **编译期**类型系统 | 会话绑定不可猜 token | **进程级** C-list 下标 |
| **能否铸新能力** | 能(`grant`,触发 consent) | 能(control 面 mint) | **不能**(仅 loader 可 `install`) |
| **实现位置** | `capsh/src/` | `crates/capable-broker/src/lib.rs` | `crates/capable-broker/src/capvm.rs` |

### 1.1 三处不可伪造机制互补

这是本架构值得强调的一点:**三层各有各的「不可伪造」,互不依赖**。

1. **capsh 层**:`Cap.t` 在 `cap.mli` 里是 abstract type,签名外无法构造/匹配/序列化 ——
   `forge_fail.ml` **编译失败**即是证明(`make -C capsh forge-check`)。
2. **Broker 层**:cap 引用是不可猜测、会话绑定的 token,换连接/换会话即失效,不是可复制重放的 bearer。
3. **capvm 层**:guest 只见 `usize`,句柄每进程,写不出 `CapRef`。

任何一层被击穿,另外两层仍在。这与「单点强制」的设计相比是纵深。

---

## 2. 设计上的结合点:capsh 构造 → capvm syscall

来自 [capsh-language.md](capsh-language.md) §13:

| capsh 写法 | 落到 capvm |
|---|---|
| `grant dir "." {read}` | Broker powerbox → consent → 装入进程 cap_table |
| `repo.read(path\`x.ml\`)` | `cap_read(h, "x.ml")` |
| `repo.sub("src").readonly()` | `cap_derive(h, attenuation) -> h'` |
| `run(cmd)` | `cap_exec(h)` |
| `out.send(data)` | `cap_send(h, message)` |
| `spawn "x" with {…}` | 新 subject + `cap_delegate`(先衰减后委托) |
| `confine "x" with {…}` | **独立 isolate**,Broker 只发对应 cap 集 |
| `prepare … / commit` | `cap_prepare_write` → 一次性 WritePatchCap → `cap_commit` |

最后两行是结合的最深处:**语言里的一个块,对应 VM 里一个零权限进程**。`confine` 的设计意图不是
语言层的作用域检查,而是落到真正的 isolate 进程边界上(Capsicum `cap_enter()` 语义)。

---

## 3. 为什么 Broker 要夹在中间

多一层看似冗余,但它承担三件 capsh 与 capvm 都做不到的事:

1. **两侧的不可伪造机制互不兼容**。OCaml abstract type 出不了进程;`usize` 句柄出不了进程。
   跨进程传递能力必须有第三方持有真身,并向两侧发放**两种不同形态**的引用。
2. **跨语言 / 跨机器**。capsh 是 OCaml、capvm 是 Rust。DESIGN §11.5.2 明确否决裸 FFI
   (OCaml GC 与 Rust 耦合易碎,且给不了跨进程/跨机器能力传递),选 CapTP-lite over socket ——
   顺带拿到进程隔离:**capsh 崩了不拖垮 Broker/TCB**。
3. **审计与撤销需要全局视角**。parent 链级联撤销、跨会话 hash-chain 审计、L5 consent 账本,
   只能在唯一持有全部能力的地方做。

---

## 4. 当前接线状态(诚实标注)

§0 的分层图是**设计意图**,不是运行时事实。四条连接线,目前通两条:

| # | 连接 | 状态 | 证据 |
|---|---|---|---|
| 1 | capsh ↔ Broker | ✅ **已通** | `CAPSH_BROKER=<sock>` 切 `Backend_rpc`;`make -C capsh run-capsh-remote` 实跑 |
| 2 | capvm ↔ Broker | ✅ **已通** | `GuestProcess` 持 `&mut Session`;`cap_read` 底下复用 openat2 + C1 沙箱 + L5 gate;4 条不变量单测 |
| 3 | capsh ↔ capvm | ❌ **未接线** | `capable-rpc` 的 proto **无任何 capvm 动词**;capsh 不知道 capvm 存在 |
| 4 | capvm ↔ V8 isolate | ❌ **未做** | 需 fork/深改 secure-exec(DESIGN §3 D-capvm,高工作量里程碑) |

**关于 #3**:capsh 目前走 `GRANT_DIR` / `DERIVE` / `INVOKE` 这套**直接对 Broker** 的 CapTP-lite 协议,
绕过了 capvm。也就是说 capvm 现在是一个**语义已验证但未接线的模块** —— 它的 4 条不变量
(零权限起步 / 句柄不可伪造 / 衰减+收回 / 句柄每进程)都由单测钉死,但没有任何生产路径经过它。

**取舍说明**(与 capvm-report §6 一致):先把内核语义做实并单测,再谈接线与嵌入 V8;这样嵌入时是
「把已验证的语义接上真实执行基座」,而不是边设计边改一个大内核。

---

## 5. capvm 的 host/guest 类型边界

newton 复审(e6b08520 / 446936be)逼出的关键设计,是三层结合能成立的前提:

```rust
GuestProcess  // host 侧门面:内部持 CList + &mut Session;loader 用它 install
Syscalls      // 交给 guest 的 trait:方法不接收 Session,无 install、拿不到 CapRef
```

交给 guest 代码的是 `&mut dyn Syscalls` 而**不是** `&mut Session` —— 于是「guest 只见 usize」
从注释变成 **Rust 类型系统强制**:测试 `guest_surface_has_no_session_no_mint_no_install` 里的
`guest_code(sys: &mut dyn Syscalls, ...)` 签名根本没有 `Session` 可用,无法 `grant_*` 凭空铸能力。

**诚实边界**:per-process 不可伪造对 **guest 面**由类型系统强制;host/loader(持 Session)负责装入,
是设计内的职责分离,不是漏洞。真正的强制要等内嵌 V8 —— 那时 guest JS 永不持 Rust 引用,只经此 ABI。

---

## 6. 与 Capsicum 的对照

capvm 的语义等价于 FreeBSD 的 **`cap_enter()`**:进入之后连 `open()` 都失败,只能用已持有的 fd。

区别在粒度目标:Capsicum 是「进程级最小权限」;capvm 想做到 **「一命令一 isolate」** ——
每条命令一个零权限进程,Broker 只发这条命令需要的那几个句柄(capvm-report §6 roadmap 第 2 项)。

---

## 7. 后续里程碑

1. **接线 #3(capsh ↔ capvm)**:在 CapTP-lite proto 里加 capvm 动词,让 capsh 的
   `spawn`/`confine` 真正落到 `GuestProcess` 的独立 C-list,而非仅语言层作用域检查。
2. **接线 #4(嵌入 secure-exec V8 内核)**:用 capvm 的句柄化 syscall 入口替换 secure-exec 的
   字符串 syscall 入口。需 fork 并与上游分叉,DESIGN §3 已标为高工作量里程碑。
3. **isolate 拆分级最小权限**:一命令一 isolate,把 `cap_enter` 语义落到进程级。
4. **补齐 syscall 表**:`cap_prepare_write` / `cap_commit` / `cap_connect` / `cap_send` /
   `cap_delegate` / `cap_revoke` / `cap_request` 目前只在 DESIGN §3.2 有 ABI 定义,
   `capvm.rs` 实现的是 `cap_read`/`cap_list`/`cap_exec`/`cap_derive_sub`/`cap_close` 五条。

> 若前端改用 capfish(见 [capfish.md](capfish.md) / [capsh-on-fish-eval.md](capsh-on-fish-eval.md)),
> 本文的三层关系**完全不变** —— 换的只是 §0 图里最上面那一层,Broker 与 capvm 一行不改。
