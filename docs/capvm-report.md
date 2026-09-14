# CapVM 报告

> Capable 的 L1–L2 执行运行时。定位:一个 **Object-Capability(Model 4)原生**的代码执行内核语义层。
> 状态:cap-indexed syscall ABI + C-list 运行时**已实现并单测**(`crates/capable-broker/src/capvm.rs`,
> commit f311bfa);内嵌进 secure-exec V8-isolate 内核为后续深集成里程碑。
> 依据:DESIGN §3、`docs/syscall-abi.md`、评估框架 `design/ocap-security-model-evaluation-framework.md`。

---

## 1. 一句话定位

CapVM 把 guest 代码(工具 / 命令 / 子任务)访问外部世界的方式,从**字符串指名 + 权限策略**
（`open("/path")` → 内核查 fs 策略）改成**能力句柄索引**（`cap_read(h, rel)`）。
**不存在 ambient authority 接口**：没有句柄就没有任何权限；指名即授权。

这正是评估框架里 **Model 4** 与 Model 1.5–2 的分界。

## 2. 为什么需要它（问题）

深扫结论（DESIGN §0.3）：agentos 建立在 secure-exec（Rust V8-isolate kernel + sidecar）之上,
隔离基座优秀,但权限模型是**对 6 个命名 scope(fs/network/childProcess/process/env/binding)的
deny-by-default 策略**,syscall 参数仍是**路径 / host 字符串**。这有两个结构性弱点:

1. **Ambient authority 残留**:进程能凭空写出一个路径 / URL 去"试",权限判定发生在调用时的策略查表,
   而非"你是否持有对该资源的引用"。
2. **指名与授权分离**:字符串是可枚举、可猜测、可拼接的全局命名空间;策略是一层旁挂的 allowlist,
   存在双重记账 / 绕过面(路径规范化差异、TOCTOU、scope 粒度过粗)。

Model 4 的答案:**指名即授权**。你能命名一个资源,当且仅当你持有指向它的不可伪造能力。

## 3. 内核语义:cap-indexed ABI

对照(DESIGN §3):

```
传统(agentos / secure-exec 现状,Model 1.5–2)
  open("/repo/src/main.ts", O_RDONLY)   // 路径字符串 → 内核查 fs 权限策略
  fetch("https://api.x/v1/models")       // URL 字符串  → 内核查 network allowlist

CapVM(Model 4:cap-indexed,指名即授权)
  cap_read(h, "main.ts")                 // h = 本进程 C-list 句柄 → Broker 真实能力
```

### C-list(capability list)

每个 CapVM 进程持有自己的能力表,仿 Unix fd 表,但强化为不可伪造:

| 属性 | 说明 |
|---|---|
| **不可伪造** | guest 只见 `usize` 句柄;能力真实引用只活在 Broker,句柄写不出 CapRef |
| **不可跨进程凭空构造** | 句柄**每进程**;进程 A 的句柄 3 与进程 B 的句柄 3 无关,别的进程不能凭相同下标借用 |
| **零权限起步** | 新进程 C-list 为空 → 任何 `cap_*` 都拒(无 ambient authority) |
| **装入仅 loader/Broker 侧** | guest 侧只有 use / derive / close,拿不到"凭空造能力"的入口 |

### syscall 表(全部按句柄指名)

| syscall | 语义 | 底层(Broker / L2) |
|---|---|---|
| `install(cap) -> h` | **loader 侧**:把 Broker 能力装入 C-list,返回句柄 | Broker registry |
| `cap_read(h, rel)` | 经 DirCap 句柄读 rel | openat2 `RESOLVE_BENEATH` + 持有 fd anchor |
| `cap_list(h, rel)` | 列目录 | getdents64(fd anchor) |
| `cap_exec(h)` | 执行 CommandCap 句柄 | C1 L1 沙箱(Landlock + seccomp)+ L5 gate |
| `cap_derive_sub(h, seg) -> h'` | 从句柄派生**衰减**子能力,装入新句柄 | Broker derive_sub(parent 链) |
| `cap_close(h)` | 收回本进程对该句柄的访问 | 句柄级;能力级撤销走 Broker revoke |

## 4. 不变量与测试证据

`crates/capable-broker/src/capvm.rs` 的 4 条回归,把 Model 4 关键性质钉死:

| 不变量 | 测试 | 断言 |
|---|---|---|
| **无 ambient authority** | `fresh_process_has_zero_authority` | 空 C-list 下任何句柄读都拒 |
| **句柄不可伪造 + Broker 边界** | `cap_indexed_read_and_bounds_and_forge` | 未 install 的下标无授权;经句柄读仍受 DirCap 边界约束(绝对 / `..` 拒) |
| **衰减 + 句柄收回** | `cap_derive_attenuates_and_close_revokes_handle` | 派生子句柄限定子目录、taint 服务端判定;`cap_close` 后句柄失效,父句柄不受影响 |
| **句柄每进程** | `handles_are_per_process_not_global` | 别的进程不能凭相同下标借用能力 |

全量:39 broker + 5 proto + 红队 + consent + capsh 测试全绿(`ci.sh`)。

> **host / guest 类型边界(newton 复审 e6b08520 / 446936be,已落地)**:guest 拿到的面**必须不含
> Session/CapRef/install** —— 否则 guest 可 `sess.grant_dir(...)` 凭空铸能力。落地为:
> - `GuestProcess` = **host 侧门面**,内部持 C-list + `&mut Session`;host/loader 用它 `install`。
> - `Syscalls` = **交给 guest 的面**(`&mut dyn Syscalls`),方法**不接收 Session**,只按已装入句柄
>   操作 —— 无 `install`、无法取得 `CapRef`、无法 `grant_*`/derive 出裸引用。把它交给 guest 代码即在
>   **类型层面**把 guest 关进"只能用 loader 给的句柄集"(测试 `guest_surface_has_no_session_no_mint_no_install`
>   的 `guest_code(sys: &mut dyn Syscalls, ...)` 签名根本没有 Session)。
>
> 因此 per-process 不可伪造对 **guest 面**由 Rust 类型系统强制;host/loader(持 Session)负责装入,是设计内
> 的职责分离。内嵌 V8 后 guest JS 经此 ABI、永不持 Rust 引用 —— 当前纯 Rust 切片把 `&mut dyn Syscalls`
> 交给 guest 即等价边界。此外,JIT consent 的 exec 审批 summary 现显示**规范化+转义+限长**的 argv/cwd,
> 供人类核对具体命令(不再是 opaque cap id)。

## 5. 与 secure-exec 的关系(复用 vs 替换)

CapVM **复用** secure-exec / Broker 的机制作为 L2 底层,**替换**其权限语义:

- 复用:**kernel 全中介 + `openat2 RESOLVE_BENEATH`** —— 正是 `cap_read` / `cap_list` 的落地(DirCap
  的 root fd + 相对路径);**C1 L1 沙箱**(Landlock fs 限制 + seccomp 网络/io_uring/跨进程 default-deny
  + fd 泄漏封堵)—— 正是 `cap_exec` 的落地;**L5 策略 + JIT consent** —— `cap_exec` 前的治理闸。
- 替换:syscall 入口从"路径 / host 字符串参数 + scope 策略"改为"**cap 句柄索引**",让 cap-indexed
  成为内核**原生 ABI**,而非旁挂一层翻译 shim(避免双重记账 / 绕过面)。

映射 Capsicum 范式:CapVM 里"进程零权限起步 + loader 只装入对应句柄"等价于 `cap_enter()` 之后
连 `open()` 都失败 —— 把最小权限从"Agent 逻辑级"细化到"isolate 进程级"。

## 6. 现状与 roadmap(诚实标注)

**已实现(f311bfa):** cap-indexed ABI + C-list 运行时,复用 Broker 作为真实资源中介;单测覆盖上述不变量。

**后续深集成(未实现,已在文档标注,非虚报):**
1. **内嵌 secure-exec V8-isolate 内核**:把 CapVM 的句柄化 syscall 入口替换 secure-exec 的字符串
   syscall,让 guest JS/工具代码在真实 isolate 内以 cap-indexed ABI 运行。需 fork / 深改 secure-exec
   并与上游分叉(DESIGN §3 D-capvm 已标为高工作量里程碑)。
2. **isolate 拆分级最小权限**:一命令一 isolate,Broker 只发对应 cap 集(cap_enter 语义落到进程级)。
3. 与 capsh 的类型化 IPC/FFI 边界(capsh 侧 abstract type = 语言级不可伪造引用)对接句柄。

**取舍说明**:先把内核语义做实并单测(确保 cap-indexed ABI 语义正确、不变量成立),再谈嵌入 V8;
这样嵌入时是"把已验证的语义接上真实执行基座",而不是边设计边改一个大内核。

## 7. 结论

CapVM 已把 Capable 的核心命题 —— **Model 4 指名即授权、无 ambient authority** —— 在内核 ABI 层做实并
单测:零权限进程、不可伪造 / 每进程句柄、经句柄的读/列/执行/衰减/收回,全部复用 Broker 的 openat2 +
C1 沙箱 + L5 治理作为底层。剩下的是把这套已验证语义**嵌入 secure-exec 的 V8 执行基座**,属最大且需
fork 的后续里程碑。
