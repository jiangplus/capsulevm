# capvm — cap-indexed syscall ABI

capvm 的内核 ABI 把资源**指名方式从字符串改为能力句柄索引**(cap handle)。这是 Model 4
的地基:**指名即授权,无句柄即无权**;不存在 `open(路径字符串)` 这类 ambient authority 接口。

对照(DESIGN §3):

```
传统(agentos / secure-exec 现状,Model 1.5–2:字符串指名 + scope 策略)
  open("/repo/src/main.ts", O_RDONLY)    // 路径字符串 → 内核查 fs 权限策略
  fetch("https://api.x/v1/models")        // URL 字符串 → 内核查 network allowlist

capvm(Model 4:cap-indexed,指名即授权)
  cap_read(h, "main.ts")                  // h = 本进程 C-list 句柄 → Broker 真实能力
```

## C-list(capability list)

每个 capvm 进程持有自己的能力表,仿 Unix fd 表,但:

- **不可伪造**:guest 只见 `usize` 句柄;能力真实引用只活在 Broker,句柄写不出 CapRef。
- **不可跨进程凭空构造**:句柄是**每进程**的。进程 A 的句柄 3 与进程 B 的句柄 3 无关;
  别的进程不能凭相同下标借用你的能力(见 `handles_are_per_process_not_global`)。
- **零权限起步**:新进程 C-list 为空 → 任何 `cap_*` 都拒(无 ambient authority)。
- **装入(install)仅 loader/Broker 侧**:guest 侧只有 use/derive/close,拿不到"凭空造能力"的入口。

## syscalls(全部按句柄指名)

| syscall | 语义 | 底层(Broker/L2) |
|---|---|---|
| `install(cap) -> h` | **loader 侧**:把 Broker 能力装入 C-list,返回句柄 | Broker registry |
| `cap_read(h, rel) -> (taint, bytes)` | 经 DirCap 句柄读 rel | openat2 RESOLVE_BENEATH + 持有 fd anchor |
| `cap_list(h, rel) -> names` | 列目录 | getdents64(fd anchor) |
| `cap_exec(h) -> stdout` | 执行 CommandCap 句柄 | C1 L1 沙箱(Landlock+seccomp)+ L5 gate |
| `cap_derive_sub(h, seg) -> h'` | 从句柄派生**衰减**子能力,装入新句柄 | Broker derive_sub(parent 链) |
| `cap_close(h)` | 收回本进程对该句柄的访问(C-list 置空) | 句柄级;能力级撤销用 Broker revoke |

## 不变量(单测覆盖,`capvm.rs`)

- **无 ambient authority**:`fresh_process_has_zero_authority` —— 空 C-list 下任何句柄都拒。
- **句柄不可伪造 + Broker 边界**:`cap_indexed_read_and_bounds_and_forge` —— 未 install 的下标无授权;
  经句柄读仍受 DirCap 边界约束(绝对/`..` 拒)。
- **衰减 + 句柄收回**:`cap_derive_attenuates_and_close_revokes_handle` —— 派生子句柄限定子目录、
  taint 服务端判定;`cap_close` 后句柄失效,父句柄不受影响。
- **句柄每进程**:`handles_are_per_process_not_global` —— 别的进程不能凭相同下标借用能力。

## 现状与深集成(诚实标注)

本模块是 **cap-indexed ABI + C-list 运行时**,复用 Broker 作为 L2/L3 真实资源中介
(DirCap 的 root fd + openat2 正是 `cap_read`/`cap_list` 的落地)。把它**内嵌进 secure-exec 的
V8-isolate 内核**、替换其字符串 syscall 入口,是更深的集成(需 fork/深改 secure-exec,DESIGN §3
D-capvm),属后续里程碑;此处先把内核语义做实并单测,确保 ABI 语义正确后再谈嵌入。
