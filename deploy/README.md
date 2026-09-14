# Capable 部署

把 Capable 的 Rust Broker 与 capsh 解释器构建为可运行产物,并以后台服务方式起两个
listener(control / guest),供 capsh 或不可信客户端连接。

> 状态:pre-alpha。能力语义骨架 + 已加固的 Broker(Phase A / B1 HttpCap 通过 newton 复审)。
> **CommandCap 的 exec 已有 C1 L1 沙箱**(Landlock 限 fs 到 cwd + 系统只读、seccomp 网络/io_uring/
> 跨进程 default-deny、close_range(CLOEXEC) 关继承 fd、可配 uid/gid/rlimit,任一步失败即拒执行)。
> **但文件/目录读列操作仍以 Broker 本进程身份执行**(靠 openat2 fd-身份 + 能力语义 + 审计约束),
> 尚无 capvm 硬件/OS 隔离基座。多租户/强不可信场景:guest Broker 必须以专用 uid 运行(见下)。

## 构建

```sh
deploy/build.sh
# -> target/release/capable-rpc, capsh/_build/capsh
```

## 运行(两个 listener)

```sh
deploy/run-broker.sh
# control: .run/control.sock  (0600,仅属主;可信编排/capsh,可 mint)
# guest:   .run/guest.sock    (0660;不可信客户端,无 mint,workspace 受限)
# 审计:    .run/control-audit.log / .run/guest-audit.log(各自独立全局链)
```

环境变量:`CAPABLE_RUN_DIR`(默认 `.run`)、`CAPABLE_WORKSPACE`(guest 授权域根)。

## 连接

capsh 作为**可信本地编排器**连 control 面:

```sh
CAPSH_BROKER=.run/control.sock capsh/_build/capsh prog.capsh
```

不可信客户端连 guest 面(无 mint;`BOOTSTRAP` 取注入的 workspace 根后 `DERIVE`/`INVOKE`)。

## L5 策略 + JIT consent(能力使用点的人类实时授权)

`serve` 支持策略 flag,对高风险动作要求 JIT consent 或直接拒绝:

```sh
capable-rpc serve .run/control.sock --trusted --prompt-exec --audit-log .run/control-audit.log
# 也可 --prompt-http / --prompt-post / --deny-exec
```

流程(单 socket,同进程内所有连接共享一个 consent 账本):

1. 请求方(capsh/编排器)`INVOKE <cmd> exec` → 服务端回 `CONSENT\t<id>\t<摘要>`(动作挂起,未执行)。
2. **审批者**(人类,连到**同一控制面 socket** 的另一连接)`CONSENT_APPROVE <id>`(或 `CONSENT_DENY <id>`)。
3. 请求方重放该动作 → 已批准则放行执行(**一次性**,再次需重新批准);被拒则 `ERR`。

审批仅 control 面可做(guest 不能自批)。JIT 决策全部入审计链。

> 说明:consent 账本是**进程内**共享 —— 审批者只需连到**同一 Broker 进程**(自然模型:capsh 与
> 人类审批者都连控制面 socket)。若要让 control 面审批**另一进程**的 guest 面请求,需单进程双面或
> 后续 consent 总线(当前 run-broker.sh 的 control/guest 是两进程)。

## 停止

```sh
deploy/stop-broker.sh
```

## 审计校验

```sh
# 用 verify_persisted(通过一个小工具或 cargo test)校验持久链完整性 + 尾截检测
# 日志格式:seq \t session \t op \t detail \t decision \t prev \t hash;anchor:<count>\t<head>
```

## systemd(可选)

- `capable-broker.service` —— control 面(可信编排)模板,`User=capable`,socket 0600。
- `capable-guest.service` —— guest 面(不可信)模板,**`User=capable-guest` 必须 != control 面 uid**。
  这是 CommandCap exec 子进程与控制面之间的进程隔离边界:L1 沙箱内 seccomp 已禁
  ptrace/pidfd/process_vm_* 作纵深防御,但真正的进程隔离保证来自"guest 与 control 不同 uid"。

改路径与 uid 后 `systemctl daemon-reload && systemctl enable --now capable-broker capable-guest`。

## 信任模型速记

- **control socket = 可信面**:能 mint 任意能力(DirCap/CommandCap/HttpCap…)。仅属主(0600)。
  capsh 求值器属 TCB,连这里。
- **guest socket = 不可信面**:无任何 mint verb;初始 authority 由服务端注入 + 一次性
  BOOTSTRAP;只能 DERIVE + INVOKE read/list。跨权限隔离靠 uid + socket 权限。
- DirCap 边界:openat2(RESOLVE_BENEATH)+ Cap 持稳定目录 fd(防路径/根替换 TOCTOU)。
- CommandCap exec 的 C1 L1 沙箱(在 fork 后子进程 pre_exec,任一步失败即拒执行):
  no_new_privs → rlimits → Landlock(cwd 读写执行 + /usr /bin /lib* 只读执行,其余不可达)→
  fchdir(held cwd fd)→ close_range(CLOEXEC,继承 fd 在 execve 时关)→ seccomp default-deny
  (网络 socket/connect/…、io_uring_setup/enter/register、ptrace/pidfd_*/process_vm_*/kcmp)→
  可配 setgroups/setgid/setuid。**同 uid 下进程隔离靠 seccomp 纵深防御;强隔离需专用 guest uid。**
- 审计:durable(fsync + 原子 anchor)+ fail-closed 恢复。
- HttpCap:SSRF/metadata/private 恒拒、DNS 解析一次连预解析 IP、request-target 注入防护。
