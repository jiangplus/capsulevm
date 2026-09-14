# Changelog

本文件记录 Capable 的开发变更。大的变更同时进行 git commit。

格式参考 [Keep a Changelog](https://keepachangelog.com/)；日期用 YYYY-MM-DD。

## [Unreleased]

### Added
- 2026-09-14 — **E1:mitigation-coupled egress(Broker 不变量)**。`Session::set_mitigation_reduced(true)` 立即级联撤销本会话全部 http/message 能力,且此后 `grant_http` 在 L5 之前无条件拒绝(不可配置放行);恢复为控制面动作,决策全部入审计链。对应 Apart AI Incident Response Sprint 报告 §3.5 E1(事故 F4:拒答分类器关闭而网络姿态未收紧)。回归 `reduced_subject_cannot_hold_egress`。诚实标注:`grant_message` 返回非 Result,降级期间的 mint 门禁尚未加(已持有的 message cap 会被撤销);wire 层 verb 待接。
- 2026-07-16 — **L5 consent 机密分离修(newton a2d306ff):requester/approver 视图分离 + 限长渲染**。
  - **跨面机密泄露 → 关**:此前 exec 的 approval summary(含 **env**,CommandCap 的 env 常含 API token/凭据)被 `gate` 原样放进 `__CONSENT__` 帧回给**触发动作的 requester**(可能不可信)——只需触发一次 Prompt(未获批、未执行)即可读走整份 env。修:`gate` 拆 **hint(给 requester,非敏感:只 verb + cap 短 id)** 与 **detail(含 argv/env/cwd,只入 ledger)**;完整详情仅经 **control-only** `CONSENT_DESCRIBE`/`CONSENT_LIST` 读取(guest 拒),审批仍以 id 操作。
  - **限长渲染**:`canon_list` 改为**逐字符边渲染边检查上限**,单个超长 argv/env 元素不再在内存里被完整构造后才截断。
  - proto:新增 `CONSENT_DESCRIBE`/`CONSENT_LIST`(control-only)。回归:broker `l5_exec_summary_unambiguous_argv_and_env`(requester hint 不含 env/argv;control `consent_describe` 才有无歧义 argv + env);proto guest 拒 DESCRIBE/LIST;consent 集成测试断言 requester CONSENT 帧无 `PATH`/`env=`,control `CONSENT_DESCRIBE` 解码后含 env。43 broker + 5 proto + consent + 红队全绿。

- 2026-07-16 — **L5/capvm 复审修(newton e6b08520)**。
  - **L5 action-substitution 绕过 → 关**:consent 签名此前未绑定 `post` 的 body、`post_from` 的 subject,可"批准 benign 内容→重放替换 payload 放行"。修:`action_sig`(域分隔 + **长度定界**每字段 → sha256)把**所有影响副作用的规范化参数**纳入签名与审批 summary —— exec 绑 cap;http_get 绑 cap+path;**post 绑 body 的 hash**;**post_from 绑 subject**+src+rel。回归 `l5_consent_signature_binds_payload_no_substitution`:批准 A 后换 body/subject 必须重新 CONSENT,原样才放行。
  - **capvm C-list 边界 → 收窄 + 诚实降级**:此前 per-process 不可伪造只是注释(`install` 是 pub、`CapRef` 是 String,持 ref 的 host 可装入任意进程)。新增 **`Syscalls` guest 视图 trait**(只 cap_read/list/exec/derive_sub/close,**无 install、无 CapRef**)—— 交给 guest `&mut dyn Syscalls` 即类型层面阻止其装入能力。诚实标注:per-process 不可伪造是"对 guest 视图成立 + host loader 约定",强制来自未来 guest↔host(V8)边界;新增 `guest_syscall_view_has_no_install_and_no_capref` 与 `host_holding_ref_can_install_is_the_loader_boundary`(明确记录 host/loader 语义)。`docs/capvm-report.md` 同步该边界。42 broker + 5 proto + consent + 红队全绿。

- 2026-07-12 — **capvm:cap-indexed syscall ABI + C-list 运行时(Model 4 内核语义,DESIGN §3)**。
  - `crates/capable-broker/src/capvm.rs`:资源指名从字符串改为**能力句柄索引**——`cap_read(h, rel)` 而非 `open("/path")`;**不存在 ambient `open(路径)` 接口**,指名即授权、无句柄即无权。
  - `CapProcess` 持每进程 **C-list**(仿 fd 表但不可伪造/不可跨进程凭空构造):`usize` 句柄 → Broker CapRef;零权限起步(空表→任何 cap_* 拒);`install` 仅 loader 侧;syscalls `cap_read/cap_list/cap_exec/cap_derive_sub/cap_close`,复用 Broker(openat2 RESOLVE_BENEATH + C1 沙箱 + L5 gate)为底层。
  - 回归 4 条:`fresh_process_has_zero_authority`(无 ambient authority)、`cap_indexed_read_and_bounds_and_forge`(句柄不可伪造 + DirCap 边界)、`cap_derive_attenuates_and_close_revokes_handle`(衰减 + 句柄收回,父不受影响)、`handles_are_per_process_not_global`(句柄每进程,不可跨进程借用)。
  - 文档 `docs/syscall-abi.md`。诚实标注:这是 cap-indexed ABI + C-list 运行时(复用 Broker 中介);内嵌进 secure-exec V8-isolate 内核、替换其字符串 syscall 入口是更深集成(需 fork,DESIGN §3 D-capvm),属后续。

- 2026-07-12 — **L5 策略引擎 + JIT consent(能力使用点的治理层)**。
  - `crates/capable-broker/src/policy.rs`:`PolicyEngine{deny_exec,prompt_exec,prompt_http,prompt_post}`(默认 `allow_all`,不改既有行为)决策三态 `Allow|Deny|Prompt`;`ConsentLedger`(跨会话共享)—— 请求方登记 Pending、**控制面** approve/deny(按 id)、请求方重放时 `request_or_check` 消费已批准授权(**一次性**、按 (action-sig, session) 精确作用域)。
  - Session:`set_policy`/`set_consent`/`gate(verb,sig,summary)`/`consent_approve`/`consent_deny`。`gate` 在 **exec/http_get/post/post_from** 执行前插闸:Allow→放行;Deny→拒;Prompt→查/登记 consent,已批准消费放行,否则返回 `__CONSENT__` 标记(**fail-closed**:要 Prompt 但无 ledger → 拒)。所有决策入审计链。
  - proto:gate 的 `__CONSENT__\t<id>\t<summary>` → `CONSENT` 帧(区别于 ERR);新增 `CONSENT_APPROVE`/`CONSENT_DENY`(**control 面**,guest 不能自批)。`serve` 加 `--prompt-exec/--prompt-http/--prompt-post/--deny-exec`,同进程共享一个 consent 账本。
  - 回归:broker `l5_jit_consent_exec_flow`(exec→CONSENT→control 批准→重放放行→一次性再需批准)、`l5_deny_and_fail_closed_without_ledger`(deny_exec 直接拒 + 无 ledger 时 Prompt fail-closed);proto `l5_consent_wire_flow_and_guest_cannot_self_approve`(CONSENT 帧 + guest 不得自批 + control 批准 + 重放 OK + 一次性)。
  - 诚实标注:JIT consent 账本是**进程内**共享 —— 单进程双面(control+guest 连同一进程)才能跨面审批;当前 deploy 的 control/guest 分两进程,跨进程审批需单进程双面或后续 consent 总线。ci.sh 补 `--bins` 使 proto 测试纳入门禁。
  - **端到端黑盒**(`crates/capable-rpc/tests/consent.rs`):对真实 `serve --trusted --prompt-exec` 进程,请求方 exec→CONSENT、**审批者(同一 socket 的另一连接)** approve→重放放行、一次性再需批准、deny→重放 ERR。证明自然模型(capsh + 人类审批者都连控制面 socket,共享 consent 账本)可用。deploy/README 补 L5 consent 流程说明 + 更正跨进程限制表述。ci.sh step3 改跑全部集成测试(`--tests`)纳入 consent。

- 2026-07-12 — **MessageCap P0/P1 修(newton 复审):关 IFC 洗白 + mailbox_read fail-closed + owner facet 语义**。
  - **P0 IFC 洗白**:此前 `post` 从 wire 取 taint(`Taint::parse`),委托出去的只投递 facet 可把 secret 字节标 `green` 外发。修:`post` **不再接受 wire taint** —— 字面投递服务端固定 `Green`;新增 `post_from(msg, subject, src_dir, rel)`:由 broker 读源、**taint 服务端按源判定**(secret 路径 → Secret)再走 IFC 闸,Secret 即拒(即"消息体由 broker 操作产出并携带不可变 taint")。proto:`INVOKE post <subject> <body-b64>`、`INVOKE post_from <subject> <src_ref> <rel>`。回归:从 secret 源 `post_from` 被拒、字面 taint 恒 Green。
  - **P1**:`mailbox_read` 现遵循 audit 布尔 —— 披露收件箱若不能持久审计则 fail-closed 不返回(新增注入审计故障回归 `mailbox_read_fail_closed_on_audit_break`)。
  - **owner facet 语义**:明确 `grant_message` 返回 **owner(读+投递)facet**;委托用 `derive_msg_*` 派生只投递 facet,严格分离。
  - 诚实标注:`send`(SinkCap)仍由可信 capsh 编排器自报 taint(guest 不持 sink);若将来把 sink 委托给不可信方,须同样改为服务端判定 taint。
- 2026-07-12 — **MessageCap P0 二次修(newton):禁委托 facet 字面投递 —— 关"客户端知识洗白"路径**。
  - newton:字面 `post` 仍可洗白 —— 持委托 facet 者 `read(secret)` 拿到明文,再 `post(literal=复制字节)` 标 Green 外发;客户端侧知识无法保住 taint 不变量(同 SinkCap 的结构性课题)。修:**字面投递仅 owner facet(can_receive)可用**;委托(只投递)facet 一律拒字面投递,只能 `post_from`(broker 读源并判定 taint)。owner 投递进自有 mailbox(自己唯一收件、派生从不授 can_receive),不构成跨边界外发,故字面允许。
  - 新增结构性回归 `message_cap_no_literal_laundering_via_delegated_facet`:委托 facet `read(secret)`→`post(literal 复制字节)` **必须失败**,`post_from(secret)` 亦被 IFC 拒,owner 收件箱零 secret。

- 2026-07-12 — **MessageCap:CapTP 式"引用即授权"的消息投递能力(能力模型泛化到 files/cmd/http 之外)**。
  - `MsgSpec{mailbox, subject_prefix, one_shot, can_receive}` + `Cap.msg`;`Session.mailboxes`(不可伪造 mailbox id → 已投递消息,记录 provenance:发送方会话 + 数据 taint)。
  - `grant_message(recipient)`(control mint)返回**收件 facet**(can_receive);`derive_msg_prefix`(主题命名空间衰减,单调收紧)/`derive_msg_oneshot`(单次投递)派生**只投递** facet;`post`(IFC:Secret 不得外发,与 sink 一致;副作用前置 durable intent;衰减:subject 须落在 prefix 内;one_shot 投递后自动 revoke);`mailbox_read`(仅收件 facet 可读)。撤销级联复用 parent 链。
  - proto:`GRANT_MSG`(guest 拒 mint)、`DERIVE msg_prefix|msg_oneshot`、`INVOKE post|mailbox_read`。
  - 回归:broker `message_cap_delegation_attenuation_ifc_revoke`(委托/前缀衰减/IFC/one_shot/级联);proto guest `GRANT_MSG` 拒 + control 端到端 mint→委托→越界拒→只投递不可读→owner 读。
  - 诚实标注:mailbox 目前会话内(owner 与投递方同会话);真正的跨会话/跨 agent 投递需 CapTP 第三方 handoff(在收件会话重新 mint ref),列为后续。

- 2026-07-12 — **valid_host 完整 grammar**:char 白名单 → 真正的 host 文法。`[IPv6]` 须括号匹配且解析为 Ipv6Addr;裸 IPv4 literal;否则 RFC1123 主机名(label 1..=63、仅 alnum/`-`、不以 `-` 起止、拒空 label/前导尾随连续点/下划线/控制符/空白);拒"全数字点分"伪 IP(`1.2.3.4.5`/`999.1`)、内嵌端口、杂散括号。16 个 host 回归。

- 2026-07-12 — **Red-team CI 门禁:黑盒对抗测试 + 一键全量回归 `ci.sh`**。
  - `crates/capable-rpc/tests/redteam.rs`:对**真实 `capable-rpc serve` 进程**、走**真实 wire 协议**(4字节大端长度帧 + tab 文本)发起 7 类攻击,逐条断言被拒:①伪造 cap ref ②guest 自铸(GRANT_DIR/SINK/CMD/HTTP)③二次 BOOTSTRAP ④路径逃逸(绝对/`../`)⑤跨会话重放 ⑥REVOKE 级联 ⑦超大帧(16MiB>MAX_FRAME→连接关闭);正向对照合法 read 成功;收尾独立进程 `verify-audit` 断言持久审计链完整。这是端到端黑盒,不是内部单元 mock。
  - `ci.sh`:一处跑齐 build → 27 单元/proto 回归 → 红队黑盒 → capsh(OCaml)语言测试;任一步失败即非零退出。`--quick` 跳过 OCaml。全绿。
  - C1 结论:**newton 复审通过(commit 214924a),C1 CommandCap exec 沙箱在该作用域完成**。BPF arch/跳转正确、io_uring 与 pidfd/process-inspection 已拦、CLOEXEC 保留 pre_exec 错误上报同时清继承 fd、policy 失败 fail-closed。诚实标注:`.run` 现仍以 ubuntu 起双 listener,`capable-guest.service` 是模板 —— 未实际安装并验证独立 uid 前不宣称跨面 uid 隔离。

- 2026-07-11 — **B1''(P1 修,newton 复审):request-target 路径语义规范化(关代理解释差异绕过)**。
  - newton:仅拒控制字符不够 —— `//host`、反斜杠、percent-encoded 分隔符/点(`/v1/%2e%2e/admin`、`/v1/%2f..%2fadmin`、`/v1/%5c..%5cadmin`)可匹配 `/v1/**`,但代理/框架会规范化成 `/admin`,绕过白名单。修:
    - `net::canonical_request_target`:origin-form 单斜杠起始(拒 `//`/absolute/authority)、拒反斜杠/control/空白、严格 `%HH`(拒 `%2e`/`%2f`/`%5c`/malformed)、RFC3986 dot-segment 归并(`..` 穿越根之上即拒);返回 **canonical target**,`http_get_i` 用它**同时**做 allowlist 与写请求行。
    - authority 构造:IPv6 literal 加方括号,非默认端口带 port。
    - 回归 `canonical_target_and_injection_and_normalization`(newton 4 个绕过样例 + `//` + malformed + 穿越 + query 保留 + dot 归并)。28 个测试全绿。
  - **deploy 修**:capsh 环境变量实为 `CAPSH_BROKER`(非 `CAPABLE_BROKER`),deploy/run-broker.sh + README 已更正(此前 deploy 端到端误跑本地后端即因此)。

- 2026-07-11 — **B1'(P1 修,newton 复审):关闭 HttpCap CRLF/request-target 注入 + IP 分类收紧**。
  - newton:`path` 未校验控制字符就进请求行,`/**` 下可注入 `X-Original-URL`/重复 Host 绕过白名单。修:
    - `net::valid_request_target`:必须以 `/` 起始,拒绝 CR/LF/NUL/所有 <0x20 control/DEL/空白/absolute-form;`http_get_i` 在白名单**前**校验,只把 canonical target 写进请求;`fetch_get` 再兜一层 fail-closed。
    - `net::valid_host`:host 必须是合法 DNS name/IP literal(仅 alnum/`.`/`-`/`:`/`[]`);`grant_http` 校验。Host 头对非默认端口构造规范 `host:port`。
    - `is_blocked_ip` 收紧:补 IPv4 `0/8`、multicast `224/4`、reserved `240/4`、broadcast、documentation、6to4-relay `192.88.99/24`;IPv6 multicast `ff00::/8`。
  - 回归:`rejects_crlf_request_target_and_host_injection`、`blocks_reserved_and_multicast`。28 个测试全绿。

- 2026-07-11 — **Phase B / B1:HttpCap + 受限网络 helper(nono-proxy 蓝本)**。
  - `crates/capable-broker/src/net.rs`:egress 安全策略 —— cloud-metadata 主机名恒拒、private/loopback/link-local/CGNAT/ULA IP 恒拒、`resolve_checked` **DNS 解析一次**并要求调用方连接解析出的 IP(关 DNS-rebind);`path_matches`(`*`/`**` glob);`fetch_get`(明文 HTTP,连接**预解析地址**、固定 Host、byte-limited、**不跟随重定向**)。
  - `capable-broker`:`HttpSpec`(scheme/host/port/methods/paths/max_bytes)+ `Cap.http`;`grant_http`(control-only mint)、`http_get`(method/path 白名单 → SSRF 检查 → 连接预解析 IP;**响应 taint 由服务端标 External**,不 wire 自报;有副作用 → 前置 durable intent)。
  - `capable-rpc`:`GRANT_HTTP`(guest 拒,control-only)+ `INVOKE <ref> http_get <path>`。
  - 诚实:https 需 TLS(离线无 rustls)暂拒,列为后续;安全关键的 SSRF/白名单逻辑离线单测。
  - 回归:net `blocks_metadata_and_private`/`ip_classification`/`path_glob`;broker `http_cap_denials`(metadata/loopback/path 越界/https 均拒);proto guest `GRANT_HTTP` 被拒。26 个测试全绿。
  - newton 复审标准:DNS/连接/TLS-SNI/重定向绑定同一已验证 endpoint(已:解析一次+连预解析 IP+固定 Host+不跟随重定向;TLS 待补);taint 服务端携带(已:响应 External)。

### Security
- 2026-07-12 — **C1 修(newton 复审 P0):seccomp 从「拦已知网络 syscall」补齐为真正的 default-deny + 跨进程隔离**。
  - newton 指出两类 kernel bypass:①`io_uring_setup/enter/register` 被 ALLOW → 支持 `IORING_OP_SOCKET` 的内核可不经 `socket()` 建网络 socket;②默认不 drop uid 且 `ptrace/pidfd_open/pidfd_getfd/process_vm_*` 被 ALLOW → 子进程可对同 uid 的 Broker 父进程做进程/FD 操纵。修:
    - `install_seccomp_deny`(原 `_net_deny`)扩表 23→47 条:补 `recvfrom/recvmsg`;**io_uring** `io_uring_setup(425)/enter(426)/register(427)`;**跨进程** `ptrace(101)/process_vm_readv(310)/process_vm_writev(311)/kcmp(312)/pidfd_send_signal(424)/pidfd_open(434)/pidfd_getfd(438)` 全部 EACCES。
    - 网络 default-deny 正确性论证写进注释:socket 只能经 socket/socketpair/io_uring/继承fd/SCM_RIGHTS/`/proc/*/fd` 取得,已分别封死(后二者靠 close_range CLOEXEC + Landlock 挡 /proc),故无 socket fd 可 read/write —— 无需按 nr 过滤 read/write。
    - 回归 `seccomp_blocks_network_socket` 加强:子进程内 socket/socketpair/io_uring_setup/pidfd_open/ptrace **逐条**必须被拒,任一放行即 fail。
    - **同 uid 诚实标注 + 部署边界**:seccomp 禁跨进程 syscall 属纵深防御;真正的进程隔离需 guest Broker 以专用 uid 运行。新增 `deploy/capable-guest.service`(`User=capable-guest` 必须 != control 面 uid),deploy/README 信任模型同步。31 个测试全绿。

- 2026-07-11 — **C1 / L1 OS 沙箱:CommandCap exec 加 Landlock fs 限制 + cwd fd-identity**。
  - 现在 exec 在 fork 后、execve 前(`Command::pre_exec`)施加:`no_new_privs` + **Landlock**(handled=全 v1 fs 访问,仅允许 cwd 与 `/usr`/`/bin`/`/lib`/`/lib64` **只读+exec**;写/删/创建一律拒,cwd 外与 `/etc`/用户 HOME/.ssh/其它项目均不可达)+ `fchdir` 到**持有的 cwd fd**(CommandCap 复用 cwd DirCap 的稳定 dir_fd,关 newton 的 cwd 路径 swap 残留)。纯 raw-syscall(延续 openat2 做法)。
  - **fail-closed**:Landlock 不可用/非 x86_64/无 cwd fd → 拒绝执行(不无沙箱跑)。
  - 回归 `exec_sandbox_confines_fs_to_cwd`(cwd 内 `cat` 可读、cwd 外绝对路径读 stdout 空);远端 capsh 实测 `cat f.txt` OK、`cat /etc/hostname` 被拒(空)。29 个测试全绿。
  - 残留:网络 deny(seccomp/netns)、可写子目录按需授权 —— 下一子步。

- 2026-07-11 — **A-polish(newton 非阻塞 follow-up):Phase A 已通过复审,补两个小项**。
  - **#1 grant_dir 改返回 `Result`**:root 打不开即 **fail grant**,不产生「无 fd 的已授予 cap」(避免 allow 审计/describe 与不可用 cap 状态分叉)。`set_bootstrap` 相应 `.ok()`,proto GRANT_DIR `?`,测试 `.unwrap()`。
  - **#3 getdents64 fail-closed**:遇畸形/截断记录返回错误,不再 `break` 返回部分目录。
  - 残留 #2(CommandCap cwd 仍字符串,control-only):记为独立项,待 command 委托给非 TCB 或成真实副作用前切 held cwd fd。22 个测试全绿。
  - **Phase A(newton 2 P0 + 多轮 P1)复审通过**。

- 2026-07-11 — **A2''(P0 完整关闭,newton 复审):Cap 持有稳定 root 目录 fd**。
  - newton 复审 A2':openat2 只护「已打开 root fd 以下」,但我每次从**可变字符串路径**重开 root fd → 授予/派生后替换根路径(如把 `/tmp/ws` 换成 →/etc 的 symlink)可让 openat2 把 /etc 当可信 root。root/path-identity 重解析未关。修:
    - `Cap` 新增 `dir_fd: Option<Arc<OwnedFd>>`;`grant_dir` 授予时可信打开 root 得到稳定 fd 并保存;`derive_sub` 用**父 fd** 的 `openat2(O_PATH|O_DIRECTORY)` 原子派生子 fd;`derive_readonly`/撤销共享父 fd(Arc)。
    - `read`/`list` 以持有的 dir fd 作 openat2 anchor(`os::read_at`/`list_at`),不再 `File::open(root)` —— 授予/派生后替换路径不再影响已持有 inode。`os.rs` 全改 fd-based,`rel=""`→`"."`(目录本身,保留语义)。
    - 路径字符串仅留作 describe/taint 标签。command cwd 仍用字符串(control-only,标注为独立残留)。
  - 回归:`root_path_swap_after_grant_defeated_by_held_fd`、`sub_path_swap_after_derive_defeated_by_held_fd`(授予/派生后把路径换成 →/etc,held fd 仍只访问原 inode、/etc/passwd 不可达);`os::openat2_fd_blocks_symlink_and_swap`。22 个测试全绿;demo/远端 capsh 无回归。

- 2026-07-11 — **A2'(P0 原子解析,newton 优先):openat2 RESOLVE_BENEATH 关闭 DirCap TOCTOU**。
  - 新增 `crates/capable-broker/src/os.rs`:纯 std + `core::arch::asm!` 直发 **openat2**(x86_64-linux,零依赖),`RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS` 原子解析,关闭 symlink/`..` 越界与残留 TOCTOU;`list` 用 openat2 + **getdents64** 在 fd 上枚举(无路径再解析);`derive_sub` 用 openat2 `O_PATH` 原子校验。
  - **fail-closed(newton)**:openat2 不可用/ENOSYS/非 x86_64 → **拒绝访问**,不静默回退 canonicalize;canonicalize 仅在显式 `CAPABLE_UNSAFE_CANONICALIZE=1` 的不安全 dev 模式下启用(默认关)。
  - `read`/`list`/`derive_sub` 全改走 `os::*`。回归 `os::openat2_blocks_symlink_escape`(根内读 OK、symlink 越界读/子目录 derive 均拒);`symlink_escape_blocked` 现经 openat2。20 个测试全绿;demo/远端 capsh 无回归。

- 2026-07-11 — **A4''(P1 crash-recovery 修,newton 复审):审计 durable fsync + fail-closed 恢复**。
  - newton:`record` 只 `flush`(无 fsync)、anchor 非原子替换 → 断电时 "durable intent" 可能仅在 page cache;`open` 盲信 anchor → 会从伪 head 续坏链。修:
    - `record`:log append 后 `sync_data()`;anchor 走 **临时文件 → `sync_all()` → 原子 rename → fsync 父目录**;任一步失败 → `record` Err → exec/send **不执行**。
    - `open`:**fail-closed** —— 重放并验证 log 得 `(count, head)`,要求 anchor 与之一致;log/anchor 缺失/损坏/不一致 → 拒绝启动。空 log+空 anchor = 合法新起。崩溃状态矩阵注释在案(log 领先 anchor → 重启拒绝)。
    - `verify_persisted` 复用 `replay`。
  - 回归测试 `open_rejects_inconsistent_anchor`(伪造 anchor + restart 拒绝)、`record_failure_blocks_side_effect`(anchor 原子写失败 → exec 不执行)。19 个测试全绿。
  - openat2(A2 原子解析)门槛记:syscall 不可用/ENOSYS/非 x86_64 必须 **fail-closed**,不静默回退 canonicalize(否则重开 TOCTOU);canonicalize 仅作显式标注的不安全 dev 模式,非默认。

- 2026-07-11 — **A4'(P1 重修,newton 复审):审计全局链 + 副作用前 durable intent**。
  - newton 复审:①共享 `AuditSink` 时每会话 seq/prev 从 0/GENESIS 重来,而 `verify_persisted` 按全局连续链验证 → 第二个会话即令日志验证失败;②`audit_broken` 发生在副作用之后,首次失败的操作仍"已执行但未持久审计"。修:
    - **全局链移入 AuditSink**:`AuditSink` 持有 `(count, head)`,`record(session, op, detail, dec)` 在同一把锁内分配 seq/prev、写 **session 身份**、append+anchor;多会话共享同一 sink 仍是一条连续链。`open` 从 anchor 恢复 (count,head) 以跨重启续链。`verify_persisted` 改 7 字段(seq|session|op|detail|dec|prev|hash)。
    - **副作用前 durable intent**:`exec`/`send` 执行前预写 `*.intent`,intent 审计失败则**不执行**(fail-closed);完成后记 `*.result`。read/list 无外部副作用,执行后审计,成功结果若未能持久审计则**不返回数据**(fail-closed 拒绝返回)。`audit()` 返回是否持久化成功。
  - OS 权限:control socket bind 后立即 chmod 0600(newton 指出的 umask 窗口为已知小项,已注释)。
  - 回归测试 `shared_sink_global_chain_across_sessions`(两会话共享 sink 后全局链仍可验证)。17 个测试全绿;demo/远端 capsh 无回归。

- 2026-07-11 — **A1'(P0 重修,newton 复审):guest wire 彻底移除 mint verb + 审计 fail-closed**。
  - newton 复审指出 A1 只堵了 GRANT_DIR,GRANT_CMD/GRANT_SINK 仍开放 → guest 可自铸 CommandCap(任意命令以 broker 身份执行)、自铸 SinkCap 且 send 信客户端 taint(读 Secret 后改标 green 外泄)。**重修**:
    - `Role`(Control/Guest)贯穿 proto:**guest 面拒绝所有 GRANT_***(GRANT_DIR/CMD/SINK);mint 仅 control 面。
    - guest 初始 authority 由服务端**注入** workspace 根 DirCap;新增 `BOOTSTRAP` verb(**一次性**,`Session::take_bootstrap`)取预注入根,之后只能 DERIVE + INVOKE read/list。
    - **OS 访问控制**:control socket 文件权限 0600(仅属主)、guest 0660;跨权限隔离靠 uid + socket 权限,非仅 `--trusted` 参数。
    - 审计 **fail-closed**:`AuditSink::append` 失败置 `audit_broken`,`get_active` 起点 `ensure_audit_ok` 拒绝后续敏感操作;`verify_persisted` 对缺失/畸形 anchor 返回 `Ok(false)`(不再 fail-open)。
  - capsh 作为本地 TCB 编排器连 control 面(`serve --trusted`),功能不变;不可信客户端走 guest 面。
  - 回归测试:proto `guest_cannot_mint_bootstrap_oneshot_control_can`;broker `audit_missing_or_corrupt_anchor_fail_closed`、`audit_broken_fails_closed`。16 个测试全绿;guest demo 演示所有 mint 被拒 + BOOTSTRAP 一次性;远端 capsh 经 control 面正常。

- 2026-07-11 — **A4(P1 修复,newton review):审计持久化 + 诚实降级文案**。
  - `capable-broker/src/audit.rs`:`AuditSink`(append-only 文件 + `.anchor`(count+head))+ `verify_persisted`(重算链 + 连续 seq + anchor 比对,**检测尾部截断**)。`Session::with_sink` 可选持久化;audit 字段先规范化(去 tab/换行)再算 hash,保证内存链与持久链一致。
  - `capable-rpc`:`serve --audit-log <path>` 全服务共享 sink;AUDIT 标签降级为 `in_process_chain_verify(仅进程内完整性)`。
  - **诚实降级**:文案不再宣称「防篡改/tamper-evident」——内存链=进程内完整性校验;持久化+anchor 只检测尾截;对能同时改写 log 与 anchor 的写者不设防,需外部签名(DSSE/Sigstore),列为后续。
  - 回归测试 `persisted_audit_survives_and_detects_truncation`(落盘 → verify 通过 → 删末行 → anchor 检测到)。14 个测试全绿。

- 2026-07-11 — **A3(P1 修复,newton review):传输层资源上限**。
  - `capable-rpc/proto.rs`:`MAX_FRAME=8MiB`,`read_frame` 先校验长度再分配(防单连接宣称 4GiB 帧 OOM);手动读帧头,**半个头报 UnexpectedEof 截断错误**(不再静默当 EOF),干净 EOF 才返回 None。
  - `main.rs`:并发连接上限 `MAX_CONNS=64`(超过即拒绝关闭,不建线程)+ 单连接 `READ_TIMEOUT=30s`(防半开连接占线程)。
  - 回归测试:`oversized_frame_rejected_before_alloc`、`truncated_header_is_error_not_eof`、`clean_eof_is_none`。13 个测试全绿。

- 2026-07-11 — **A2(P0 修复,newton review):关闭 DirCap 经 symlink 越界**。
  - `capable-broker`:新增 `resolve_contained(root, rel)` —— 字符串层拒 abs/`..` 后,`canonicalize`(解析所有 symlink)并验证结果仍在 canonical root 之下。`read`/`list`/`derive_sub` 全改用它;symlink 指向根外、或 symlink 子目录 derive 均被拒。
  - 回归测试 `symlink_escape_blocked`(根内建 `escape -> /etc` symlink,读 `escape/passwd` 与 `derive_sub escape` 均被拒)。10 个测试全绿;demo/远端 capsh 无回归。
  - 诚实标注:canonicalize+containment 有 TOCTOU 残留;原子版需 `openat2(RESOLVE_BENEATH)`,当前离线环境无 libc,待引入后升级(已在代码注释与 DESIGN 记)。

- 2026-07-11 — **A1(P0 修复,newton review):关闭 guest RPC 可颁发任意主机路径 DirCap 的漏洞**。
  - `capable-broker`:新增 `Role`(Control/Guest)+ `Policy`(guest 的 grant 限定在 canonical 化的 workspace 内,fail-closed;污点由服务端决定,不信客户端自报)。`read` 对敏感路径(.ssh/.env/secret/id_rsa/credential…)一律升级为 Secret —— 客户端无法 under-report 成 Project 再外泄。
  - `capable-rpc`:`handle` 传入 `&Policy`;`GRANT_DIR` 先过 `gate_grant_dir`,污点走 `grant_taint`。`serve <sock> --workspace <root>`(guest,默认)/ `--trusted`(可信控制面)。
  - 回归测试:`guest_grant_confined_to_workspace`、`secret_path_taint_escalation`、proto `guest_cannot_grant_outside_workspace`(guest grant /etc 被拒)。9 个 Rust 测试全绿;远端 capsh 仍工作,secret 读服务端升级。
  - 说明:这是「grant scope/taint 由服务端 policy 决定 + 区分 control/guest 角色」;后续 A-系列继续 symlink(A2)、资源上限(A3)、审计持久化(A4)。

### Added
- 2026-07-11 — **实现 slice 6:Rust Broker 防篡改审计(hash-chain,D-audit=nono)**。
  - `crates/capable-broker/src/sha256.rs`:手写 SHA-256(std-only,含已知向量测试)。
  - `capable-broker`:`AuditEvent`(seq/op/detail/decision/prev/hash)+ `Session.audit`;每个 grant/derive/read/list/exec/send/revoke **及其拒绝**都记一条 hash-chain 事件(hash=sha256(seq|op|detail|decision|prev));`verify_audit()` 重算全链验证防篡改。read/list/exec/send 改 `&mut self` 以记审计。
  - `capable-rpc`:`AUDIT` 动作 dump 全链 + `chain_verify`。demo 第 8 段打印审计链。
  - 测试:6 个单测全绿(新增 sha256 已知向量 + audit_chain 篡改必被检测);`cargo run -p capable-rpc -- demo` 打印 16 条 hash-chain 事件,末尾 `chain_verify: ok`。

- 2026-07-11 — **实现 slice 5c:求值器可插后端(`.capsh` 透明跑本地或远端 Broker)**。
  - `backend.ml`:`BACKEND` 模块类型(grant/derive/read/list/send/exec/describe/kind/taint)。
  - `backend_local.ml`:进程内后端(包 `Cap`/`Broker`)。`backend_rpc.ml`:远端后端(走 `rpc_client` → Rust Broker;cap=opaque ref + 客户端记 kind/taint 供 confine 检查)。
  - `value.ml` 改为对能力类型多态(`'c t`);`eval.ml` 改为函子 `Make(B:BACKEND)`;`main.ml` 按 `CAPSH_BROKER` 环境变量选后端。
  - `taint.ml`:`of_string`。Makefile:`run-capsh-remote`(起 Rust 服务 + 同一份 `hello.capsh` 透明跑远端)。
  - 验证:`make test` 本地全绿;`make run-capsh-remote` —— **同一份 hello.capsh 在 Rust Broker 上跑,grant/read/衰减/secret→sink IFC 全在 Rust 侧执行**。capsh↔Broker 端到端语言运行时打通。

- 2026-07-10 — **实现 slice 5b:OCaml capsh ↔ Rust Broker 桥(端到端)**。
  - `capsh/src/rpc_client.ml`:capsh 侧 CapTP-lite 客户端(OCaml,unix)——帧读写 + 手写 base64 + 高层能力操作(grant dir/sink/cmd、derive sub/readonly、read/list/exec/send、revoke、describe)。capsh 只持 opaque ref,真实能力在 Rust Broker。
  - `capsh/src/remote_demo.ml`:OCaml 客户端驱动 Rust `capable-rpc` 的端到端 demo。
  - Makefile `remote` / `remote-demo`:`remote-demo` 自动起 Rust 服务 + OCaml 客户端跑 6 段(grant/read、越界拒绝、衰减、secret IFC、CommandCap exec、撤销级联),全程 OCaml→socket→Rust。跑通。
  - 说明:这是 capsh↔Broker 的【桥】;把 `.capsh` 求值器透明改走 RPC(替换进程内 Cap)是 5c。

- 2026-07-10 — **实现 slice 5(B):Rust capable-broker + capable-rpc（CapTP-lite over socket）**。
  - Cargo workspace `capable/`(crates/capable-broker + crates/capable-rpc),**纯 std 零依赖**,可离线构建。
  - `capable-broker`(lib):L3 Broker。cap 引用 = /dev/urandom 生成的不可猜测、会话绑定 token(不变量 14);grant dir/sink/command、invoke read/list/exec/send、derive sub/readonly(单向衰减)、revoke(祖先链级联)、taint IFC(secret 拒外发)、路径越界拒绝。4 个单测(含跨会话 ref 失效)全绿。
  - `capable-rpc`(bin):CapTP-lite over Unix socket。length-prefixed 帧 + tab 文本 + base64(手写);`serve <sock>` 服务(每连接一会话)/ `demo` 端到端。
  - `cargo run -p capable-rpc -- demo` 端到端跑通 7 段:grant/read、越界拒绝、衰减、secret→sink IFC、CommandCap exec、撤销级联、**跨会话 ref 不可重放**。
  - `crates/README.md` 协议文档;`.gitignore` 加 `target/`。

- 2026-07-10 — **实现 slice 4:confine 区室 + spawn 委托**。
  - `ast.ml`:`SScope of scope_kind * label * (name*expr) list * stmt list`(Confine|Spawn)。
  - `cap.mli`/`cap.ml`:`any_taint`(读能力污点,供区室规则)。
  - `parser.ml`:`parse_stmt` 并入递归组 + `parse_block` + `parse_scope`;语法 `confine|spawn "label" with { name: capexpr, ... } { body }`。
  - `eval.ml`:`exec_stmt` 改递归;`SScope` 在外层求值委托能力 → 子环境仅含委托项(默认零权限,外层不可达)→ 执行 body;**confine 规则**:同区室同时持 Secret 读能力 + sink 即 Capsh_error。
  - `examples/confine.capsh`:spawn 只读委托、confine reader(敏感读无外发,合法)、confine leaky(敏感读+外发,拒绝)。
  - `make test` 纳入 confine.capsh,全绿。

- 2026-07-07 (五) — **实现 slice 3:CommandCap + run（一命令一卡,无 shell）**。
  - `cap.mli`/`cap.ml`:新增 command 种类;`exec`(execvpe 直接执行 argv,fork+chdir 到绑定 cwd,捕获 stdout,输出标 Yellow)、`root_of`、`any_cmd`/`as_cmd`、`Trusted.mint_command`;`raw` 加 `argv`/`cenv` 字段。
  - `broker.ml`:`grant_command`。
  - `ast.ml`:`EGrantCmd`;`lexer.ml`:`:` -> `TColon`;`parser.ml`:`grant command sh\`..\` { cwd: e, ... }` + `parse_fields`;`eval.ml`:`argv_of_sh`(插值恒为单个 argv 元素)、`EGrantCmd`(cwd 取自 DirCap 根,env allowlist 剥离宿主环境)、`run` 内置。
  - **shell 注入结构上不可能**:`examples/command.capsh` 中 `echo ${"oops; rm -rf /"}` 把整串作为一个 argv 元素原样打印,不经 shell、不执行。
  - Makefile `run-capsh`/`test` 纳入 `examples/command.capsh`;`make test` 全绿。

- 2026-07-07 (四) — **实现 slice 2:capsh 解释器（OCaml）**——把 core 接成真正的语言。
  - `cap.mli`/`cap.ml`:新增存在类型 `Cap.any`(抹去 phantom,供求值器统一持有能力)+ `as_dir`/`as_sink`/`any_describe` 等投影。
  - `value.ml`:运行期值 `VData`(带 taint)/`VCap`/`VUnit`,两个宇宙分离;`as_cap` 对裸值报错。
  - `ast.ml` / `lexer.ml`(手写)/ `parser.ml`(递归下降)/ `eval.ml`(求值器,TCB)/ `main.ml`(CLI)。
  - 语言子集:`let`、字符串、`grant dir/sink`(含 `{...,secret}` 显式污点标记)、方法链衰减/使用(`.sub/.readonly/.read/.list/.send/.describe`)、`print`、**quasi-literal**(`path`/`sh`,`${ident}` 插值恒为数据)。
  - **path quasi 注入防护**:插值必须是单一安全路径段(含 `/`/`..` 即拒)——`examples/injection.capsh` 演示。
  - **taint 信息流**:secret 数据流入 `send` 外发 sink 运行期拒绝——`examples/hello.capsh` 末行。
  - Makefile:`make capsh` 构建解释器,`make run-capsh` 跑示例,`make test` 含全部;`examples/hello.capsh`、`examples/injection.capsh`、`examples/workspace/`。
  - `make test` 全绿(core demo + forge-check + 两个 capsh 示例)。

- 2026-07-07 (三) — **实现 slice 1:capsh-core（OCaml）**——把「能力不可伪造」变成可跑可验证的事实。
  - `capsh/src/cap.mli` + `cap.ml`:能力抽象类型 `'k t`(phantom 种类 dir/file/command/sink),表示隐藏;USE(read/list/send)+ ATTENUATE(sub/read_only)+ 可撤销 forwarder(make_revocable/revoke,祖先链级联)+ declassify(需 declassifier)+ Trusted.mint_*(仅 TCB)。
  - `capsh/src/taint.ml`:运行期 taint 标签(三色 + 细粒度)+ join/combine + 信息流谓词(D-taint 运行期起步)。
  - `capsh/src/broker.ml`:最小 Broker,持有唯一 minter,grant 是唯一授权入口。
  - `capsh/src/script_layer.ml`:窄签名 `ScriptCap`(类型相等、无 Trusted/minter)模拟不可信脚本层——结构上无法铸造能力。
  - `capsh/src/demo.ml`:可运行 demo,演示 grant/越界拒绝/衰减/taint confinement/declassify/撤销级联,全部通过。
  - `capsh/src/forge_fail.ml` + Makefile `forge-check`:**反向测试**——伪造能力(记录字面量构造 / 字符串当 cap)必须编译失败;`make forge-check` 断言之(`Unbound record field root`)。
  - 纯 `ocamlc + unix.cma` 构建(无 dune/opam 依赖),`make run|forge-check|test`。
  - `.gitignore`、`capsh/README.md`。
  - 尚无解析器/求值器(slice 2);此片先验证 D-encap 内核论点。

### Changed
- 2026-07-07 (二) — 依 jiangplus 对 4 个开放问题的方向,拍板并写进文档。
  - **D-encap → OCaml abstract type（capsh 侧）**：capsh-language.md 新增 §2.3「语言层强封装」——`.mli` 抽象类型使能力不可构造/匹配/序列化/伪造,phantom 种类 + generative-functor 会话 brand + sealer/unsealer,并写清「只挡 capsh 层」的诚实边界。
  - **D-rpc → 能力传递 RPC**：DESIGN 新增 §11.5「Capable RPC（CapTP-lite）」。连接即最小权限、方法作用在能力引用、线上引用为会话绑定不可伪造 token、promise+eventual send。crate 布局加 `capable-rpc/`。（Codar workspace 集成暂不做,但 RPC 先具备。）
  - **D-ipc → CapTP-lite over socket**：DESIGN §11.5.2 给出 FFI vs CapTP vs CapTP-lite 评估表；采 CapTP 概念子集(lease 替代分布式 GC、broker 中介替代三方 handoff),本地 Unix socket/远程 TCP/vsock,非裸 FFI。
  - **D-taint → 运行期标签起步,GADT 暂不上**：capsh-language.md §6 顶部加实现节奏说明；GADT 编译期化记为「IFC 2→3 分」后续可选。
  - DESIGN §16 重构为「16.1 已定决策 / 16.2 仍开放」,记录全部 7 条决策(capsh=OCaml、capvm 改 kernel、审计=nono、encap、rpc、ipc、taint)。

- 2026-07-07 (一) — 依 jiangplus 反馈迭代设计。
  - **重命名 cvm → capvm**（Capable VM）全文档统一。
  - **capsh 重设计为一门完整 capability 语言**：新增 `docs/capsh-language.md`（v0.1）。致敬 E 语言对象能力谱系。核心特性:数据/能力两个宇宙、能力即对象引用 + 衰减靠方法链、quasi-literal 从语法层杀死注入(path/sh/glob/url/sql 模板,插值恒为数据)、taint-aware 信息流在类型层强制 confinement、eventual send + promise 并发、revocable forwarder 一等撤销、prepare/commit 事务、confine 区室(fork+cap_enter 的语言形态)。DESIGN §5 改为概览 + 指向该文档。
  - **三条选型决策拍板并回写 DESIGN §16**：
    - capsh 实现语言 → **OCaml**（迭代快;abstract type = 语言级不可伪造引用;GADT/phantom type = 编译期 taint）；capvm/Broker 核心保持 Rust。
    - capvm 落地 → **改造 secure-exec kernel**（cap-indexed 为原生 ABI,非 shim）。DESIGN §3.1 更新取舍。
    - 审计防篡改 → **采用/借鉴 nono 方案**（hash-chain + Merkle + DSSE/Sigstore;写入侧必须在可信 sidecar,不落 guest）。

### Added
- 2026-07-07 — 初始化 Capable 仓库与设计基线。
  - `README.md`：项目定位（OCap VM 运行环境 + capsh capability-native shell）与「为什么不是增强 agentos」。
  - `DESIGN.md`：完整设计方案初稿 v0.1。包含：定位与目标、总体架构（6 层映射到具体组件）、Capable VM（capvm）的 cap-indexed syscall ABI、Capability Broker（HMAC 不可伪造引用 + facet 链 + 衰减/委托/撤销）、capsh 语言规范、Capability 类型目录、三色信任 + taint + 区室化 confinement、Policy Engine / Human Control Plane、Restricted Helpers + OS 沙箱基线、威胁模型映射、与 agentos 的具体复用/替换映射、M0–M4 路线图、采纳的 D1–D15 决策、OCap 七属性自评目标。
  - `CHANGELOG.md`：本文件。
