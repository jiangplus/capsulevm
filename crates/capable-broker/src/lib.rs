//! capable-broker —— Capable 的 L3 能力 Broker(Rust,纯 std)。
//!
//! 持有真实能力 registry;cap 引用是不可猜测、会话绑定的 token(不变量 14):
//! A 会话铸的 ref 不在 B 会话的 registry 里,天然失效。能力表示只活在这里,
//! 客户端(capsh)只拿到 opaque ref。对应 DESIGN §4 / §11.5。

pub mod audit;
pub mod capvm;
pub mod net;
mod os;
pub mod policy;
mod sha256;

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::os::unix::io::{AsRawFd, OwnedFd};
use std::process::Command;
use std::sync::{Arc, Mutex};

/// 一条审计事件(hash-chain)。hash = sha256(seq|op|detail|decision|prev);
/// 未重算的插入/删改会断链。**内存链只是「进程内完整性校验」**;持久化 + 尾截检测见
/// `audit` 模块;真正的防篡改(对写者)需外部签名(DSSE),尚未实现,故不宣称 tamper-evident。
#[derive(Clone)]
pub struct AuditEvent {
    pub seq: u64,
    pub op: String,
    pub detail: String,
    pub decision: String,
    pub prev: String,
    pub hash: String,
}

fn decision<T>(r: &Result<T, String>) -> String {
    match r {
        Ok(_) => "allow".into(),
        Err(e) => format!("deny:{}", e),
    }
}

/// 连接角色:Control=可信控制面(可任意铸造);Guest=不可信客户端(grant 受 policy 约束)。
#[derive(Clone, Copy, PartialEq)]
pub enum Role {
    Control,
    Guest,
}

/// 服务端授权 policy(最小 L5):约束 guest 的 grant 范围与污点,由服务端决定,不信客户端自报。
#[derive(Clone)]
pub struct Policy {
    pub role: Role,
    pub workspace: Option<String>, // guest 的授权域根(canonical 后做前缀约束)
}

impl Policy {
    pub fn control() -> Policy {
        Policy { role: Role::Control, workspace: None }
    }
    pub fn guest(workspace: &str) -> Policy {
        Policy { role: Role::Guest, workspace: Some(workspace.to_string()) }
    }

    /// 是否允许 guest 对 root 颁发 DirCap:必须在 workspace 之内(canonical 前缀,fail-closed)。
    pub fn gate_grant_dir(&self, root: &str) -> Result<(), String> {
        match self.role {
            Role::Control => Ok(()),
            Role::Guest => {
                let ws = self
                    .workspace
                    .as_ref()
                    .ok_or("guest 无 workspace 授权域,拒绝 grant")?;
                if path_within(ws, root) {
                    Ok(())
                } else {
                    Err(format!("越出 workspace:grant root {} 不在 {} 之内", root, ws))
                }
            }
        }
    }

    /// grant 的污点由服务端决定:guest 一律 Project 基线(读时按路径升级);control 信客户端。
    pub fn grant_taint(&self, client_taint: Taint) -> Taint {
        match self.role {
            Role::Control => client_taint,
            Role::Guest => Taint::Project,
        }
    }
}

/// 服务端污点策略:敏感路径的读一律标 Secret(客户端无法通过自报 Project 绕过 IFC 外泄)。
pub fn is_secret_path(p: &str) -> bool {
    [".ssh", ".aws", ".gnupg", ".env", "secret", "vault", "id_rsa", "id_ed25519", "credential", ".pem"]
        .iter()
        .any(|m| p.contains(m))
}

/// canonical 前缀约束(解析 symlink 后比较,fail-closed:任一 canonicalize 失败即拒)。
pub fn path_within(root: &str, child: &str) -> bool {
    match (fs::canonicalize(root), fs::canonicalize(child)) {
        (Ok(r), Ok(c)) => c.starts_with(&r),
        _ => false,
    }
}

/// 从 /dev/urandom 取熵,生成不可猜测的 hex 串(cap id / session key)。
pub fn rand_hex(nbytes: usize) -> String {
    let mut f = fs::File::open("/dev/urandom").expect("open /dev/urandom");
    let mut buf = vec![0u8; nbytes];
    f.read_exact(&mut buf).expect("read /dev/urandom");
    let mut s = String::with_capacity(nbytes * 2);
    for b in buf {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// 三色信任 + 细粒度污点(运行期标签,决策 D-taint)。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Taint {
    Green,
    Yellow,
    Project,
    Secret,
    External,
    AgentGenerated,
}

impl Taint {
    pub fn as_str(&self) -> &'static str {
        match self {
            Taint::Green => "green",
            Taint::Yellow => "yellow",
            Taint::Project => "project",
            Taint::Secret => "secret",
            Taint::External => "external",
            Taint::AgentGenerated => "agent_generated",
        }
    }
    pub fn parse(s: &str) -> Taint {
        match s {
            "yellow" => Taint::Yellow,
            "project" => Taint::Project,
            "secret" => Taint::Secret,
            "external" => Taint::External,
            "agent_generated" => Taint::AgentGenerated,
            _ => Taint::Green,
        }
    }
    /// 是否属于「敏感读」(用于 confinement 与 IFC)。
    pub fn is_sensitive(&self) -> bool {
        *self == Taint::Secret
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Op {
    Read,
    Write,
    Delete,
    List,
    Exec,
}

pub type CapRef = String;

/// HttpCap 规格:origin(scheme+host+port)+ method/path 白名单 + 字节上限。
#[derive(Clone)]
pub struct HttpSpec {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub methods: Vec<String>,
    pub paths: Vec<String>,
    pub max_bytes: usize,
}

/// MessageCap 规格:指向一个不可伪造 mailbox 的引用 —— 能力即"向该接收者投递消息"的授权。
/// 衰减(designation 约束 authority):`subject_prefix` 限定只能在某主题命名空间下投递;
/// `one_shot` 单次投递后自动失效;`can_receive` 区分收件(owner)与投递(delegatee)facet。
#[derive(Clone)]
pub struct MsgSpec {
    pub mailbox: String,        // 不可伪造 mailbox id(能力持有者无法凭它猜到别的 mailbox)
    pub subject_prefix: String, // 衰减:强制主题前缀("" = 无约束);派生只能收紧(单调)
    pub one_shot: bool,         // 衰减:投递一次后自动 revoke 本 facet
    pub can_receive: bool,      // true=收件 facet(owner,可读 mailbox);false=只投递 facet
}

/// mailbox 内的一条已投递消息(记录 provenance:发送方会话 + 数据 taint)。
#[derive(Clone)]
pub struct PostedMsg {
    pub subject: String,
    pub body: String,
    pub taint: Taint,
    pub from_session: String,
}

/// 能力的真实表示(只存在于 Broker 进程内)。
#[derive(Clone)]
pub struct Cap {
    pub id: CapRef,
    pub kind: &'static str, // "dir" | "sink" | "command"
    pub revoked: bool,
    pub root: String,       // dir/command 的根 / cwd
    pub ops: Vec<Op>,
    pub taint: Taint,
    pub name: String,       // sink 名 / 命令展示
    pub argv: Vec<String>,  // command
    pub env: Vec<String>,   // command env allowlist
    pub dir_fd: Option<Arc<OwnedFd>>, // DirCap:授予时打开的稳定目录 fd(openat2 anchor,防 root 路径 swap)
    pub http: Option<HttpSpec>, // HttpCap 规格
    pub msg: Option<MsgSpec>,   // MessageCap 规格(投递到不可伪造 mailbox)
    pub parent: Option<CapRef>, // 衰减派生链,供撤销级联
}

/// 一个会话:独立的能力 registry + 会话密钥。
pub struct Session {
    pub key: String,
    caps: HashMap<CapRef, Cap>,
    audit: Vec<AuditEvent>,
    sink: Option<Arc<Mutex<audit::AuditSink>>>, // 可选:append-only 持久化 + 尾截 anchor
    bootstrap: Option<CapRef>,                  // guest 的注入 workspace 根 cap(BOOTSTRAP 取)
    audit_broken: bool,                         // 持久审计写失败 -> fail-closed
    exec_policy: os::SandboxPolicy,             // exec 子进程身份/资源策略
    mailboxes: HashMap<String, Vec<PostedMsg>>, // MessageCap 的不可伪造 mailbox -> 已投递消息
    l5: policy::PolicyEngine,                   // L5 策略引擎(默认 allow_all)
    consent: Option<Arc<Mutex<policy::ConsentLedger>>>, // JIT consent 账本(服务内跨会话共享)
    mitigation_reduced: bool, // E1:主体处于降低安全缓解状态 -> 结构上不得持有任何网络/外发能力
}

type R<T> = Result<T, String>;

impl Session {
    pub fn new() -> Session {
        Session {
            key: rand_hex(16),
            caps: HashMap::new(),
            audit: Vec::new(),
            sink: None,
            bootstrap: None,
            audit_broken: false,
            exec_policy: os::SandboxPolicy::default_limits(),
            mailboxes: HashMap::new(),
            l5: policy::PolicyEngine::allow_all(),
            consent: None,
            mitigation_reduced: false,
        }
    }

    /// E1 — mitigation-coupled egress(Broker 不变量,不经 L5 策略,不可配置绕过)。
    /// 置 `reduced=true`(拒答分类器关闭 / 安全缓解降低的评测运行)时:立即级联撤销本会话
    /// 已持有的全部 http / message 能力,且此后 `grant_http` 无条件拒绝。恢复 `false` 为控制面动作,入审计链。
    pub fn set_mitigation_reduced(&mut self, reduced: bool) {
        self.mitigation_reduced = reduced;
        if reduced {
            let egress: Vec<CapRef> = self
                .caps
                .iter()
                .filter(|(_, c)| !c.revoked && (c.kind == "http" || c.kind == "message"))
                .map(|(r, _)| r.clone())
                .collect();
            for r in egress {
                let _ = self.revoke(&r);
            }
            self.audit("mitigation", "reduced: egress caps revoked", "allow");
        } else {
            self.audit("mitigation", "full", "allow");
        }
    }

    /// 配置 L5 策略引擎(对高风险 verb 要求 JIT consent 或直接拒绝)。
    pub fn set_policy(&mut self, p: policy::PolicyEngine) {
        self.l5 = p;
    }

    /// 注入服务内共享的 JIT consent 账本(控制面批准、请求方重放)。
    pub fn set_consent(&mut self, ledger: Arc<Mutex<policy::ConsentLedger>>) {
        self.consent = Some(ledger);
    }

    /// L5 闸:动作执行前调用。Allow→放行;Deny→拒;Prompt→查/登记 JIT consent。
    /// fail-closed:要求 Prompt 但无 consent 账本 → 拒绝(不静默放行)。
    ///
    /// **requester / approver 视图分离(newton a2d306ff)**:
    /// - `detail` = 完整审批摘要(argv/env/cwd 等,**可能含 CommandCap 的 env 凭据**)→ **只**存进 ledger,
    ///   仅 control 面经 `consent_describe`/`consent_list` 可读。
    /// - `hint` = 给**触发动作的 requester**(可能是不可信方)的非敏感提示 —— 只回 verb + cap 短 id,
    ///   **绝不含 env/payload**。否则 requester 只要触发一次 Prompt(未获批、未执行)就能读走 env。
    fn gate(&mut self, verb: &str, sig: &str, hint: &str, detail: &str) -> R<()> {
        use policy::{ConsentOutcome, Decision};
        match self.l5.decide(verb) {
            Decision::Allow => Ok(()),
            Decision::Deny => {
                self.audit("policy.deny", sig, "deny");
                Err(format!("L5 策略拒绝动作 {}", verb))
            }
            Decision::Prompt => {
                let ledger = self
                    .consent
                    .clone()
                    .ok_or_else(|| "L5 需 JIT consent 但无 consent 账本,fail-closed 拒绝".to_string())?;
                // detail(含敏感)只入 ledger(control-only 可读);requester 只得 id + benign hint。
                let outcome = ledger.lock().unwrap().request_or_check(sig, &self.key, detail);
                match outcome {
                    ConsentOutcome::Approved => {
                        self.audit("policy.consent", sig, "approved");
                        Ok(())
                    }
                    ConsentOutcome::Denied => {
                        self.audit("policy.consent", sig, "denied");
                        Err(format!("JIT consent 被拒:{}", verb))
                    }
                    ConsentOutcome::Pending(id) => {
                        self.audit("policy.consent", &format!("{} id={}", sig, id), "pending");
                        Err(format!("{}\t{}\t{}", policy::CONSENT_REQUIRED, id, hint))
                    }
                }
            }
        }
    }

    /// 控制面读取一个待决 consent 请求的完整审批详情(argv/env/cwd)。**含敏感,control-only**。
    pub fn consent_describe(&self, id: &str) -> R<String> {
        let ledger = self.consent.as_ref().ok_or("无 consent 账本")?;
        ledger.lock().unwrap().describe(id).ok_or_else(|| format!("consent {} 不存在", id))
    }

    /// 控制面列出所有待决 consent 请求 (id, 发起会话, 完整详情)。**含敏感,control-only**。
    pub fn consent_list(&self) -> Vec<(String, String, String)> {
        match &self.consent {
            Some(l) => l.lock().unwrap().list_pending(),
            None => Vec::new(),
        }
    }

    /// 构造动作签名:域分隔 + **长度定界**每个字段,消除字段边界歧义(`a|bc` vs `ab|c`),
    /// 再取 sha256。所有**影响副作用的规范化参数**都必须进来 —— 否则批准 benign 动作后可
    /// 替换 payload 重放放行(action substitution bypass,newton e6b08520)。
    fn action_sig(parts: &[&str]) -> String {
        let mut s = String::from("capsig:v1");
        for p in parts {
            s.push('|');
            s.push_str(&p.len().to_string());
            s.push(':');
            s.push_str(p);
        }
        sha256::sha256_hex(s.as_bytes())
    }

    /// 控制面批准一个待决 JIT consent 请求(按 id)。返回人类摘要。
    pub fn consent_approve(&mut self, id: &str) -> R<String> {
        let ledger = self.consent.clone().ok_or("无 consent 账本")?;
        let r = ledger.lock().unwrap().approve(id);
        self.audit("consent.approve", id, if r.is_ok() { "allow" } else { "deny" });
        r
    }

    /// 控制面拒绝一个待决 JIT consent 请求(按 id)。
    pub fn consent_deny(&mut self, id: &str) -> R<String> {
        let ledger = self.consent.clone().ok_or("无 consent 账本")?;
        let r = ledger.lock().unwrap().deny(id);
        self.audit("consent.deny", id, if r.is_ok() { "allow" } else { "deny" });
        r
    }

    /// 配置 exec 子进程的沙箱策略(uid/gid drop + rlimits)。
    pub fn set_exec_policy(&mut self, p: os::SandboxPolicy) {
        self.exec_policy = p;
    }

    /// 带持久化审计 sink 的会话(服务端多连接可共享同一 sink)。
    pub fn with_sink(sink: Arc<Mutex<audit::AuditSink>>) -> Session {
        let mut s = Session::new();
        s.sink = Some(sink);
        s
    }

    /// 由服务端(可信侧)在会话创建时注入一个 workspace 根 DirCap 作为 guest 的初始 authority。
    /// guest wire 无 mint verb,只能 BOOTSTRAP 取这个根再 derive/invoke。
    pub fn set_bootstrap(&mut self, workspace: &str) {
        // 打不开 workspace 则无 bootstrap(BOOTSTRAP 将 fail),不产生不可用 cap
        self.bootstrap = self
            .grant_dir(workspace, vec![Op::Read, Op::List], Taint::Project)
            .ok();
    }

    /// 一次性取出预注入的 workspace 根 ref;第二次调用报错(唯一、一次性,newton 边界)。
    pub fn take_bootstrap(&mut self) -> R<CapRef> {
        self.bootstrap
            .take()
            .ok_or_else(|| "BOOTSTRAP 已被消费或不可用(guest 无预注入根)".to_string())
    }

    /// 审计健康:持久 sink 曾写失败则不健康,敏感操作应 fail-closed 拒绝。
    fn ensure_audit_ok(&self) -> R<()> {
        if self.audit_broken {
            Err("审计 sink 写失败,fail-closed 拒绝后续敏感操作".into())
        } else {
            Ok(())
        }
    }

    fn insert(&mut self, cap: Cap) -> CapRef {
        let id = cap.id.clone();
        self.caps.insert(id.clone(), cap);
        id
    }

    // ---- 审计 hash-chain ----

    /// 记一条审计事件。返回是否**成功持久化**(无 sink 时视为 true)。
    /// 持久 sink 写失败 -> 置 audit_broken 并返回 false,调用方据此把本次操作 fail-closed。
    fn audit(&mut self, op: &str, detail: &str, dec: &str) -> bool {
        let seq = self.audit.len() as u64;
        let prev = self
            .audit
            .last()
            .map(|e| e.hash.clone())
            .unwrap_or_else(|| "GENESIS".into());
        // 先规范化(去 tab/换行,保证单行且与持久化格式一致),再算 hash —— 内存链与持久链一致
        let op_c = op.replace(['\t', '\n'], " ");
        let detail_c = detail.replace(['\t', '\n'], " ");
        let dec_c = dec.replace(['\t', '\n'], " ");
        let content = format!("{}|{}|{}|{}|{}", seq, op_c, detail_c, dec_c, prev);
        let hash = sha256::sha256_hex(content.as_bytes());
        // 会话内 in-mem 链(供 verify_audit / AUDIT dump);持久化交给全局 sink。
        self.audit.push(AuditEvent {
            seq,
            op: op_c.clone(),
            detail: detail_c.clone(),
            decision: dec_c.clone(),
            prev,
            hash,
        });
        if let Some(s) = &self.sink {
            // 全局链(跨会话连续)在 sink 锁内分配 seq/prev 并 append;写 session 身份。
            if s.lock().unwrap().record(&self.key, &op_c, &detail_c, &dec_c).is_err() {
                self.audit_broken = true;
                return false; // 持久审计失败 -> 调用方 fail-closed
            }
        }
        true
    }

    pub fn audit_log(&self) -> &[AuditEvent] {
        &self.audit
    }

    /// 重算 hash-chain,验证审计未被篡改。
    pub fn verify_audit(&self) -> bool {
        let mut prev = String::from("GENESIS");
        for (i, e) in self.audit.iter().enumerate() {
            if e.seq != i as u64 || e.prev != prev {
                return false;
            }
            let content = format!("{}|{}|{}|{}|{}", e.seq, e.op, e.detail, e.decision, e.prev);
            if sha256::sha256_hex(content.as_bytes()) != e.hash {
                return false;
            }
            prev = e.hash.clone();
        }
        true
    }

    /// 活性:存在、未撤销、且祖先链上无已撤销节点(撤销级联的基础)。
    fn is_active(&self, r: &str) -> bool {
        match self.caps.get(r) {
            None => false,
            Some(c) => {
                !c.revoked
                    && match &c.parent {
                        Some(p) => self.is_active(p),
                        None => true,
                    }
            }
        }
    }

    fn get_active(&self, r: &str) -> R<&Cap> {
        self.ensure_audit_ok()?; // 审计故障 -> fail-closed(读/写/exec/derive 全走这里)
        if !self.is_active(r) {
            return Err(format!("cap {} 无效/已撤销(ENOTCAPABLE)", short(r)));
        }
        self.caps
            .get(r)
            .ok_or_else(|| format!("cap {} 未知(脱离 registry 上下文不可调用)", short(r)))
    }

    // ---- MINT / GRANT ----

    pub fn grant_dir(&mut self, root: &str, ops: Vec<Op>, taint: Taint) -> R<CapRef> {
        // 授予时可信打开 root 得到稳定 fd;打不开则 fail grant(不产生无 fd 的“已授予”能力,
        // 避免 allow 审计/describe 与不可用 cap 的状态分叉,newton follow-up #1)。
        let fd = os::open_dir_fd(root)?;
        let cap = Cap {
            id: format!("cap_{}", rand_hex(16)),
            kind: "dir",
            revoked: false,
            root: root.to_string(),
            ops,
            taint,
            name: String::new(),
            argv: vec![],
            env: vec![],
            dir_fd: Some(Arc::new(fd)),
            http: None,
            msg: None,
            parent: None,
        };
        let id = self.insert(cap);
        self.audit("grant_dir", &format!("{} root={} taint={}", short(&id), root, taint.as_str()), "allow");
        Ok(id)
    }

    pub fn grant_sink(&mut self, name: &str) -> CapRef {
        let cap = Cap {
            id: format!("cap_{}", rand_hex(16)),
            kind: "sink",
            revoked: false,
            root: String::new(),
            ops: vec![],
            taint: Taint::Green,
            name: name.to_string(),
            argv: vec![],
            env: vec![],
            dir_fd: None,
            http: None,
            msg: None,
            parent: None,
        };
        let id = self.insert(cap);
        self.audit("grant_sink", &format!("{} {}", short(&id), name), "allow");
        id
    }

    // ---- MessageCap:向不可伪造 mailbox 投递的能力(CapTP 式的"引用即授权")----

    /// 铸造一个 MessageCap:新建不可伪造 mailbox,返回 **owner facet(读+投递)**。
    /// 语义明确:owner facet 既可 `mailbox_read` 也可 `post`(拥有者对自有 mailbox 的完整权);
    /// 委托给他人时用 `derive_msg_*` 派生**只投递**的衰减 facet(can_receive=false),严格分离。
    ///
    /// ⚠ 能力模型注意(newton):owner ref 是"读 + 字面投递"的完整权;把**这个 ref 本身**交给
    /// 另一 principal 等于故意转移全部权限。跨 principal 使用**必须只给派生的只投递 facet**,
    /// 绝不外传 owner ref —— 否则对方可读你的 mailbox 并以 Green 字面投递。
    pub fn grant_message(&mut self, recipient: &str) -> CapRef {
        let mailbox = format!("mbox_{}", rand_hex(16)); // 不可伪造:持有者无法猜到别的 mailbox
        self.mailboxes.insert(mailbox.clone(), Vec::new());
        let cap = Cap {
            id: format!("cap_{}", rand_hex(16)),
            kind: "message",
            revoked: false,
            root: String::new(),
            ops: vec![],
            taint: Taint::Green,
            name: recipient.to_string(),
            argv: vec![],
            env: vec![],
            dir_fd: None,
            http: None,
            msg: Some(MsgSpec { mailbox, subject_prefix: String::new(), one_shot: false, can_receive: true }),
            parent: None,
        };
        let id = self.insert(cap);
        self.audit("grant_message", &format!("{} to={}", short(&id), recipient), "allow");
        id
    }

    /// 衰减派生:限定主题前缀(designation 收紧 authority),得到**只投递**子 facet。
    /// 前缀单调收紧:子的前缀 = 父前缀 + 追加段;派生本身也丢弃 can_receive。
    pub fn derive_msg_prefix(&mut self, r: &str, add_prefix: &str) -> R<CapRef> {
        let (mailbox, prefix) = {
            let c = self.get_active(r)?;
            let m = c.msg.as_ref().ok_or_else(|| format!("cap {} 不是 message", short(r)))?;
            (m.mailbox.clone(), format!("{}{}", m.subject_prefix, add_prefix))
        };
        Ok(self.insert_msg_facet(r, mailbox, prefix, false))
    }

    /// 衰减派生:单次投递 facet(one_shot;投递后自动失效)。
    pub fn derive_msg_oneshot(&mut self, r: &str) -> R<CapRef> {
        let (mailbox, prefix) = {
            let c = self.get_active(r)?;
            let m = c.msg.as_ref().ok_or_else(|| format!("cap {} 不是 message", short(r)))?;
            (m.mailbox.clone(), m.subject_prefix.clone())
        };
        Ok(self.insert_msg_facet_oneshot(r, mailbox, prefix))
    }

    fn insert_msg_facet(&mut self, parent: &str, mailbox: String, prefix: String, one_shot: bool) -> CapRef {
        let cap = Cap {
            id: format!("cap_{}", rand_hex(16)),
            kind: "message",
            revoked: false,
            root: String::new(),
            ops: vec![],
            taint: Taint::Green,
            name: String::new(),
            argv: vec![],
            env: vec![],
            dir_fd: None,
            http: None,
            // 衰减 facet:can_receive=false(不能读 mailbox),只能投递
            msg: Some(MsgSpec { mailbox, subject_prefix: prefix, one_shot, can_receive: false }),
            parent: Some(parent.to_string()),
        };
        let id = self.insert(cap);
        self.audit("derive_message", &short(&id), "allow");
        id
    }

    fn insert_msg_facet_oneshot(&mut self, parent: &str, mailbox: String, prefix: String) -> CapRef {
        self.insert_msg_facet(parent, mailbox, prefix, true)
    }

    /// 投递一条**字面文本**:taint 由服务端固定为 Green —— wire 调用方**不能命名 taint**。
    ///
    /// 关键(newton 结构性课题):字面投递**只允许 owner facet**(can_receive)。委托出去的
    /// 只投递 facet **禁止字面投递** —— 否则不可信持有者可"read(secret) → post(literal 复制的字节)"
    /// 把 secret 洗成 green 外发(客户端侧的知识无法保住 taint 不变量)。委托方只能 `post_from`
    /// (由 broker 读源并判定 taint)。owner 投递进的是**自己的** mailbox(自己是唯一收件人,
    /// 派生从不授出 can_receive),不构成跨边界外发,故字面允许。
    pub fn post(&mut self, r: &str, subject: &str, body: &str) -> R<()> {
        // 签名**必须绑定 body**(否则批准 benign 内容后可替换 body 重放放行)。
        let body_hash = sha256::sha256_hex(body.as_bytes());
        let hint = format!("需审批 post on MessageCap {}(详情见 control CONSENT_DESCRIBE)", short(r));
        let detail = format!("投递 {} subj={} body#{}", short(r), safe_display(subject), &body_hash[..12]);
        self.gate("post", &Self::action_sig(&["post", r, subject, &body_hash]), &hint, &detail)?;
        let d = format!("{} subj={} src=literal", short(r), subject);
        if !self.audit("post.intent", &d, "attempt") {
            return Err("post 前置审计失败,fail-closed 不投递".into());
        }
        let res = self.post_literal_owner_only(r, subject, body);
        self.audit("post.result", &d, &decision(&res));
        res
    }

    fn post_literal_owner_only(&mut self, r: &str, subject: &str, body: &str) -> R<()> {
        {
            let c = self.get_active(r)?;
            let m = c.msg.as_ref().ok_or_else(|| format!("cap {} 不是 message", short(r)))?;
            if !m.can_receive {
                return Err(format!(
                    "委托(只投递)facet {} 禁止字面投递(防 taint 洗白);请用 post_from 由 broker 判定 taint",
                    short(r)
                ));
            }
        }
        // owner 投递进自有 mailbox:服务端固定 Green(不接受 wire taint)。
        self.post_bytes(r, subject, Taint::Green, body)
    }

    /// 转发投递:从源 DirCap 读取内容,**taint 由服务端按源判定**(secret 路径 → Secret),
    /// 再走 IFC 闸 —— 即"消息体由 broker 操作产出并携带不可变 taint"。Secret → 拒(不得外发)。
    pub fn post_from(&mut self, r: &str, subject: &str, src: &str, rel: &str) -> R<()> {
        // 签名**必须绑定 subject**(否则批准某主题后可改主题重放放行)+ src + rel。
        let hint = format!("需审批 post_from on MessageCap {}(详情见 control CONSENT_DESCRIBE)", short(r));
        let detail = format!("转发投递 {} subj={} <- {} {}", short(r), safe_display(subject), short(src), safe_display(rel));
        self.gate("post_from", &Self::action_sig(&["post_from", r, subject, src, rel]), &hint, &detail)?;
        let d = format!("{} subj={} src={} {}", short(r), subject, short(src), rel);
        if !self.audit("post.intent", &d, "attempt") {
            return Err("post 前置审计失败,fail-closed 不投递".into());
        }
        // read_i 内部无审计;taint 由服务端 read 逻辑决定(secret 路径升级 Secret)。
        let res = self
            .read_i(src, rel)
            .and_then(|(taint, bytes)| {
                let body = String::from_utf8_lossy(&bytes).into_owned();
                self.post_bytes(r, subject, taint, &body)
            });
        self.audit("post.result", &d, &decision(&res));
        res
    }

    /// 共享投递核:facet 校验 + IFC(Secret 拒)+ 主题命名空间衰减 + one_shot 自撤。
    /// `taint` 只由**服务端**产出(post=Green / post_from=read 判定),绝不来自 wire。
    fn post_bytes(&mut self, r: &str, subject: &str, taint: Taint, body: &str) -> R<()> {
        let (mailbox, one_shot) = {
            let c = self.get_active(r)?;
            let m = c.msg.as_ref().ok_or_else(|| format!("cap {} 不是 message", short(r)))?;
            if taint.is_sensitive() {
                return Err(format!(
                    "IFC violation: secret 污点数据不能经 MessageCap {} 外发. next: declassify.",
                    short(r)
                ));
            }
            if !subject.starts_with(&m.subject_prefix) {
                return Err(format!(
                    "衰减违规:subject {:?} 不在该 facet 的主题命名空间 {:?} 内",
                    subject, m.subject_prefix
                ));
            }
            (m.mailbox.clone(), m.one_shot)
        };
        let from = self.key.clone();
        self.mailboxes
            .get_mut(&mailbox)
            .ok_or_else(|| "mailbox 不存在(已被回收)".to_string())?
            .push(PostedMsg { subject: subject.to_string(), body: body.to_string(), taint, from_session: from });
        if one_shot {
            // 单次:投递后自动失效(不影响其它 facet / owner)
            if let Some(c) = self.caps.get_mut(r) {
                c.revoked = true;
            }
        }
        Ok(())
    }

    /// 读 mailbox —— 只有收件 facet(can_receive)可读。返回 (subject, taint, body) 列表。
    pub fn mailbox_read(&mut self, r: &str) -> R<Vec<(String, Taint, String)>> {
        let mailbox = {
            let c = self.get_active(r)?;
            let m = c.msg.as_ref().ok_or_else(|| format!("cap {} 不是 message", short(r)))?;
            if !m.can_receive {
                return Err(format!("cap {} 是只投递 facet,无收件权限", short(r)));
            }
            m.mailbox.clone()
        };
        let out: Vec<(String, Taint, String)> = self
            .mailboxes
            .get(&mailbox)
            .map(|v| v.iter().map(|p| (p.subject.clone(), p.taint, p.body.clone())).collect())
            .unwrap_or_default();
        // 与 read/list 一致:披露 mailbox 内容若不能持久审计 → fail-closed,不返回任何消息体。
        if !self.audit("mailbox_read", &short(r), "allow") {
            return Err("mailbox_read 未能持久审计,fail-closed 拒绝披露收件箱".into());
        }
        Ok(out)
    }

    pub fn grant_command(&mut self, cwd_ref: &str, argv: Vec<String>) -> R<CapRef> {
        let (cwd, cwd_fd) = {
            let d = self.get_active(cwd_ref)?;
            if d.kind != "dir" {
                return Err("grant command 的 cwd 必须是 DirCap".into());
            }
            // 复用 cwd DirCap 的稳定目录 fd(exec 时 fchdir 到它,防 cwd 路径 swap)
            (d.root.clone(), d.dir_fd.clone())
        };
        // 收紧 env(newton):只给 PATH(execvp 需要);不设不存在的 HOME、不带 locale/loader/凭据 env。
        let env = vec!["PATH=/usr/bin:/bin:/usr/local/bin".to_string()];
        let name = argv.join(" ");
        let cap = Cap {
            id: format!("cap_{}", rand_hex(16)),
            kind: "command",
            revoked: false,
            root: cwd,
            ops: vec![Op::Exec],
            taint: Taint::Yellow,
            name,
            argv: argv.clone(),
            env,
            dir_fd: cwd_fd, // cwd 的稳定目录 fd(exec 时 fchdir + Landlock anchor)
            http: None,
            msg: None,
            parent: None,
        };
        let id = self.insert(cap);
        self.audit("grant_cmd", &format!("{} [{}]", short(&id), argv.join(" ")), "allow");
        Ok(id)
    }

    /// grant HttpCap:origin(scheme+host+port)+ method/path 白名单 + 字节上限(control-only mint)。
    pub fn grant_http(
        &mut self,
        scheme: &str,
        host: &str,
        port: u16,
        methods: Vec<String>,
        paths: Vec<String>,
        max_bytes: usize,
    ) -> R<CapRef> {
        if self.mitigation_reduced {
            // E1:降低缓解的主体结构上拿不到网络能力;在策略引擎之前拒,无配置可放行
            self.audit("grant_http", host, "deny:mitigation_reduced");
            return Err("mitigation reduced: subject cannot hold network authority (E1)".into());
        }
        net::valid_host(host)?; // host 必须是合法 DNS name/IP literal,无 control/注入
        let spec = HttpSpec {
            scheme: scheme.to_string(),
            host: host.to_string(),
            port,
            methods,
            paths,
            max_bytes,
        };
        let cap = Cap {
            id: format!("cap_{}", rand_hex(16)),
            kind: "http",
            revoked: false,
            root: format!("{}://{}:{}", scheme, host, port),
            ops: vec![],
            taint: Taint::External,
            name: String::new(),
            argv: vec![],
            env: vec![],
            dir_fd: None,
            http: Some(spec),
            msg: None,
            parent: None,
        };
        let id = self.insert(cap);
        self.audit("grant_http", &format!("{} {}://{}:{}", short(&id), scheme, host, port), "allow");
        Ok(id)
    }

    /// HttpCap GET:method/path 白名单 + SSRF/metadata/rebind 检查 + 连接预解析 IP;
    /// 响应 taint 由服务端打(External);有外部副作用 → 执行前预写 durable intent。
    pub fn http_get(&mut self, r: &str, path: &str) -> R<(Taint, Vec<u8>)> {
        // L5 闸:出网高风险,按策略可要求 JIT consent(先于 intent 审计)。
        // 签名绑定 cap ref + 请求 path(side effect 由二者决定)。
        let hint = format!("需审批 http_get on HttpCap {}(详情见 control CONSENT_DESCRIBE)", short(r));
        let detail = format!("HTTP GET {} path={}", short(r), safe_display(path));
        self.gate("http_get", &Self::action_sig(&["http_get", r, path]), &hint, &detail)?;
        let d = format!("{} GET {}", short(r), path);
        if !self.audit("http.intent", &d, "attempt") {
            return Err("http 前置审计失败,fail-closed 不请求".into());
        }
        let res = self.http_get_i(r, path);
        self.audit("http.result", &d, &decision(&res));
        res
    }
    fn http_get_i(&self, r: &str, path: &str) -> R<(Taint, Vec<u8>)> {
        let c = self.get_active(r)?;
        let spec = c.http.as_ref().ok_or("cap 不是 HttpCap")?;
        // 规范化 request-target:拒注入 + %HH + dot-segment 归并;canonical 同时用于白名单与请求行
        let target = net::canonical_request_target(path)?;
        let match_path = target.split('?').next().unwrap_or("/");
        if !spec.methods.iter().any(|m| m == "GET") {
            return Err("HttpCap 未授权 GET".into());
        }
        if !spec.paths.iter().any(|p| net::path_matches(p, match_path)) {
            return Err(format!("canonical path {} 不在 HttpCap allowlist", match_path));
        }
        if spec.scheme != "http" {
            return Err("目前仅支持 http://(https 需 TLS,后续)".into());
        }
        let addrs = net::resolve_checked(&spec.host, spec.port)?; // metadata/private/rebind 恒拒
        // 规范 authority:IPv6 literal 加方括号;非默认端口带 port
        let hostpart = if spec.host.contains(':') && !spec.host.starts_with('[') {
            format!("[{}]", spec.host)
        } else {
            spec.host.clone()
        };
        let authority = if spec.port == 80 {
            hostpart
        } else {
            format!("{}:{}", hostpart, spec.port)
        };
        let resp = net::fetch_get(addrs[0], &authority, &target, spec.max_bytes)?; // 连预解析 IP,固定 Host,写 canonical target
        Ok((Taint::External, resp.body)) // 网络响应服务端标 External
    }

    // ---- ATTENUATE (衰减,单向,parent 指向原 cap) ----

    pub fn derive_sub(&mut self, r: &str, seg: &str) -> R<CapRef> {
        let (root, ops, taint, child_fd) = {
            let c = self.get_active(r)?;
            if c.kind != "dir" {
                return Err("sub 只适用于 DirCap".into());
            }
            let pfd = c.dir_fd.as_ref().ok_or("DirCap 无 root fd")?;
            // 从父 fd 原子派生子目录 fd(RESOLVE_BENEATH,swap 无效)
            let child = os::derive_dir_at(pfd.as_raw_fd(), seg)?;
            (safe_join(&c.root, seg)?, c.ops.clone(), c.taint, child)
        };
        let cap = Cap {
            id: format!("cap_{}", rand_hex(16)),
            kind: "dir",
            revoked: false,
            root,
            ops,
            taint,
            name: String::new(),
            argv: vec![],
            env: vec![],
            dir_fd: Some(Arc::new(child_fd)),
            http: None,
            msg: None,
            parent: Some(r.to_string()),
        };
        let id = self.insert(cap);
        self.audit("derive_sub", &format!("{} <- {} /{}", short(&id), short(r), seg), "allow");
        Ok(id)
    }

    pub fn derive_readonly(&mut self, r: &str) -> R<CapRef> {
        let (root, taint, kind, dir_fd) = {
            let c = self.get_active(r)?;
            (c.root.clone(), c.taint, c.kind, c.dir_fd.clone())
        };
        let cap = Cap {
            id: format!("cap_{}", rand_hex(16)),
            kind,
            revoked: false,
            root,
            ops: vec![Op::Read, Op::List],
            taint,
            name: String::new(),
            argv: vec![],
            env: vec![],
            dir_fd, // 只读:共享同一 root fd
            http: None,
            msg: None,
            parent: Some(r.to_string()),
        };
        let id = self.insert(cap);
        self.audit("derive_readonly", &format!("{} <- {}", short(&id), short(r)), "allow");
        Ok(id)
    }

    // ---- USE(&mut self:每次调用记审计)----

    pub fn read(&mut self, r: &str, rel: &str) -> R<(Taint, Vec<u8>)> {
        let res = self.read_i(r, rel);
        // 无外部副作用:执行后审计;若成功结果未能持久审计 -> 不把数据返回给调用方(fail-closed)。
        let audited = self.audit("read", &format!("{} {}", short(r), rel), &decision(&res));
        if res.is_ok() && !audited {
            return Err("read 结果未能持久审计,fail-closed 拒绝返回".into());
        }
        res
    }
    fn read_i(&self, r: &str, rel: &str) -> R<(Taint, Vec<u8>)> {
        let c = self.get_active(r)?;
        if !c.ops.contains(&Op::Read) {
            return Err(format!("DirCap {} 无 Read", short(r)));
        }
        let _ = safe_join(&c.root, rel)?; // 字符串层第一道闸(abs/..)
        let fd = c.dir_fd.as_ref().ok_or("DirCap 无 root fd(打开失败)")?;
        let data = os::read_at(fd.as_raw_fd(), rel)?; // 以持有 fd 为 anchor,openat2 原子;root 路径 swap 无效
        // 服务端污点:敏感路径的读一律升级为 Secret,不信 cap 自带的 Project(防 under-report 外泄)。
        let taint = if is_secret_path(&format!("{}/{}", c.root, rel)) {
            Taint::Secret
        } else {
            c.taint
        };
        Ok((taint, data))
    }

    pub fn list(&mut self, r: &str, rel: &str) -> R<Vec<u8>> {
        let res = self.list_i(r, rel);
        let audited = self.audit("list", &format!("{} {}", short(r), rel), &decision(&res));
        if res.is_ok() && !audited {
            return Err("list 结果未能持久审计,fail-closed 拒绝返回".into());
        }
        res
    }
    fn list_i(&self, r: &str, rel: &str) -> R<Vec<u8>> {
        let c = self.get_active(r)?;
        if !c.ops.contains(&Op::List) {
            return Err(format!("DirCap {} 无 List", short(r)));
        }
        let _ = safe_join(&c.root, rel)?; // 字符串层第一道闸(abs/..)
        let fd = c.dir_fd.as_ref().ok_or("DirCap 无 root fd(打开失败)")?;
        let names = os::list_at(fd.as_raw_fd(), rel)?; // 以持有 fd 为 anchor,openat2 + getdents64
        Ok(names.join("\n").into_bytes())
    }

    pub fn exec(&mut self, r: &str) -> R<Vec<u8>> {
        // L5 闸:exec 高风险,按策略可要求 JIT consent 或直接拒绝(先于 intent 审计)。
        // 签名绑定 cap ref —— argv/env 由该 cap 不可变决定,cap id 即完整指名。
        // 审批 summary 显示**规范化 + 转义 + 限长**的命令身份(argv/cwd),供人类核对(newton 建议)。
        // detail(control-only,可能含 env 凭据):无歧义 argv + env + cwd,供审批人核对。
        let detail = match self.caps.get(r) {
            Some(c) => format!(
                "执行命令 {} cwd={} argv=[{}] env=[{}]",
                short(r),
                safe_display(&c.root),
                canon_list(&c.argv, 240),
                canon_list(&c.env, 160),
            ),
            None => format!("执行命令 CommandCap {}", short(r)),
        };
        // hint(给 requester,非敏感):只 verb + cap 短 id,绝不含 argv/env。
        let hint = format!("需审批 exec on CommandCap {}(详情见 control CONSENT_DESCRIBE)", short(r));
        self.gate("exec", &Self::action_sig(&["exec", r]), &hint, &detail)?;
        // 有外部副作用:执行前预写 durable intent;intent 审计失败则不执行(newton P1#2)。
        if !self.audit("exec.intent", &short(r), "attempt") {
            return Err("exec 前置审计失败,fail-closed 不执行".into());
        }
        let res = self.exec_i(r);
        // 结果审计(命令已执行;此处失败只置 audit_broken,intent 已 durable 记录,问责可追)
        self.audit("exec.result", &short(r), &decision(&res));
        res
    }
    fn exec_i(&self, r: &str) -> R<Vec<u8>> {
        let c = self.get_active(r)?;
        if !c.ops.contains(&Op::Exec) {
            return Err(format!("CommandCap {} 无 Exec", short(r)));
        }
        if c.argv.is_empty() {
            return Err("CommandCap argv 为空".into());
        }
        let mut cmd = Command::new(&c.argv[0]);
        cmd.args(&c.argv[1..]).env_clear();
        for e in &c.env {
            if let Some((k, v)) = e.split_once('=') {
                cmd.env(k, v);
            }
        }
        // L1 沙箱:fork 后、execve 前施加 Landlock(fs 限 cwd+系统只读)+ fchdir 到持有的 cwd fd。
        match &c.dir_fd {
            Some(fd) => {
                let raw = fd.as_raw_fd();
                let policy = self.exec_policy;
                use std::os::unix::process::CommandExt;
                unsafe {
                    cmd.pre_exec(move || os::exec_sandbox(raw, &policy));
                }
            }
            None => {
                // 无 cwd fd:不进沙箱且无稳定 cwd -> fail-closed 拒绝(不无沙箱执行)
                return Err("CommandCap 无 cwd fd,fail-closed 拒绝执行".into());
            }
        }
        let out = cmd.output().map_err(|e| format!("exec failed: {}", e))?;
        Ok(out.stdout)
    }

    /// 外发 sink:信息流检查 —— secret 污点数据不能外发(confinement)。
    pub fn send(&mut self, r: &str, taint: Taint, _data: &[u8]) -> R<()> {
        // 有外部副作用(接真实 helper 后):执行前预写 durable intent。
        let d = format!("{} taint={}", short(r), taint.as_str());
        if !self.audit("send.intent", &d, "attempt") {
            return Err("send 前置审计失败,fail-closed 不发送".into());
        }
        let res = self.send_i(r, taint);
        self.audit("send.result", &d, &decision(&res));
        res
    }
    fn send_i(&self, r: &str, taint: Taint) -> R<()> {
        let c = self.get_active(r)?;
        if c.kind != "sink" {
            return Err(format!("cap {} 不是 sink", short(r)));
        }
        if taint.is_sensitive() {
            return Err(format!(
                "IFC violation: secret 污点数据不能流入外发 sink {}({}). next: declassify.",
                short(r),
                c.name
            ));
        }
        Ok(())
    }

    pub fn revoke(&mut self, r: &str) -> R<()> {
        let res = match self.caps.get_mut(r) {
            Some(c) => {
                c.revoked = true;
                Ok(())
            }
            None => Err(format!("cap {} 未知", short(r))),
        };
        self.audit("revoke", &short(r), &decision(&res));
        res
    }

    pub fn describe(&self, r: &str) -> R<String> {
        let c = self
            .caps
            .get(r)
            .ok_or_else(|| format!("cap {} 未知", short(r)))?;
        Ok(format!(
            "<{} {} root={} taint={}{}>",
            short(r),
            c.kind,
            c.root,
            c.taint.as_str(),
            if self.is_active(r) { "" } else { " REVOKED" }
        ))
    }
}

#[cfg(test)]
impl Session {
    /// 白盒:改一条历史事件但不重算后续 hash,用于验证篡改可被检测。
    fn tamper_first_for_test(&mut self) {
        if let Some(e) = self.audit.first_mut() {
            e.detail.push_str("_TAMPERED");
        }
    }
}

fn short(r: &str) -> String {
    if r.len() > 14 {
        format!("{}…", &r[..14])
    } else {
        r.to_string()
    }
}

/// 转义控制字符(换行/tab/等)为 `\xHH`,防审批摘要被伪造/截断/注入。限长兜底。
fn safe_display(s: &str) -> String {
    let mut out = String::new();
    for ch in s.chars() {
        if ch.is_control() {
            out.push_str(&format!("\\x{:02x}", ch as u32 & 0xff));
        } else {
            out.push(ch);
        }
        if out.len() > 160 {
            out.push('…');
            break;
        }
    }
    out
}

/// **无歧义 + 逐字符受限**呈现 argv/env:每段双引号包裹,内部 `"`/`\`/控制字符转义;
/// 边渲染边检查总长,超 `cap` 即停 —— 单个超长元素不会在内存里被完整构造(newton)。
/// 无歧义:`["a b"]` → `"a b"`、`["a","b"]` → `"a" "b"`,审批人不混淆"含空格的一个参数"与"两个参数"。
fn canon_list(items: &[String], cap: usize) -> String {
    if items.is_empty() {
        return "(空)".to_string();
    }
    let mut out = String::new();
    'outer: for (i, it) in items.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        if out.len() >= cap {
            out.push('…');
            break;
        }
        out.push('"');
        for ch in it.chars() {
            // 预留最宽转义(`\xNN`=4)+ 收尾引号(1)的空间,保证严格不超 cap(newton 后续硬化)
            if out.len() + 5 > cap {
                out.push_str("…\""); // 截断标记 + 收尾引号
                break 'outer;
            }
            match ch {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                c if c.is_control() => out.push_str(&format!("\\x{:02x}", c as u32 & 0xff)),
                c => out.push(c),
            }
        }
        out.push('"');
    }
    out
}

/// 解析并约束在能力根内:先做字符串层 abs/.. 拒绝,再 canonicalize(解析所有 symlink)
/// 并验证结果仍在 canonical root 之下 —— 关闭「根内 symlink 指向根外」的越界。
///
/// 注意(诚实标注):canonicalize+containment 有 TOCTOU 残留(检查与打开之间攻击者
/// 若能替换路径组件仍可越界)。原子版需 openat2(RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS),
/// 但当前离线环境无 libc;待引入后升级为原子解析。
pub fn resolve_contained(root: &str, rel: &str) -> R<std::path::PathBuf> {
    let joined = safe_join(root, rel)?;
    let canon = fs::canonicalize(&joined).map_err(|e| format!("resolve failed: {}", e))?;
    let canon_root =
        fs::canonicalize(root).map_err(|e| format!("root resolve failed: {}", e))?;
    if canon.starts_with(&canon_root) {
        Ok(canon)
    } else {
        Err(format!(
            "path escapes capability root via symlink: {} -> {} (root={})",
            rel,
            canon.display(),
            canon_root.display()
        ))
    }
}

/// 路径安全:只接受相对路径,拒绝绝对与 .. 逃逸(deny_parent_escape)。字符串层第一道闸。
pub fn safe_join(root: &str, rel: &str) -> R<String> {
    if rel.starts_with('/') {
        return Err(format!("绝对路径不允许: {}(DirCap root={})", rel, root));
    }
    for part in rel.split('/') {
        if part == ".." {
            return Err(format!("path escapes capability root: {}(root={})", rel, root));
        }
    }
    let cleaned: Vec<&str> = rel.split('/').filter(|p| !p.is_empty() && *p != ".").collect();
    if cleaned.is_empty() {
        Ok(root.to_string())
    } else {
        Ok(format!("{}/{}", root.trim_end_matches('/'), cleaned.join("/")))
    }
}

pub fn parse_ops(csv: &str) -> Vec<Op> {
    csv.split(',')
        .filter_map(|o| match o.trim() {
            "read" => Some(Op::Read),
            "write" => Some(Op::Write),
            "delete" => Some(Op::Delete),
            "list" => Some(Op::List),
            "exec" => Some(Op::Exec),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_workspace() -> String {
        let dir = std::env::temp_dir().join(format!("capbroker_{}", rand_hex(6)));
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(dir.join("main.txt"), b"hello broker").unwrap();
        fs::write(dir.join("src/secret.txt"), b"API_KEY=sk-xyz").unwrap();
        dir.to_string_lossy().into_owned()
    }

    #[test]
    fn grant_read_and_bounds() {
        let root = tmp_workspace();
        let mut s = Session::new();
        let repo = s.grant_dir(&root, parse_ops("read,list"), Taint::Project).unwrap();
        let (t, data) = s.read(&repo, "main.txt").unwrap();
        assert_eq!(t, Taint::Project);
        assert_eq!(&data, b"hello broker");
        assert!(s.read(&repo, "/etc/passwd").is_err());
        assert!(s.read(&repo, "../../etc/passwd").is_err());
    }

    #[test]
    fn attenuate_and_ifc() {
        let root = tmp_workspace();
        let mut s = Session::new();
        let repo = s.grant_dir(&root, parse_ops("read,write,list"), Taint::Project).unwrap();
        let sub = s.derive_sub(&repo, "src").unwrap();
        let ro = s.derive_readonly(&sub).unwrap();
        assert!(s.read(&ro, "secret.txt").is_ok());
        let vault = s.grant_dir(&root, parse_ops("read"), Taint::Secret).unwrap();
        let (t, _) = s.read(&vault, "src/secret.txt").unwrap();
        assert_eq!(t, Taint::Secret);
        let sink = s.grant_sink("https://x.example.com");
        assert!(s.send(&sink, Taint::Project, b"ok").is_ok());
        assert!(s.send(&sink, Taint::Secret, b"leak").is_err());
    }

    #[test]
    fn revoke_cascade() {
        let root = tmp_workspace();
        let mut s = Session::new();
        let repo = s.grant_dir(&root, parse_ops("read,list"), Taint::Project).unwrap();
        let child = s.derive_sub(&repo, "src").unwrap();
        assert!(s.read(&child, "secret.txt").is_ok());
        s.revoke(&repo).unwrap();
        assert!(s.read(&child, "secret.txt").is_err()); // 祖先撤销 -> 级联失效
    }

    #[test]
    fn message_cap_delegation_attenuation_ifc_revoke() {
        let mut s = Session::new();
        // owner 铸 MessageCap(owner facet:读+投递)
        let owner = s.grant_message("agent:newton");

        // owner 可直接投递字面文本(服务端固定 Green)+ 读自己的 mailbox
        s.post(&owner, "hello", "hi newton").unwrap();
        let inbox = s.mailbox_read(&owner).unwrap();
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox[0].0, "hello");
        assert_eq!(inbox[0].1, Taint::Green, "字面投递 taint 必须由服务端定为 Green");

        // 委托:派生只投递 facet,限定主题前缀 "build/"(designation 收紧 authority)
        let delegate = s.derive_msg_prefix(&owner, "build/").unwrap();
        // 该 facet 不能读 mailbox(只投递)
        assert!(s.mailbox_read(&delegate).is_err(), "只投递 facet 不得读收件箱");
        // 委托(只投递)facet **禁止字面投递**(防 taint 洗白);只能 post_from
        assert!(s.post(&delegate, "build/x", "authored").is_err(), "委托 facet 不得字面投递");

        // 委托方只能 post_from(broker 判定 taint):非敏感源 OK,前缀内
        let root = tmp_workspace();
        let vault = s.grant_dir(&root, parse_ops("read,list"), Taint::Project).unwrap();
        s.post_from(&delegate, "build/main", &vault, "main.txt").unwrap();
        // 前缀外投递被拒(衰减:主题命名空间约束)
        assert!(s.post_from(&delegate, "deploy/prod", &vault, "main.txt").is_err(), "越出主题前缀必须被拒");
        // 从 secret 源转发:服务端判 Secret → IFC 拒
        assert!(
            s.post_from(&delegate, "build/exfil", &vault, "src/secret.txt").is_err(),
            "从 secret 源转发投递必须被 IFC 拒(不能洗白 taint)"
        );

        // one_shot(owner 派生的只投递单次 facet):owner 用 post_from 单次
        let once = s.derive_msg_oneshot(&owner).unwrap();
        s.post_from(&once, "ping", &vault, "main.txt").unwrap();
        assert!(s.post_from(&once, "ping", &vault, "main.txt").is_err(), "one_shot 第二次投递必须失效");

        // owner 收件箱现应含:hello + build/main + ping(被拒的不入箱)
        let inbox = s.mailbox_read(&owner).unwrap();
        let subjects: Vec<&str> = inbox.iter().map(|m| m.0.as_str()).collect();
        assert_eq!(subjects, vec!["hello", "build/main", "ping"]);

        // 撤销 owner → 级联:派生 facet 也失效(祖先撤销)
        s.revoke(&owner).unwrap();
        assert!(s.post_from(&delegate, "build/after", &vault, "main.txt").is_err(), "owner 撤销后委托 facet 应级联失效");
    }

    #[test]
    fn message_cap_no_literal_laundering_via_delegated_facet() {
        // newton 结构性回归:read(secret) 得到明文,再 post(literal 复制的字节)必须失败 ——
        // 委托(只投递)facet 禁止字面投递,故客户端侧的 secret 明文无法经字面路径洗成 green 外发。
        let root = tmp_workspace();
        let mut s = Session::new();
        let owner = s.grant_message("agent:collector");
        let delegate = s.derive_msg_prefix(&owner, "").unwrap();

        // 攻击者(持委托 facet)读到 secret 明文
        let vault = s.grant_dir(&root, parse_ops("read,list"), Taint::Project).unwrap();
        let (t, secret_bytes) = s.read(&vault, "src/secret.txt").unwrap();
        assert_eq!(t, Taint::Secret, "secret 路径读应升级为 Secret");
        let copied = String::from_utf8_lossy(&secret_bytes).into_owned();

        // 把复制来的 secret 字节当字面文本投递 —— 必须被拒(委托 facet 无字面投递权)
        assert!(
            s.post(&delegate, "exfil", &copied).is_err(),
            "read(secret)→post(literal 复制字节) 必须失败(委托 facet 禁字面投递,防洗白)"
        );
        // 唯一合法路径是 post_from,由 broker 判定 taint 后 IFC 拒 secret
        assert!(
            s.post_from(&delegate, "exfil", &vault, "src/secret.txt").is_err(),
            "post_from secret 源也必须被 IFC 拒"
        );
        // owner 收件箱应为空(无一条 secret 泄入)
        assert!(s.mailbox_read(&owner).unwrap().is_empty(), "不得有任何 secret 数据入箱");
    }

    #[test]
    fn l5_jit_consent_exec_flow() {
        use policy::{ConsentLedger, PolicyEngine};
        let root = tmp_workspace();
        let ledger = Arc::new(Mutex::new(ConsentLedger::new()));

        // guest 会话:策略要求 exec 需 JIT consent;共享 ledger
        let mut guest = Session::new();
        guest.set_policy(PolicyEngine { prompt_exec: true, ..PolicyEngine::allow_all() });
        guest.set_consent(ledger.clone());
        let cwd = guest.grant_dir(&root, parse_ops("read,list,exec"), Taint::Project).unwrap();
        let cmd = guest.grant_command(&cwd, vec!["/bin/echo".into(), "hi".into()]).unwrap();

        // 首次 exec → consent-required(标记错误 + 登记 pending)
        let e = guest.exec(&cmd).unwrap_err();
        assert!(e.starts_with(policy::CONSENT_REQUIRED), "首次 exec 应要求 consent: {}", e);
        let id = e.split('\t').nth(1).unwrap().to_string();
        assert_eq!(ledger.lock().unwrap().pending_count(), 1);

        // 未批准前重放仍 pending(不放行)
        assert!(guest.exec(&cmd).unwrap_err().starts_with(policy::CONSENT_REQUIRED));

        // 控制面会话(共享同一 ledger)批准
        let mut control = Session::new();
        control.set_consent(ledger.clone());
        assert!(control.consent_approve(&id).is_ok());

        // guest 重放 → 放行并执行(echo 输出 hi)
        let out = guest.exec(&cmd).unwrap();
        assert!(String::from_utf8_lossy(&out).contains("hi"), "批准后 exec 应执行: {:?}", out);

        // 一次性:再 exec 又需新批准
        assert!(guest.exec(&cmd).unwrap_err().starts_with(policy::CONSENT_REQUIRED));
    }

    #[test]
    fn l5_consent_signature_binds_payload_no_substitution() {
        // newton e6b08520:批准 benign 动作后不得替换 payload/subject 重放放行。
        use policy::{ConsentLedger, PolicyEngine};
        let ledger = Arc::new(Mutex::new(ConsentLedger::new()));
        let mut s = Session::new();
        s.set_policy(PolicyEngine { prompt_post: true, ..PolicyEngine::allow_all() });
        s.set_consent(ledger.clone());
        let mut c = Session::new();
        c.set_consent(ledger.clone());
        let owner = s.grant_message("agent:a");

        // post(subject=hi, body=benign) → CONSENT(id A);审批者批准 A
        let ea = s.post(&owner, "hi", "benign").unwrap_err();
        assert!(ea.starts_with(policy::CONSENT_REQUIRED));
        let id_a = ea.split('\t').nth(1).unwrap().to_string();
        c.consent_approve(&id_a).unwrap();
        // 换 **body** 重放 → 必须重新 CONSENT(签名绑定 body,不复用 A 的批准)
        let eb = s.post(&owner, "hi", "MALICIOUS").unwrap_err();
        assert!(eb.starts_with(policy::CONSENT_REQUIRED), "换 body 必须重新 CONSENT: {}", eb);
        // 原 body 重放 → 放行(消费 A)
        assert!(s.post(&owner, "hi", "benign").is_ok(), "原 body 应被批准放行");

        // post_from **subject** 替换同理
        let root = tmp_workspace();
        let vault = s.grant_dir(&root, parse_ops("read,list"), Taint::Project).unwrap();
        let deleg = s.derive_msg_prefix(&owner, "").unwrap();
        let ef = s.post_from(&deleg, "topicA", &vault, "main.txt").unwrap_err();
        assert!(ef.starts_with(policy::CONSENT_REQUIRED));
        let id_f = ef.split('\t').nth(1).unwrap().to_string();
        c.consent_approve(&id_f).unwrap();
        let ef2 = s.post_from(&deleg, "topicB", &vault, "main.txt").unwrap_err();
        assert!(ef2.starts_with(policy::CONSENT_REQUIRED), "换 subject 必须重新 CONSENT: {}", ef2);
        assert!(s.post_from(&deleg, "topicA", &vault, "main.txt").is_ok(), "原 subject 应放行");
    }

    #[test]
    fn l5_exec_summary_unambiguous_argv_and_env() {
        // newton:审批 summary 必须无歧义呈现 argv(区分 ["a b"] vs ["a","b"])+ 呈现 env(影响执行语义)。
        use policy::{ConsentLedger, PolicyEngine};
        let root = tmp_workspace();
        let ledger = Arc::new(Mutex::new(ConsentLedger::new()));
        let mut s = Session::new();
        s.set_policy(PolicyEngine { prompt_exec: true, ..PolicyEngine::allow_all() });
        s.set_consent(ledger.clone());
        let cwd = s.grant_dir(&root, parse_ops("read,list,exec"), Taint::Project).unwrap();
        // argv 含空格参数 + 控制字符;exec 只触发 gate(返回 CONSENT),不真正执行
        let cmd = s
            .grant_command(&cwd, vec!["/bin/echo".into(), "a b".into(), "c\td".into()])
            .unwrap();
        let e = s.exec(&cmd).unwrap_err();
        assert!(e.starts_with(policy::CONSENT_REQUIRED));
        let id = e.splitn(3, '\t').nth(1).unwrap().to_string();
        let hint = e.splitn(3, '\t').nth(2).unwrap().to_string();
        // **requester 视图(hint)**:绝不含 env / argv payload —— 触发 Prompt 不得泄露机密
        assert!(!hint.contains("PATH="), "requester hint 不得泄露 env: {}", hint);
        assert!(!hint.contains("\"a b\""), "requester hint 不得含 argv payload: {}", hint);

        // **approver 视图(control-only consent_describe)**:无歧义 argv + env
        let detail = s.consent_describe(&id).unwrap();
        assert!(detail.contains("\"a b\""), "含空格参数应无歧义引用: {}", detail);
        assert!(!detail.contains("\"a\" \"b\""), "不应把 [\"a b\"] 呈现成两个参数");
        assert!(detail.contains("\"c\\x09d\""), "控制字符应转义: {}", detail);
        assert!(!detail.contains('\t'), "详情内不得有裸 tab");
        assert!(detail.contains("env=[") && detail.contains("PATH="), "detail 须含 env: {}", detail);
    }

    #[test]
    fn l5_deny_and_fail_closed_without_ledger() {
        use policy::PolicyEngine;
        let root = tmp_workspace();
        // deny_exec:直接拒
        let mut s = Session::new();
        s.set_policy(PolicyEngine { deny_exec: true, ..PolicyEngine::allow_all() });
        let cwd = s.grant_dir(&root, parse_ops("read,list,exec"), Taint::Project).unwrap();
        let cmd = s.grant_command(&cwd, vec!["/bin/echo".into()]).unwrap();
        let e = s.exec(&cmd).unwrap_err();
        assert!(e.contains("策略拒绝"), "deny_exec 应直接拒: {}", e);

        // prompt 但无 ledger → fail-closed 拒(不静默放行)
        let mut s2 = Session::new();
        s2.set_policy(PolicyEngine { prompt_exec: true, ..PolicyEngine::allow_all() });
        let cwd2 = s2.grant_dir(&root, parse_ops("read,list,exec"), Taint::Project).unwrap();
        let cmd2 = s2.grant_command(&cwd2, vec!["/bin/echo".into()]).unwrap();
        let e2 = s2.exec(&cmd2).unwrap_err();
        assert!(e2.contains("无 consent 账本"), "无 ledger 时须 fail-closed: {}", e2);
    }

    #[test]
    fn mailbox_read_fail_closed_on_audit_break() {
        // 注入审计故障后,mailbox_read 不得披露任何消息体(与 read/list 一致)。
        let mut s = Session::new();
        let owner = s.grant_message("agent:x");
        s.post(&owner, "hi", "body").unwrap();
        assert!(s.mailbox_read(&owner).is_ok());
        s.audit_broken = true; // 模拟持久审计已损坏
        assert!(s.mailbox_read(&owner).is_err(), "审计故障时披露收件箱必须 fail-closed");
    }

    #[test]
    fn persisted_audit_survives_and_detects_truncation() {
        let dir = std::env::temp_dir().join(format!("capaudit_{}", rand_hex(6)));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("audit.log").to_string_lossy().into_owned();
        let root = tmp_workspace();
        {
            let sink = Arc::new(Mutex::new(audit::AuditSink::open(&log).unwrap()));
            let mut s = Session::with_sink(sink);
            let repo = s.grant_dir(&root, parse_ops("read,list"), Taint::Project).unwrap();
            let _ = s.read(&repo, "main.txt");
            let _ = s.read(&repo, "/etc/passwd"); // deny 也落链
        }
        assert!(audit::verify_persisted(&log).unwrap(), "干净持久链应通过");
        // 尾部截断:删末行 -> anchor 对不上 -> 必被检测
        let content = std::fs::read_to_string(&log).unwrap();
        let mut lines: Vec<&str> = content.lines().collect();
        lines.pop();
        std::fs::write(&log, lines.join("\n") + "\n").unwrap();
        assert!(!audit::verify_persisted(&log).unwrap(), "尾截必须被 anchor 检测到");
    }

    #[test]
    fn shared_sink_global_chain_across_sessions() {
        let dir = std::env::temp_dir().join(format!("capaudit3_{}", rand_hex(6)));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("audit.log").to_string_lossy().into_owned();
        let root = tmp_workspace();
        let sink = Arc::new(Mutex::new(audit::AuditSink::open(&log).unwrap()));
        {
            let mut a = Session::with_sink(sink.clone());
            let ra = a.grant_dir(&root, parse_ops("read"), Taint::Project).unwrap();
            let _ = a.read(&ra, "main.txt");
        }
        {
            let mut b = Session::with_sink(sink.clone()); // 第二会话共享同一 sink
            let rb = b.grant_dir(&root, parse_ops("read"), Taint::Project).unwrap();
            let _ = b.read(&rb, "main.txt");
        }
        // newton P1#1:两会话共享 sink 后,全局链必须仍连续可验证
        assert!(
            audit::verify_persisted(&log).unwrap(),
            "两会话共享 sink 的全局链应连续可验证"
        );
    }

    #[test]
    fn audit_missing_or_corrupt_anchor_fail_closed() {
        let dir = std::env::temp_dir().join(format!("capaudit2_{}", rand_hex(6)));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("audit.log").to_string_lossy().into_owned();
        let root = tmp_workspace();
        {
            let sink = Arc::new(Mutex::new(audit::AuditSink::open(&log).unwrap()));
            let mut s = Session::with_sink(sink);
            let repo = s.grant_dir(&root, parse_ops("read"), Taint::Project).unwrap();
            let _ = s.read(&repo, "main.txt");
        }
        assert!(audit::verify_persisted(&log).unwrap());
        // 删 anchor -> fail-closed(不再 fail-open 报成功)
        std::fs::remove_file(format!("{}.anchor", log)).unwrap();
        assert!(!audit::verify_persisted(&log).unwrap(), "缺失 anchor 必须判失败");
        // 损坏 anchor
        std::fs::write(format!("{}.anchor", log), "garbage").unwrap();
        assert!(!audit::verify_persisted(&log).unwrap(), "畸形 anchor 必须判失败");
    }

    #[test]
    fn open_rejects_inconsistent_anchor() {
        let dir = std::env::temp_dir().join(format!("capaudit4_{}", rand_hex(6)));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("audit.log").to_string_lossy().into_owned();
        let root = tmp_workspace();
        {
            let sink = Arc::new(Mutex::new(audit::AuditSink::open(&log).unwrap()));
            let mut s = Session::with_sink(sink);
            let repo = s.grant_dir(&root, parse_ops("read"), Taint::Project).unwrap();
            let _ = s.read(&repo, "main.txt");
        }
        // 伪造但格式正确的 anchor(与 log 不一致)-> 重启 open 必须拒绝(不从伪 head 续链)
        std::fs::write(format!("{}.anchor", log), "999\tdeadbeefdeadbeef").unwrap();
        assert!(
            audit::AuditSink::open(&log).is_err(),
            "不一致 anchor 重启必须 fail-closed 拒绝"
        );
    }

    #[test]
    fn record_failure_blocks_side_effect() {
        let dir = std::env::temp_dir().join(format!("capaudit5_{}", rand_hex(6)));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("audit.log").to_string_lossy().into_owned();
        let root = tmp_workspace();
        let sink = Arc::new(Mutex::new(audit::AuditSink::open(&log).unwrap()));
        let mut s = Session::with_sink(sink);
        let repo = s.grant_dir(&root, parse_ops("read"), Taint::Project).unwrap();
        let echo = s.grant_command(&repo, vec!["echo".into(), "hi".into()]).unwrap();
        // 制造 anchor 原子写失败(uid 无关):把 .anchor.tmp 预建成目录,File::create 必失败
        std::fs::create_dir(format!("{}.anchor.tmp", log)).unwrap();
        let r = s.exec(&echo);
        let _ = std::fs::remove_dir(format!("{}.anchor.tmp", log));
        // 前置 durable intent 写失败 -> exec 必须不执行(fail-closed)
        assert!(r.is_err(), "审计 intent durable 化失败时 exec 必须不执行");
    }

    #[test]
    fn audit_broken_fails_closed() {
        // append 失败模拟:sink 打开在一个随后被设为只读的文件不易做;改为直接置 audit_broken
        let root = tmp_workspace();
        let mut s = Session::new();
        let repo = s.grant_dir(&root, parse_ops("read"), Taint::Project).unwrap();
        s.audit_broken = true; // 模拟持久审计写失败
        assert!(s.read(&repo, "main.txt").is_err(), "审计故障后敏感操作必须 fail-closed 拒绝");
    }

    #[test]
    fn exec_sandbox_confines_fs_to_cwd() {
        let root = tmp_workspace(); // 内含 main.txt = "hello broker"
        // 在 workspace 之外(同在 /tmp 但不同子树)放一个"机密"文件
        let outside = std::env::temp_dir().join(format!("cap_outside_{}.txt", rand_hex(6)));
        std::fs::write(&outside, b"OUTSIDE-SECRET").unwrap();
        let mut s = Session::new();
        let repo = s.grant_dir(&root, parse_ops("read"), Taint::Project).unwrap();
        // cwd 内相对读:允许(Landlock cwd 规则)
        let c_in = s.grant_command(&repo, vec!["cat".into(), "main.txt".into()]).unwrap();
        assert_eq!(s.exec(&c_in).unwrap(), b"hello broker", "cwd 内文件应可读");
        // cwd 外绝对读:Landlock 拒绝 open -> cat 失败,stdout 空
        let c_out = s
            .grant_command(&repo, vec!["cat".into(), outside.to_string_lossy().into_owned()])
            .unwrap();
        let out = s.exec(&c_out).unwrap();
        assert!(
            out.is_empty(),
            "沙箱内不应读到 cwd 外文件,得到: {:?}",
            String::from_utf8_lossy(&out)
        );
        let _ = std::fs::remove_file(&outside);
    }

    #[test]
    fn exec_policy_drop_uid_fail_closed_when_nonroot() {
        let root = tmp_workspace();
        let mut s = Session::new();
        // 配置掉权到某 uid;测试进程非 root -> setuid 失败 -> exec 必须 fail-closed 拒绝
        // drop_uid=u32::MAX -> setuid((uid_t)-1) 恒 EINVAL(与是否 root/CAP_SETUID 无关)
        // -> 配置的掉权无法施加 -> pre_exec Err -> spawn 失败 -> exec fail-closed 返回 Err
        s.set_exec_policy(os::SandboxPolicy {
            drop_uid: Some(u32::MAX),
            ..os::SandboxPolicy::default_limits()
        });
        let repo = s.grant_dir(&root, parse_ops("read"), Taint::Project).unwrap();
        let c = s.grant_command(&repo, vec!["cat".into(), "main.txt".into()]).unwrap();
        assert!(s.exec(&c).is_err(), "配置的掉权无法施加时 exec 必须 fail-closed 拒绝");
    }

    #[test]
    fn reduced_subject_cannot_hold_egress() {
        // E1:降级前已持有的 http/message 能力被级联撤销;降级期间 grant_http 无条件拒;恢复后可再授
        let mut s = Session::new();
        let h = s.grant_http("http", "registry.example", 80, vec!["GET".into()], vec!["/**".into()], 4096).unwrap();
        let m = s.grant_message("recipient");
        assert!(s.get_active(&h).is_ok() && s.get_active(&m).is_ok());
        s.set_mitigation_reduced(true);
        assert!(s.get_active(&h).is_err(), "降级瞬间已持有的 HttpCap 必须被撤销");
        assert!(s.get_active(&m).is_err(), "降级瞬间已持有的 MessageCap 必须被撤销");
        assert!(s.grant_http("http", "registry.example", 80, vec!["GET".into()], vec!["/**".into()], 4096).is_err(),
            "降低缓解状态下 grant_http 必须无条件拒绝");
        s.set_mitigation_reduced(false);
        assert!(s.grant_http("http", "registry.example", 80, vec!["GET".into()], vec!["/**".into()], 4096).is_ok());
        assert!(s.verify_audit(), "E1 决策必须全部入链");
    }

    #[test]
    fn http_cap_denials() {
        let mut s = Session::new();
        // metadata 主机:grant 允许(不解析),http_get 恒拒(SSRF)
        let h = s.grant_http("http", "metadata.google.internal", 80, vec!["GET".into()], vec!["/**".into()], 4096).unwrap();
        assert!(s.http_get(&h, "/latest/meta-data/").is_err(), "metadata 主机必须被 SSRF 拒");
        // loopback
        let h2 = s.grant_http("http", "127.0.0.1", 8080, vec!["GET".into()], vec!["/**".into()], 4096).unwrap();
        assert!(s.http_get(&h2, "/").is_err(), "loopback 必须被拒");
        // path 不在 allowlist(在解析/连接前拒)
        let h3 = s.grant_http("http", "example.com", 80, vec!["GET".into()], vec!["/v1/*".into()], 4096).unwrap();
        assert!(s.http_get(&h3, "/admin").is_err(), "path 越白名单必须拒");
        // https 暂不支持
        let h4 = s.grant_http("https", "example.com", 443, vec!["GET".into()], vec!["/**".into()], 4096).unwrap();
        assert!(s.http_get(&h4, "/").is_err(), "https 需 TLS,暂拒");
        // 响应 taint 由服务端定为 External(此处通过 grant 的 cap.taint 体现)
        assert_eq!(s.describe(&h).is_ok(), true);
    }

    #[test]
    fn cross_session_ref_invalid() {
        let root = tmp_workspace();
        let mut a = Session::new();
        let repo = a.grant_dir(&root, parse_ops("read"), Taint::Project).unwrap();
        let mut b = Session::new();
        // A 的 ref 在 B 的 registry 里不存在 -> 不可调用(不变量 14)
        assert!(b.read(&repo, "main.txt").is_err());
    }

    #[test]
    fn guest_grant_confined_to_workspace() {
        let root = tmp_workspace();
        let pol = Policy::guest(&root);
        assert!(pol.gate_grant_dir(&root).is_ok()); // workspace 本身
        assert!(pol.gate_grant_dir(&format!("{}/src", root)).is_ok()); // 内部
        assert!(pol.gate_grant_dir("/etc").is_err()); // 外部拒绝
        assert!(pol.gate_grant_dir("/").is_err());
        assert!(Policy::control().gate_grant_dir("/etc").is_ok()); // control 不受限
    }

    #[test]
    fn symlink_escape_blocked() {
        let root = tmp_workspace();
        // 在授权根内建一个指向 /etc 的 symlink
        let link = format!("{}/escape", root);
        let _ = std::os::unix::fs::symlink("/etc", &link);
        let mut s = Session::new();
        let repo = s.grant_dir(&root, parse_ops("read,list"), Taint::Project).unwrap();
        // 经 symlink 读根外文件必须被拒(P0 A2:/etc/passwd 恒存在)
        assert!(s.read(&repo, "escape/passwd").is_err(), "symlink 越界读必须被拒");
        // derive 一个 symlink 子目录也必须被拒
        assert!(s.derive_sub(&repo, "escape").is_err(), "symlink 子目录 derive 必须被拒");
    }

    #[test]
    fn root_path_swap_after_grant_defeated_by_held_fd() {
        // 授予 ws;随后把 ws 换成指向 /etc 的 symlink。持有 fd 应仍指向原 inode。
        let base = std::env::temp_dir().join(format!("capswap_{}", rand_hex(6)));
        std::fs::create_dir_all(&base).unwrap();
        let ws = base.join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::write(ws.join("main.txt"), b"inside").unwrap();
        let ws_s = ws.to_string_lossy().into_owned();
        let mut s = Session::new();
        let repo = s.grant_dir(&ws_s, parse_ops("read,list"), Taint::Project).unwrap();
        // 攻击:把 ws 目录换成 -> /etc 的 symlink
        std::fs::rename(&ws, base.join("ws.real")).unwrap();
        std::os::unix::fs::symlink("/etc", &ws).unwrap();
        // 持有 fd 指向原 inode:读原文件仍 OK,读 /etc/passwd(经被换的路径)不可达
        assert_eq!(s.read(&repo, "main.txt").unwrap().1, b"inside", "held fd 应仍读到原 inode");
        assert!(s.read(&repo, "passwd").is_err(), "root path swap 不得让 cap 访问 /etc");
        let _ = std::fs::remove_file(&ws);
    }

    #[test]
    fn sub_path_swap_after_derive_defeated_by_held_fd() {
        let base = std::env::temp_dir().join(format!("capswap2_{}", rand_hex(6)));
        std::fs::create_dir_all(base.join("ws/src")).unwrap();
        std::fs::write(base.join("ws/src/note.txt"), b"note-inside").unwrap();
        let ws_s = base.join("ws").to_string_lossy().into_owned();
        let mut s = Session::new();
        let repo = s.grant_dir(&ws_s, parse_ops("read,list"), Taint::Project).unwrap();
        let src = s.derive_sub(&repo, "src").unwrap();
        // 攻击:把 ws/src 换成 -> /etc
        std::fs::rename(base.join("ws/src"), base.join("ws/src.real")).unwrap();
        std::os::unix::fs::symlink("/etc", base.join("ws/src")).unwrap();
        // derived cap 持有 src 的原 fd:读原文件 OK,/etc/passwd 不可达
        assert_eq!(s.read(&src, "note.txt").unwrap().1, b"note-inside", "derived held fd 应仍原 inode");
        assert!(s.read(&src, "passwd").is_err(), "sub path swap 不得扩大 scope 到 /etc");
    }

    #[test]
    fn secret_path_taint_escalation() {
        let root = tmp_workspace();
        let mut s = Session::new();
        // 客户端把 secret 文件按 project 授权,读时服务端仍应升级为 Secret
        let repo = s.grant_dir(&root, parse_ops("read"), Taint::Project).unwrap();
        let (t, _) = s.read(&repo, "src/secret.txt").unwrap();
        assert_eq!(t, Taint::Secret, "敏感路径读必须升级为 Secret");
    }

    #[test]
    fn audit_chain_tamper_evident() {
        let root = tmp_workspace();
        let mut s = Session::new();
        let repo = s.grant_dir(&root, parse_ops("read,list"), Taint::Project).unwrap();
        let _ = s.read(&repo, "main.txt");
        let _ = s.read(&repo, "/etc/passwd"); // 记为 deny
        let sink = s.grant_sink("x");
        let _ = s.send(&sink, Taint::Secret, b"leak"); // 记为 deny(IFC)
        assert!(s.verify_audit(), "干净链应验证通过");
        assert!(s.audit_log().len() >= 5);
        // 篡改一条历史事件的 detail,但不重算后续 hash -> 验证必须失败
        // (通过一个白盒助手模拟:直接改内部 vec)
        let mut s2 = Session::new();
        let r2 = s2.grant_dir(&root, parse_ops("read"), Taint::Project).unwrap();
        let _ = s2.read(&r2, "main.txt");
        s2.tamper_first_for_test();
        assert!(!s2.verify_audit(), "篡改后链验证必须失败");
    }
}
