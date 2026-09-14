//! policy.rs — L5 策略引擎 + JIT(just-in-time)consent。
//!
//! 能力"持有即授权"是基线;L5 在**使用能力的那一刻**加一层可治理的策略闸:
//! 对高风险动作(exec、http_get、post…)可要求 **JIT 人类/控制面授权**或直接拒绝。
//! 这是"安全 agent harness"的治理层 —— 不改变能力不可伪造/衰减/撤销语义,只在调用点插闸。
//!
//! 设计要点:
//! - 决策三态 `Allow | Deny | Prompt`;默认 `allow_all()`(不改变既有行为,策略需显式开启)。
//! - consent 是**跨会话**的:请求方(可能是不可信 guest)发起,**控制面**(可信人类/编排器)
//!   批准/拒绝,请求方再重放该动作即放行。ledger 用 Arc<Mutex> 在服务内共享(同 audit sink)。
//! - consent 授权**一次性**(approve 后被消费),按 (action-signature, session) 精确作用域,
//!   避免一次批准放行后续所有同类动作。
//! - fail-closed:策略要求 Prompt 但无 consent ledger 可用 → 拒绝(不静默放行)。

use std::collections::HashMap;

/// gate 在需要 JIT 授权时返回的错误前缀 —— proto 层据此把结果转成 `CONSENT\t<id>\t<summary>`
/// 帧(而非普通 `ERR`),客户端据此走审批流程后重放动作。
pub const CONSENT_REQUIRED: &str = "__CONSENT__";

/// 策略对某个动作的决策。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Decision {
    Allow,
    Deny,
    Prompt,
}

/// 声明式策略引擎:对具体高风险 verb 要求 JIT consent 或直接拒绝。
/// 默认全 Allow —— 既有行为不变;要治理需显式构造带规则的引擎。
#[derive(Clone)]
pub struct PolicyEngine {
    pub deny_exec: bool,          // 直接禁止 exec(最严)
    pub prompt_exec: bool,        // exec 前需 JIT 授权
    pub prompt_http: bool,        // http_get 前需 JIT 授权
    pub prompt_post: bool,        // MessageCap 投递前需 JIT 授权
}

impl PolicyEngine {
    /// 不治理:一切放行(默认,保持既有行为)。
    pub fn allow_all() -> Self {
        PolicyEngine { deny_exec: false, prompt_exec: false, prompt_http: false, prompt_post: false }
    }

    /// 对给定 verb 的决策。deny 优先于 prompt。
    pub fn decide(&self, verb: &str) -> Decision {
        match verb {
            "exec" if self.deny_exec => Decision::Deny,
            "exec" if self.prompt_exec => Decision::Prompt,
            "http_get" if self.prompt_http => Decision::Prompt,
            "post" | "post_from" if self.prompt_post => Decision::Prompt,
            _ => Decision::Allow,
        }
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        PolicyEngine::allow_all()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Status {
    Pending,
    Approved,
    Denied,
}

struct Req {
    sig: String,     // 动作签名(verb + cap + 关键参数):approve 精确作用于此
    session: String, // 发起会话 key:consent 绑定发起者,别的会话不能借用
    summary: String, // 给审批者看的人类摘要
    status: Status,
}

/// JIT consent 账本(跨会话共享)。请求方登记 Pending;控制面 approve/deny(按请求 id);
/// 请求方重放动作时 `take_if_approved` 消费已批准的授权(一次性)。
pub struct ConsentLedger {
    reqs: HashMap<String, Req>, // id -> Req
    seq: u64,                   // 单调计数,生成确定性 id(不依赖随机/时间)
}

/// gate 查询 consent 的结果。
pub enum ConsentOutcome {
    Approved,        // 已批准(已消费),动作放行
    Pending(String), // 待批准,携带请求 id(供 CONSENT 帧回给客户端)
    Denied,          // 已被拒
}

impl ConsentLedger {
    pub fn new() -> Self {
        ConsentLedger { reqs: HashMap::new(), seq: 0 }
    }

    /// 查询/登记:
    /// - 若该 (sig,session) 已有 Approved → 消费并返回 Approved(一次性);
    /// - 若已有 Denied → 返回 Denied(保留,直到审批者清理);
    /// - 若已有 Pending → 返回其 id(幂等,不重复登记);
    /// - 否则新建 Pending 并返回新 id。
    pub fn request_or_check(&mut self, sig: &str, session: &str, summary: &str) -> ConsentOutcome {
        // 先找该 (sig,session) 的既有请求
        let found = self
            .reqs
            .iter()
            .find(|(_, q)| q.sig == sig && q.session == session)
            .map(|(id, q)| (id.clone(), q.status));
        match found {
            Some((id, Status::Approved)) => {
                self.reqs.remove(&id); // 一次性消费
                ConsentOutcome::Approved
            }
            Some((_, Status::Denied)) => ConsentOutcome::Denied,
            Some((id, Status::Pending)) => ConsentOutcome::Pending(id),
            None => {
                self.seq += 1;
                let id = format!("consent_{}", self.seq);
                self.reqs.insert(
                    id.clone(),
                    Req {
                        sig: sig.to_string(),
                        session: session.to_string(),
                        summary: summary.to_string(),
                        status: Status::Pending,
                    },
                );
                ConsentOutcome::Pending(id)
            }
        }
    }

    /// 控制面批准一个待决请求(按 id)。返回该请求的人类摘要(便于审计/回显)。
    pub fn approve(&mut self, id: &str) -> Result<String, String> {
        match self.reqs.get_mut(id) {
            Some(q) if q.status == Status::Pending => {
                q.status = Status::Approved;
                Ok(q.summary.clone())
            }
            Some(_) => Err(format!("consent {} 非待决状态", id)),
            None => Err(format!("consent {} 不存在", id)),
        }
    }

    /// 控制面拒绝一个待决请求。
    pub fn deny(&mut self, id: &str) -> Result<String, String> {
        match self.reqs.get_mut(id) {
            Some(q) if q.status == Status::Pending => {
                q.status = Status::Denied;
                Ok(q.summary.clone())
            }
            Some(_) => Err(format!("consent {} 非待决状态", id)),
            None => Err(format!("consent {} 不存在", id)),
        }
    }

    /// 待决请求数(测试/DESCRIBE 用)。
    pub fn pending_count(&self) -> usize {
        self.reqs.values().filter(|q| q.status == Status::Pending).count()
    }

    /// **control-only**:读一个请求的完整审批详情(argv/env/cwd 等,可能含敏感)。
    pub fn describe(&self, id: &str) -> Option<String> {
        self.reqs.get(id).map(|q| q.summary.clone())
    }

    /// **control-only**:列出所有待决请求 (id, 发起会话, 完整详情)。
    pub fn list_pending(&self) -> Vec<(String, String, String)> {
        let mut v: Vec<(String, String, String)> = self
            .reqs
            .iter()
            .filter(|(_, q)| q.status == Status::Pending)
            .map(|(id, q)| (id.clone(), q.session.clone(), q.summary.clone()))
            .collect();
        v.sort_by(|a, b| a.0.cmp(&b.0)); // 确定性顺序(id 单调)
        v
    }
}

impl Default for ConsentLedger {
    fn default() -> Self {
        ConsentLedger::new()
    }
}

#[cfg(test)]
mod t {
    use super::*;

    #[test]
    fn consent_flow_approve_consume_once() {
        let mut l = ConsentLedger::new();
        // guest 发起 exec 请求 → Pending
        let id = match l.request_or_check("exec:capA", "sessG", "exec CommandCap capA") {
            ConsentOutcome::Pending(id) => id,
            _ => panic!("首次应 Pending"),
        };
        // 重复请求幂等(同 id,不新增)
        match l.request_or_check("exec:capA", "sessG", "exec CommandCap capA") {
            ConsentOutcome::Pending(id2) => assert_eq!(id, id2),
            _ => panic!("应仍 Pending 同 id"),
        }
        assert_eq!(l.pending_count(), 1);
        // 控制面批准
        assert!(l.approve(&id).is_ok());
        // guest 重放 → Approved(消费)
        assert!(matches!(l.request_or_check("exec:capA", "sessG", "x"), ConsentOutcome::Approved));
        // 一次性:再放行需重新审批
        assert!(matches!(l.request_or_check("exec:capA", "sessG", "x"), ConsentOutcome::Pending(_)));
    }

    #[test]
    fn consent_denied_and_session_scoped() {
        let mut l = ConsentLedger::new();
        let id = match l.request_or_check("http_get:capH", "sessG", "s") {
            ConsentOutcome::Pending(id) => id,
            _ => panic!(),
        };
        l.deny(&id).unwrap();
        assert!(matches!(l.request_or_check("http_get:capH", "sessG", "s"), ConsentOutcome::Denied));
        // 另一个会话相同动作是独立请求(不借用别的会话的决策)
        assert!(matches!(l.request_or_check("http_get:capH", "sessOther", "s"), ConsentOutcome::Pending(_)));
    }

    #[test]
    fn policy_decisions() {
        let e = PolicyEngine { deny_exec: false, prompt_exec: true, prompt_http: true, prompt_post: false };
        assert_eq!(e.decide("exec"), Decision::Prompt);
        assert_eq!(e.decide("http_get"), Decision::Prompt);
        assert_eq!(e.decide("read"), Decision::Allow);
        assert_eq!(e.decide("post"), Decision::Allow);
        let deny = PolicyEngine { deny_exec: true, ..PolicyEngine::allow_all() };
        assert_eq!(deny.decide("exec"), Decision::Deny);
        assert_eq!(PolicyEngine::allow_all().decide("exec"), Decision::Allow);
    }
}
