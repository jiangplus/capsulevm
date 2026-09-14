//! L5 JIT consent 端到端黑盒:对真实 `serve --trusted --prompt-exec` 进程,证明
//! "能力使用点的人类实时授权"流程走通 —— 请求方连接执行高风险动作触发 CONSENT,
//! **另一个连接到同一 socket 的审批者**批准/拒绝,请求方重放即放行/被拒。
//!
//! 这是 capsh(可信编排器)+ 人类审批者的真实模型:同一 Broker 进程内所有连接共享一个
//! consent 账本,审批者无需与请求方同连接,只需连到同一控制面 socket。

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_capable-rpc");
const US: char = '\u{1f}';

fn write_frame(s: &mut UnixStream, body: &str) {
    let len = body.len() as u32;
    s.write_all(&len.to_be_bytes()).unwrap();
    s.write_all(body.as_bytes()).unwrap();
    s.flush().unwrap();
}
fn read_frame(s: &mut UnixStream) -> Option<String> {
    let mut lenb = [0u8; 4];
    let mut got = 0;
    while got < 4 {
        match s.read(&mut lenb[got..]) {
            Ok(0) => return None,
            Ok(n) => got += n,
            Err(_) => return None,
        }
    }
    let len = u32::from_be_bytes(lenb) as usize;
    let mut buf = vec![0u8; len];
    if s.read_exact(&mut buf).is_err() {
        return None;
    }
    Some(String::from_utf8_lossy(&buf).into_owned())
}
fn call(s: &mut UnixStream, req: &str) -> String {
    write_frame(s, req);
    read_frame(s).expect("有回复")
}
fn tag(reply: &str) -> &str {
    reply.split('\t').next().unwrap_or("")
}
fn field(reply: &str, i: usize) -> String {
    reply.split('\t').nth(i).unwrap_or("").to_string()
}
fn b64_decode(s: &str) -> Vec<u8> {
    let v = |c: u8| -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };
    let (mut out, mut acc, mut nbits) = (Vec::new(), 0u32, 0u32);
    for &c in s.as_bytes() {
        if c == b'=' {
            break;
        }
        if let Some(x) = v(c) {
            acc = (acc << 6) | x;
            nbits += 6;
            if nbits >= 8 {
                nbits -= 8;
                out.push((acc >> nbits) as u8);
            }
        }
    }
    out
}

struct Server {
    child: Child,
    sock: String,
    _dir: PathBuf,
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
fn unique() -> u128 {
    static CNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = CNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    Instant::now().elapsed().as_nanos() ^ (u128::from(n) << 64) ^ 0x9e3779b97f4a7c15
}

/// 起一个 control 面、exec 需 JIT consent 的 Broker 进程。
fn start_prompt_exec() -> (Server, String) {
    let base = std::env::temp_dir().join(format!("capcns_{}_{}", std::process::id(), unique()));
    let root = base.join("ws");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("main.txt"), b"hi\n").unwrap();
    let sock = base.join("c.sock").to_string_lossy().into_owned();
    let log = base.join("audit.log").to_string_lossy().into_owned();
    let child = Command::new(BIN)
        .args(["serve", &sock, "--trusted", "--prompt-exec", "--audit-log", &log])
        .spawn()
        .expect("spawn serve --prompt-exec");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if UnixStream::connect(&sock).is_ok() {
            break;
        }
        assert!(Instant::now() < deadline, "服务端未就绪");
        std::thread::sleep(Duration::from_millis(20));
    }
    (Server { child, sock: sock.clone(), _dir: base }, root.to_string_lossy().into_owned())
}

#[test]
fn jit_consent_approve_and_deny_end_to_end() {
    let (srv, root) = start_prompt_exec();
    let mut worker = UnixStream::connect(&srv.sock).unwrap(); // 请求方(capsh)
    let mut approver = UnixStream::connect(&srv.sock).unwrap(); // 人类审批者(同一 socket)

    // 请求方 mint 一个 CommandCap(control 面可 mint;mint 不需 consent)
    let dir = call(&mut worker, &format!("GRANT_DIR\t{}\tread,list,exec\tproject", root));
    let dref = field(&dir, 1);
    let cmd = call(&mut worker, &format!("GRANT_CMD\t{}\t/bin/echo{}hi", dref, US));
    let cref = field(&cmd, 1);

    // exec → CONSENT 帧(非 OK/ERR):动作被挂起,等待审批
    let r = call(&mut worker, &format!("INVOKE\t{}\texec", cref));
    assert_eq!(tag(&r), "CONSENT", "exec 应触发 CONSENT: {}", r);
    let id = field(&r, 1);
    assert!(!id.is_empty(), "CONSENT 应带请求 id");
    // **requester 视图不得泄露 env/argv**(CommandCap 的 env 常含凭据)—— 触发 Prompt 不能读机密
    assert!(!r.contains("PATH"), "requester CONSENT 帧不得含 env: {}", r);
    assert!(!r.contains("env="), "requester CONSENT 帧不得含 env 详情: {}", r);
    // 完整详情(含 env)只经 **control-only** CONSENT_DESCRIBE 读取
    let desc = call(&mut approver, &format!("CONSENT_DESCRIBE\t{}", id));
    assert_eq!(tag(&desc), "OK", "control 面应能读详情: {}", desc);
    let detail = String::from_utf8_lossy(&b64_decode(&field(&desc, 2))).into_owned();
    assert!(detail.contains("PATH") && detail.contains("env="), "详情应含 env(供审批人核对): {}", detail);
    // CONSENT_LIST 也 control-only,能列出该待决请求
    let list = call(&mut approver, &format!("CONSENT_LIST"));
    assert_eq!(tag(&list), "OK");

    // 未批准前重放仍 CONSENT(同 id,幂等,不放行)
    let r2 = call(&mut worker, &format!("INVOKE\t{}\texec", cref));
    assert_eq!(tag(&r2), "CONSENT");
    assert_eq!(field(&r2, 1), id, "重复请求应同一 id");

    // 审批者(另一连接,共享同一 consent 账本)批准
    assert_eq!(tag(&call(&mut approver, &format!("CONSENT_APPROVE\t{}", id))), "OK");

    // 请求方重放 → 放行执行(echo hi)
    let ok = call(&mut worker, &format!("INVOKE\t{}\texec", cref));
    assert_eq!(tag(&ok), "OK", "批准后 exec 应执行: {}", ok);

    // 一次性:再 exec 又需新批准(新 id)
    let r3 = call(&mut worker, &format!("INVOKE\t{}\texec", cref));
    assert_eq!(tag(&r3), "CONSENT");
    let id3 = field(&r3, 1);
    assert_ne!(id3, id, "应是新的 consent 请求");

    // 审批者拒绝 → 请求方重放被拒(ERR,不执行)
    assert_eq!(tag(&call(&mut approver, &format!("CONSENT_DENY\t{}", id3))), "OK");
    let denied = call(&mut worker, &format!("INVOKE\t{}\texec", cref));
    assert_eq!(tag(&denied), "ERR", "被拒后 exec 不得执行: {}", denied);
}
