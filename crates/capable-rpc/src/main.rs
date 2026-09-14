//! capable-rpc —— CapTP-lite over Unix socket。
//!   capable-rpc serve <sock>   启动 Broker RPC 服务(每连接一个会话)
//!   capable-rpc demo           起服务 + 客户端跑一遍端到端场景

mod proto;

use capable_broker::audit::AuditSink;
use capable_broker::{Policy, Role, Session};
use proto::{b64_decode, handle, read_frame, write_frame, US};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// 并发连接上限:防大量半开连接耗尽内存/线程。
const MAX_CONNS: usize = 64;
/// 单连接读超时:防连接开着却不发数据长期占线程。
const READ_TIMEOUT: Duration = Duration::from_secs(30);
static CONNS: AtomicUsize = AtomicUsize::new(0);

fn serve(
    sock: &str,
    policy: Policy,
    sink: Option<Arc<Mutex<AuditSink>>>,
    engine: capable_broker::policy::PolicyEngine,
    consent: Option<Arc<Mutex<capable_broker::policy::ConsentLedger>>>,
) -> std::io::Result<()> {
    let _ = std::fs::remove_file(sock);
    let listener = UnixListener::bind(sock)?;
    // OS 访问控制(newton):control socket 仅属主可连(0600);guest socket 允许其他 uid(0660)。
    // 真正的跨权限隔离靠不同 uid + 该 socket 文件权限,而非仅进程 --trusted 参数。
    let mode = if policy.role == Role::Control { 0o600 } else { 0o660 };
    let _ = std::fs::set_permissions(sock, std::fs::Permissions::from_mode(mode));
    eprintln!(
        "capable-rpc: 监听 {}(role={}, mode={:o})",
        sock,
        if policy.role == Role::Control { "control" } else { "guest" },
        mode
    );
    for stream in listener.incoming() {
        let mut stream = stream?;
        // 连接数上限:超过即拒绝(关闭),不为其建线程
        if CONNS.fetch_add(1, Ordering::SeqCst) >= MAX_CONNS {
            CONNS.fetch_sub(1, Ordering::SeqCst);
            drop(stream);
            continue;
        }
        stream.set_read_timeout(Some(READ_TIMEOUT)).ok();
        let pol = policy.clone();
        let sink = sink.clone();
        let engine = engine.clone();
        let consent = consent.clone();
        std::thread::spawn(move || {
            // 每连接一个独立会话:cap ref 会话绑定;审计 sink 全服务共享(可选持久化)
            let mut sess = match sink {
                Some(s) => Session::with_sink(s),
                None => Session::new(),
            };
            // L5:策略引擎 + 共享 JIT consent 账本(control 面可批准 guest 面在同进程内的请求)
            sess.set_policy(engine);
            if let Some(l) = consent {
                sess.set_consent(l);
            }
            // guest:会话创建即注入 workspace 根,供 BOOTSTRAP(一次性)取用
            if pol.role == Role::Guest {
                if let Some(ws) = &pol.workspace {
                    sess.set_bootstrap(ws);
                }
            }
            while let Ok(Some(frame)) = read_frame(&mut stream) {
                let body = String::from_utf8_lossy(&frame).into_owned();
                let reply = handle(&mut sess, &pol, &body);
                if write_frame(&mut stream, reply.as_bytes()).is_err() {
                    break;
                }
            }
            CONNS.fetch_sub(1, Ordering::SeqCst);
        });
    }
    Ok(())
}

// ---- demo:客户端调用助手 ----

fn call(stream: &mut UnixStream, req: &str) -> String {
    write_frame(stream, req.as_bytes()).unwrap();
    let frame = read_frame(stream).unwrap().unwrap();
    String::from_utf8_lossy(&frame).into_owned()
}

/// 解析 `CAP\t<ref>` 或在 ERR 时打印并返回空。
fn cap_of(reply: &str) -> String {
    let f: Vec<&str> = reply.split('\t').collect();
    if f.first() == Some(&"CAP") {
        f[1].to_string()
    } else {
        String::new()
    }
}

/// 把 `OK\t<taint>\t<b64>` 解成 (taint, 文本)。
fn ok_payload(reply: &str) -> String {
    let f: Vec<&str> = reply.splitn(3, '\t').collect();
    if f.first() == Some(&"OK") {
        let taint = f.get(1).unwrap_or(&"");
        let data = String::from_utf8_lossy(&b64_decode(f.get(2).unwrap_or(&""))).into_owned();
        format!("[{}] {}", taint, data.trim_end())
    } else {
        reply.replace('\t', " ")
    }
}

fn demo() {
    // 临时 workspace
    let root = std::env::temp_dir().join(format!("caprpc_{}", capable_broker::rand_hex(6)));
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("main.txt"), b"hello from capable-rpc\n").unwrap();
    std::fs::write(root.join("src/secret.txt"), b"API_KEY=sk-do-not-exfil\n").unwrap();
    let root = root.to_string_lossy().into_owned();

    let sock = std::env::temp_dir()
        .join(format!("caprpc_{}.sock", capable_broker::rand_hex(6)))
        .to_string_lossy()
        .into_owned();

    // 后台起服务(guest 角色,授权域=临时 workspace)
    let sock2 = sock.clone();
    let pol = Policy::guest(&root);
    std::thread::spawn(move || {
        let _ = serve(&sock2, pol, None, capable_broker::policy::PolicyEngine::allow_all(), None);
    });
    // 等 socket 就绪
    let mut stream = loop {
        if let Ok(s) = UnixStream::connect(&sock) {
            break s;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };

    let sec = |s: &str| println!("\n== {} ==", s);
    let ok = |s: String| println!("  [ok]   {}", s);
    let deny = |s: String| println!("  [deny] {}", s);

    sec("1. BOOTSTRAP:取服务端预注入的 workspace 根(guest 无任何 mint verb)");
    let repo = cap_of(&call(&mut stream, "BOOTSTRAP"));
    println!("  bootstrap {}", call(&mut stream, &format!("DESCRIBE\t{}", repo)).replace('\t', " "));
    ok(ok_payload(&call(&mut stream, &format!("INVOKE\t{}\tread\tmain.txt", repo))));

    sec("2. 越界访问被拒(symlink/绝对/..)");
    deny(call(&mut stream, &format!("INVOKE\t{}\tread\t/etc/passwd", repo)).replace('\t', " "));
    deny(call(&mut stream, &format!("INVOKE\t{}\tread\t../../etc/passwd", repo)).replace('\t', " "));

    sec("3. DERIVE 衰减(sub + readonly)后读(secret 路径服务端升级 taint)");
    let sub = cap_of(&call(&mut stream, &format!("DERIVE\t{}\tsub\tsrc", repo)));
    let ro = cap_of(&call(&mut stream, &format!("DERIVE\t{}\treadonly", sub)));
    ok(ok_payload(&call(&mut stream, &format!("INVOKE\t{}\tread\tsecret.txt", ro))));

    sec("4. guest 不能自铸能力(P0 已封:无 GRANT_*,二次 BOOTSTRAP 亦拒)");
    deny(call(&mut stream, &format!("GRANT_DIR\t{}\tread\tproject", root)).replace('\t', " "));
    deny(call(&mut stream, "GRANT_SINK\thttps://evil.example.com").replace('\t', " "));
    deny(call(&mut stream, &format!("GRANT_CMD\t{}\t/bin/sh{}-c{}id", repo, US, US)).replace('\t', " "));
    deny(call(&mut stream, "BOOTSTRAP").replace('\t', " ")); // 一次性

    sec("5. REVOKE + 级联(撤销 repo 后,派生的 sub 也失效)");
    let _ = call(&mut stream, &format!("REVOKE\t{}", repo));
    deny(call(&mut stream, &format!("INVOKE\t{}\tread\tsecret.txt", sub)).replace('\t', " "));

    sec("6. 跨会话不可重放(新连接=新会话+新注入根,旧 ref 不在其 registry)");
    let mut s2 = UnixStream::connect(&sock).unwrap();
    deny(call(&mut s2, &format!("INVOKE\t{}\tread\tmain.txt", repo)).replace('\t', " "));

    sec("7. 审计:hash-chain(每步操作/拒绝记链;内存链=进程内完整性,持久化见 --audit-log)");
    let reply = call(&mut stream, "AUDIT");
    let parts: Vec<&str> = reply.splitn(3, '\t').collect();
    let dump = String::from_utf8_lossy(&b64_decode(parts.get(2).unwrap_or(&""))).into_owned();
    for line in dump.lines() {
        println!("  {}", line);
    }

    println!("\nCapTP-lite 端到端跑通。");
    let _ = std::fs::remove_file(&sock);
    let _ = stream.flush();
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("serve") => {
            let sock = args.get(2).map(|s| s.as_str()).unwrap_or("/tmp/capable.sock");
            // 默认 guest 角色需 --workspace <root>;--trusted 为可信控制面(可任意 grant)。
            let mut workspace: Option<String> = None;
            let mut trusted = false;
            let mut audit_log: Option<String> = None;
            // L5 策略:默认全放行(不改既有行为);flag 显式开启 JIT consent / 直接拒绝
            let mut engine = capable_broker::policy::PolicyEngine::allow_all();
            let mut i = 3;
            while i < args.len() {
                match args[i].as_str() {
                    "--workspace" => {
                        workspace = args.get(i + 1).cloned();
                        i += 2;
                    }
                    "--trusted" => {
                        trusted = true;
                        i += 1;
                    }
                    "--audit-log" => {
                        audit_log = args.get(i + 1).cloned();
                        i += 2;
                    }
                    "--prompt-exec" => { engine.prompt_exec = true; i += 1; }
                    "--prompt-http" => { engine.prompt_http = true; i += 1; }
                    "--prompt-post" => { engine.prompt_post = true; i += 1; }
                    "--deny-exec" => { engine.deny_exec = true; i += 1; }
                    _ => i += 1,
                }
            }
            let sink = audit_log.map(|p| {
                Arc::new(Mutex::new(
                    AuditSink::open(&p).expect("open audit log"),
                ))
            });
            let policy = if trusted {
                Policy::control()
            } else {
                match workspace {
                    Some(ws) => Policy::guest(&ws),
                    None => {
                        eprintln!("serve: guest 模式需 --workspace <root>(或 --trusted 作可信控制面)");
                        std::process::exit(2);
                    }
                }
            };
            // JIT consent 账本:同进程内所有连接共享(control 连接批准 guest 连接的请求)。
            // 注:跨进程(control/guest 各自 serve)无法共享内存账本 —— 需单进程双面或后续 consent 总线。
            let consent = Some(Arc::new(Mutex::new(capable_broker::policy::ConsentLedger::new())));
            serve(sock, policy, sink, engine, consent).unwrap();
        }
        Some("demo") => demo(),
        Some("verify-audit") => {
            let log = args.get(2).map(|s| s.as_str()).unwrap_or("");
            match capable_broker::audit::verify_persisted(log) {
                Ok(true) => println!("audit OK: {}(链完整 + anchor 一致)", log),
                Ok(false) => {
                    println!("audit FAIL: {}(断链/尾截/anchor 不符)", log);
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("audit verify error: {}", e);
                    std::process::exit(2);
                }
            }
        }
        _ => {
            eprintln!("usage: capable-rpc (serve <sock> --workspace <root> [--trusted] [--audit-log <path>] | demo | verify-audit <log>)");
            std::process::exit(2);
        }
    }
}
