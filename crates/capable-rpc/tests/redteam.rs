//! Red-team 端到端对抗测试:黑盒地对真实 `capable-rpc serve` 进程发起攻击,
//! 断言每条安全不变量在【真实 wire 协议 + 真实服务端】下成立(不是内部单元 mock)。
//!
//! 覆盖的攻击面(guest / 不可信面):
//!   1. 伪造 cap ref            → 拒(引用不可伪造、会话绑定)
//!   2. guest 自铸能力          → 拒(guest 无任何 mint verb)
//!   3. 二次 BOOTSTRAP          → 拒(初始 authority 一次性)
//!   4. 路径逃逸(绝对/../)     → 拒(DirCap RESOLVE_BENEATH + 持有 fd)
//!   5. 跨会话重放              → 拒(ref 属会话 registry,新连接不认)
//!   6. REVOKE 级联             → 拒(撤销父,派生子失效)
//!   7. 超大帧                  → 连接被服务端在分配前关闭
//! 正向对照:合法 BOOTSTRAP + read 成功。收尾:verify-audit 断言持久链完整。
//!
//! 服务端二进制由 cargo 以 CARGO_BIN_EXE_capable-rpc 提供(真实构建产物)。

use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_capable-rpc");
const US: char = '\u{1f}';

// ---- 与 proto 一致的最小 wire 实现(4 字节大端长度 + tab 文本)----

fn write_frame(s: &mut UnixStream, body: &str) {
    let len = body.len() as u32;
    s.write_all(&len.to_be_bytes()).unwrap();
    s.write_all(body.as_bytes()).unwrap();
    s.flush().unwrap();
}

/// 读一帧;EOF(对端关闭)返回 None。
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

/// 发一条请求并取回复(帧);None = 连接被关闭。
fn call(s: &mut UnixStream, req: &str) -> Option<String> {
    write_frame(s, req);
    read_frame(s)
}

/// 回复第一字段(CAP/OK/ERR/AUDIT…)。
fn tag(reply: &str) -> &str {
    reply.split('\t').next().unwrap_or("")
}

/// 从 `CAP\t<ref>` 取 ref。
fn cap_of(reply: &str) -> String {
    let f: Vec<&str> = reply.split('\t').collect();
    assert_eq!(f.first(), Some(&"CAP"), "期望 CAP,得到: {}", reply.replace('\t', " "));
    f[1].to_string()
}

/// `OK\t<taint>\t<b64>` → 解码文本(测试端独立 b64,不复用被测实现的判定/编码)。
fn payload(reply: &str) -> String {
    let f: Vec<&str> = reply.splitn(3, '\t').collect();
    if f.first() != Some(&"OK") {
        return String::new();
    }
    String::from_utf8_lossy(&b64_decode(f.get(2).unwrap_or(&""))).into_owned()
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
    log: String,
    root: PathBuf,
    _dir: PathBuf,
}

impl Server {
    /// 建临时 workspace(含 main.txt + src/secret.txt),返回 (base, root, sock, log)。
    fn scaffold() -> (PathBuf, PathBuf, String, String) {
        let base = std::env::temp_dir().join(format!("caprt_{}_{}", std::process::id(), unique()));
        let root = base.join("ws");
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("main.txt"), b"hello-redteam\n").unwrap();
        std::fs::write(root.join("src/secret.txt"), b"API_KEY=sk-nope\n").unwrap();
        let sock = base.join("s.sock").to_string_lossy().into_owned();
        let log = base.join("audit.log").to_string_lossy().into_owned();
        (base, root, sock, log)
    }

    fn wait_ready(child: Child, sock: String, log: String, base: PathBuf, root: PathBuf) -> Server {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if UnixStream::connect(&sock).is_ok() {
                break;
            }
            assert!(Instant::now() < deadline, "服务端未在 5s 内就绪");
            std::thread::sleep(Duration::from_millis(20));
        }
        Server { child, sock, log, root, _dir: base }
    }

    /// guest 面:--workspace <root>,无 mint verb,初始 authority 由服务端注入。
    fn start_guest() -> Server {
        let (base, root, sock, log) = Self::scaffold();
        let child = Command::new(BIN)
            .args(["serve", &sock, "--workspace", &root.to_string_lossy(), "--audit-log", &log])
            .spawn()
            .expect("spawn capable-rpc serve (guest)");
        Self::wait_ready(child, sock, log, base, root)
    }

    /// control 面:--trusted,可 mint(GRANT_*);用于验证跨层路径(HttpCap 规范化、C1 exec)。
    fn start_control() -> Server {
        let (base, root, sock, log) = Self::scaffold();
        let child = Command::new(BIN)
            .args(["serve", &sock, "--trusted", "--audit-log", &log])
            .spawn()
            .expect("spawn capable-rpc serve (control)");
        Self::wait_ready(child, sock, log, base, root)
    }

    fn connect(&self) -> UnixStream {
        UnixStream::connect(&self.sock).expect("connect sock")
    }

    /// workspace 内的绝对路径(用于测试端在磁盘上做 symlink/换位攻击布置)。
    fn ws_path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// 进程内单调唯一后缀(测试无 rand;Instant 单调,取纳秒低位)。
fn unique() -> u128 {
    static CNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = CNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    (Instant::now().elapsed().as_nanos()) ^ (u128::from(n) << 64) ^ 0x9e3779b97f4a7c15
}

#[test]
fn redteam_guest_attacks_all_denied_and_audit_intact() {
    let srv = Server::start_guest();
    let mut s = srv.connect();

    // 正向对照:BOOTSTRAP 取注入根,合法 read 成功
    let repo = cap_of(&call(&mut s, "BOOTSTRAP").expect("BOOTSTRAP 有回复"));
    let ok = call(&mut s, &format!("INVOKE\t{}\tread\tmain.txt", repo)).unwrap();
    assert_eq!(tag(&ok), "OK", "合法 read 应成功: {}", ok.replace('\t', " "));

    // 攻击 1:伪造 ref(随机 token)→ 拒
    let forged = "cap_00000000000000000000000000000000";
    let r = call(&mut s, &format!("INVOKE\t{}\tread\tmain.txt", forged)).unwrap();
    assert_eq!(tag(&r), "ERR", "伪造 ref 必须被拒: {}", r.replace('\t', " "));

    // 攻击 2:guest 自铸能力(全部 mint verb,均为**格式正确**的请求 → 证明是 role 拒绝而非解析失败)
    for mint in [
        format!("GRANT_DIR\t/etc\tread\tproject"),
        format!("GRANT_SINK\thttps://evil.example.com"),
        format!("GRANT_CMD\t{}\t/bin/sh{}-c{}id", repo, US, US),
        // 完整合法的 GRANT_HTTP(scheme host port methods paths max_bytes):被拒必须因 guest role
        format!("GRANT_HTTP\thttp\texample.com\t80\tGET\t/**\t4096"),
    ] {
        let r = call(&mut s, &mint).unwrap();
        assert_eq!(tag(&r), "ERR", "guest mint 必须被拒: {}", mint.replace('\t', " "));
    }

    // 攻击 3:二次 BOOTSTRAP → 拒(一次性)
    let r = call(&mut s, "BOOTSTRAP").unwrap();
    assert_eq!(tag(&r), "ERR", "二次 BOOTSTRAP 必须被拒: {}", r.replace('\t', " "));

    // 攻击 4:路径逃逸 → 拒
    for bad in ["/etc/passwd", "../../etc/passwd", "../../../etc/shadow"] {
        let r = call(&mut s, &format!("INVOKE\t{}\tread\t{}", repo, bad)).unwrap();
        assert_eq!(tag(&r), "ERR", "路径逃逸必须被拒 ({}): {}", bad, r.replace('\t', " "));
    }

    // 攻击 4b:符号链接逃逸(不只 `..`)—— workspace 内放一个指向 /etc 的 symlink,穿越读被拒
    // (openat2 RESOLVE_NO_MAGICLINKS/BENEATH:符号链接不得逃出授权域)
    std::os::unix::fs::symlink("/etc", srv.ws_path("link_to_etc")).unwrap();
    let r = call(&mut s, &format!("INVOKE\t{}\tread\tlink_to_etc/passwd", repo)).unwrap();
    assert_eq!(tag(&r), "ERR", "symlink 逃逸必须被拒: {}", r.replace('\t', " "));

    // 攻击 4c:派生后目录换位(root swap)—— 验证 Cap 持稳定 fd,而非按名字重解析。
    // DERIVE sub 拿到 src 的 fd 后,把磁盘上的 src 换成指向 /etc 的 symlink;经 sub 读:
    //   - 读原 src 内文件(secret.txt)仍能命中(走持有的 fd,指向原 inode)
    //   - 读 /etc 下文件(passwd)不命中/被拒(持有 fd 是原 src,不是被换上的 /etc)
    let sub_swap = cap_of(&call(&mut s, &format!("DERIVE\t{}\tsub\tsrc", repo)).unwrap());
    std::fs::rename(srv.ws_path("src"), srv.ws_path("src.bak")).unwrap();
    std::os::unix::fs::symlink("/etc", srv.ws_path("src")).unwrap();
    let still = call(&mut s, &format!("INVOKE\t{}\tread\tsecret.txt", sub_swap)).unwrap();
    assert_eq!(tag(&still), "OK", "换位后经持有 fd 仍应读到原 src 文件: {}", still.replace('\t', " "));
    let escaped = call(&mut s, &format!("INVOKE\t{}\tread\tpasswd", sub_swap)).unwrap();
    assert_eq!(tag(&escaped), "ERR", "换位不得让 sub 读到 /etc/passwd: {}", escaped.replace('\t', " "));
    // 还原 src 供后续用例
    let _ = std::fs::remove_file(srv.ws_path("src"));
    std::fs::rename(srv.ws_path("src.bak"), srv.ws_path("src")).unwrap();

    // 攻击 6:REVOKE 级联(先派生 sub,撤销 repo 后 sub 失效)
    let sub = cap_of(&call(&mut s, &format!("DERIVE\t{}\tsub\tsrc", repo)).unwrap());
    assert_eq!(tag(&call(&mut s, &format!("REVOKE\t{}", repo)).unwrap()), "OK");
    let r = call(&mut s, &format!("INVOKE\t{}\tread\tsecret.txt", sub)).unwrap();
    assert_eq!(tag(&r), "ERR", "撤销父后派生子必须失效: {}", r.replace('\t', " "));

    // 攻击 5:跨会话重放(新连接=新会话,旧 ref 不在其 registry)
    let mut s2 = srv.connect();
    let r = call(&mut s2, &format!("INVOKE\t{}\tread\tmain.txt", repo)).unwrap();
    assert_eq!(tag(&r), "ERR", "跨会话重放必须被拒: {}", r.replace('\t', " "));
    // 新会话自己 BOOTSTRAP 合法
    let repo2 = cap_of(&call(&mut s2, "BOOTSTRAP").unwrap());
    assert_eq!(tag(&call(&mut s2, &format!("INVOKE\t{}\tread\tmain.txt", repo2)).unwrap()), "OK");
    let _ = s2.shutdown(Shutdown::Both);

    // 攻击 7:超大帧头 → 服务端分配前拒绝并关闭连接
    let mut s3 = srv.connect();
    let huge: u32 = 16 * 1024 * 1024; // > MAX_FRAME(8 MiB)
    s3.write_all(&huge.to_be_bytes()).unwrap();
    let _ = s3.write_all(&[0u8; 16]); // 只发一点 body
    s3.flush().unwrap();
    // 服务端应关闭连接:后续读不到有效帧
    assert!(read_frame(&mut s3).is_none(), "超大帧后连接应被关闭");
    let _ = s.shutdown(Shutdown::Both);

    // 收尾:审计持久链完整(独立进程校验)
    let v = Command::new(BIN).args(["verify-audit", &srv.log]).output().unwrap();
    assert!(
        v.status.success(),
        "verify-audit 应通过: stdout={} stderr={}",
        String::from_utf8_lossy(&v.stdout),
        String::from_utf8_lossy(&v.stderr)
    );
}

/// 控制面跨层黑盒:HttpCap 请求目标规范化(连接前短路,不触网)+ C1 exec Landlock 边界。
/// 这些不变量各有白盒回归,此处把跨层路径也锁进红队黑盒集(newton 建议)。
#[test]
fn redteam_control_plane_http_canonical_and_exec_sandbox() {
    let srv = Server::start_control();
    let mut s = srv.connect();

    // ---- HttpCap:恶意 request-target 必须在建连前被 canonical_request_target 拒绝 ----
    let http = cap_of(
        &call(&mut s, "GRANT_HTTP\thttp\texample.com\t80\tGET\t/**\t4096").unwrap(),
    );
    for bad in [
        "/v1/%2e%2e/admin",    // %2e -> ..(代理归一化后越权)
        "/v1/%2f..%2fadmin",   // %2f -> /
        "/v1/%5c..%5cadmin",   // %5c -> \
        "//evil.example.com/", // network-path reference
        "/x\r\nHost: evil",    // CRLF 头注入
    ] {
        let r = call(&mut s, &format!("INVOKE\t{}\thttp_get\t{}", http, bad)).unwrap();
        assert_eq!(
            tag(&r),
            "ERR",
            "恶意 http target 必须被拒 ({}): {}",
            bad.escape_default(),
            r.replace('\t', " ")
        );
    }

    // ---- C1 exec 沙箱:Landlock 限 fs 到 cwd(RPC → CommandCap → 子进程 pre_exec 全链)----
    let cwd = cap_of(
        &call(
            &mut s,
            &format!("GRANT_DIR\t{}\tread,list,exec\tproject", srv.root.to_string_lossy()),
        )
        .unwrap(),
    );
    // cwd 内:cat main.txt → stdout 有内容
    let inside = cap_of(
        &call(&mut s, &format!("GRANT_CMD\t{}\t/bin/cat{}main.txt", cwd, US)).unwrap(),
    );
    let r = call(&mut s, &format!("INVOKE\t{}\texec", inside)).unwrap();
    assert_eq!(tag(&r), "OK", "cwd 内 exec 应成功: {}", r.replace('\t', " "));
    assert!(payload(&r).contains("hello-redteam"), "cwd 内 cat 应读到内容: {:?}", payload(&r));
    // cwd 外:cat /etc/hostname → Landlock 拒读 → stdout 空(沙箱未 fail-open)
    let outside = cap_of(
        &call(&mut s, &format!("GRANT_CMD\t{}\t/bin/cat{}/etc/hostname", cwd, US)).unwrap(),
    );
    let r = call(&mut s, &format!("INVOKE\t{}\texec", outside)).unwrap();
    assert_eq!(tag(&r), "OK", "exec 本身应返回(仅 stdout 因 Landlock 为空): {}", r.replace('\t', " "));
    assert!(payload(&r).is_empty(), "cwd 外 cat 应被 Landlock 拒(stdout 空),得到: {:?}", payload(&r));

    let _ = s.shutdown(Shutdown::Both);
}
