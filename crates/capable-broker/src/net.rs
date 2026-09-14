//! net.rs — 受限网络 helper 的安全策略(B1,nono-proxy 蓝本)。
//! 核心是 egress 的拒绝逻辑:cloud-metadata 恒拒、private/loopback/link-local 恒拒、
//! DNS-rebind 防护(解析一次,连接必须用解析出的 IP,不再重解析)。
//!
//! 说明:实际字节传输(TLS)在纯 std 离线环境无法落地,本模块聚焦策略与解析检查
//! (安全关键部分,可离线单测);真实 fetch transport 待引入 TLS 后补。

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

/// 恒拒的 metadata 主机名(SSRF 对云 metadata 服务的典型目标)。
const METADATA_HOSTS: &[&str] = &[
    "metadata.google.internal",
    "metadata",
    "instance-data",
    "metadata.azure.com",
];

/// 某个 IP 是否属于禁止 egress 的范围(SSRF 硬底线,倾向「只放行 global-unicast」)。
pub fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()                       // 127.0.0.0/8
                || v4.is_private()                 // 10/8, 172.16/12, 192.168/16
                || v4.is_link_local()              // 169.254/16(含 metadata 169.254.169.254)
                || v4.is_unspecified()             // 0.0.0.0
                || v4.is_broadcast()               // 255.255.255.255
                || v4.is_multicast()               // 224.0.0.0/4
                || v4.is_documentation()           // 192.0.2/24, 198.51.100/24, 203.0.113/24
                || o[0] == 0                        // 0.0.0.0/8「本网络」
                || o[0] >= 240                      // 240/4 保留/未来用(含 broadcast)
                || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64/10 CGNAT
                || (o[0] == 192 && o[1] == 88 && o[2] == 99) // 192.88.99/24 6to4 relay
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()               // ff00::/8
                || is_ula(v6)                      // fc00::/7 唯一本地
                || is_link_local_v6(v6)            // fe80::/10
                || v6.to_ipv4().map_or(false, |m| is_blocked_ip(IpAddr::V4(m))) // ::ffff:x / ::x 映射
        }
    }
}

/// 规范化 HTTP request-target 并返回**canonical target**(allowlist 与写请求行都用它)。
/// 关闭「代理/后端解释差异」的 allowlist 绕过(newton P1):
/// - 必须 origin-form 单斜杠起始(拒 `//`、absolute/authority-form);
/// - 拒所有反斜杠、CR/LF/NUL/control/DEL/空白;
/// - 严格 `%HH`:拒 percent-encoded `/`(%2f)、`\`(%5c)、`.`(%2e)与 malformed escape;
/// - 对 path 做 RFC3986 dot-segment 归并(`.`/`..`),`..` 穿越到根之上即拒;
/// - query(`?` 之后)保留但同样过控制字符/`%HH` 检查。
pub fn canonical_request_target(raw: &str) -> Result<String, String> {
    if !raw.starts_with('/') {
        return Err(format!("request-target 必须以 / 起始: {:?}", raw));
    }
    if raw.starts_with("//") {
        return Err(format!("拒绝 // 开头(authority-form 歧义): {:?}", raw));
    }
    for b in raw.bytes() {
        if b < 0x20 || b == 0x7f || b == b' ' || b == b'\\' {
            return Err(format!("request-target 含非法字符(control/空白/反斜杠): {:?}", raw));
        }
    }
    let (path, query) = match raw.find('?') {
        Some(i) => (&raw[..i], Some(&raw[i..])),
        None => (raw, None),
    };
    reject_bad_percent(path)?;
    if let Some(q) = query {
        reject_bad_percent(q)?;
    }
    let norm = remove_dot_segments(path)?;
    Ok(match query {
        Some(q) => format!("{}{}", norm, q),
        None => norm,
    })
}

fn hexval(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// 拒绝 malformed `%HH` 与 percent-encoded 分隔符/点(%2f `/`、%5c `\`、%2e `.`)。
fn reject_bad_percent(s: &str) -> Result<(), String> {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if i + 2 >= b.len() {
                return Err(format!("malformed %-escape: {:?}", s));
            }
            let h = (hexval(b[i + 1]), hexval(b[i + 2]));
            let (h1, h2) = match h {
                (Some(a), Some(b)) => (a, b),
                _ => return Err(format!("malformed %-escape: {:?}", s)),
            };
            let dec = (h1 << 4) | h2;
            if dec == b'/' || dec == b'\\' || dec == b'.' {
                return Err(format!("拒绝 percent-encoded separator/dot(%{:02X}): {:?}", dec, s));
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    Ok(())
}

/// RFC3986 5.2.4 dot-segment 归并;path 以 `/` 起始;`..` 穿越根之上返回 Err。
fn remove_dot_segments(path: &str) -> Result<String, String> {
    let mut out: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {} // 折叠前导/冗余斜杠与 "."
            ".." => {
                if out.pop().is_none() {
                    return Err(format!("路径穿越到根之上: {:?}", path));
                }
            }
            s => out.push(s),
        }
    }
    Ok(format!("/{}", out.join("/")))
}

/// 校验 host 为合法 DNS name / IP literal(仅 alnum/`.`/`-`/`:`/`[]`,无 control/空白)。
/// 完整 host grammar 校验:只接受 ①`[IPv6]` literal ②IPv4 literal ③RFC1123 DNS 主机名。
/// 不接受端口(port 是 GRANT_HTTP 的独立字段);拒空 label、前导/尾随/连续点、超长 label、
/// 连字符起止、下划线/控制字符/空白、以及"全数字点分"(形似 IPv4 却非法,如 `1.2.3.4.5`)。
pub fn valid_host(host: &str) -> Result<(), String> {
    if host.is_empty() || host.len() > 253 {
        return Err(format!("host 非法长度: {:?}", host));
    }
    // ① IPv6 literal:必须 [..] 包裹,内部须是合法 IPv6
    if host.starts_with('[') {
        if !host.ends_with(']') || host.len() < 3 {
            return Err(format!("IPv6 literal 括号不匹配: {:?}", host));
        }
        return host[1..host.len() - 1]
            .parse::<std::net::Ipv6Addr>()
            .map(|_| ())
            .map_err(|_| format!("非法 IPv6 literal: {:?}", host));
    }
    // 括号/冒号只应出现在 IPv6 literal(已在上面处理);此处出现即非法(防 `a]b`、裸端口、注入)
    if host.contains('[') || host.contains(']') || host.contains(':') {
        return Err(format!("host 含非法字符([]:): {:?}", host));
    }
    // ② IPv4 literal
    if host.parse::<std::net::Ipv4Addr>().is_ok() {
        return Ok(());
    }
    // ③ RFC1123 DNS 主机名:按 `.` 分 label,每 label 1..=63、仅 alnum/`-`、不以 `-` 起止
    let mut all_numeric = true;
    for label in host.split('.') {
        let b = label.as_bytes();
        if b.is_empty() || b.len() > 63 {
            return Err(format!("host label 长度非法(空/连续点/超 63): {:?}", host));
        }
        if b[0] == b'-' || b[b.len() - 1] == b'-' {
            return Err(format!("host label 不得以连字符起止: {:?}", host));
        }
        for &c in b {
            if !(c.is_ascii_alphanumeric() || c == b'-') {
                return Err(format!("host label 含非法字符(仅 alnum/-): {:?}", host));
            }
            if !c.is_ascii_digit() {
                all_numeric = false;
            }
        }
    }
    // 全数字点分(`1.2.3.4.5`、`999.1`)既非合法 IPv4 又冒充 IP → 拒
    if all_numeric {
        return Err(format!("host 形似 IPv4 但非法: {:?}", host));
    }
    Ok(())
}

fn is_ula(v6: Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xfe00) == 0xfc00
}
fn is_link_local_v6(v6: Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xffc0) == 0xfe80
}

/// 解析 host:port,拒绝 metadata 主机名与任何解析到被禁 IP 的主机(DNS-rebind 防护)。
/// 返回解析出的地址 —— 调用方必须连接这些地址,不得再重解析(关闭 TOCTOU 窗口)。
pub fn resolve_checked(host: &str, port: u16) -> Result<Vec<SocketAddr>, String> {
    let hl = host.to_ascii_lowercase();
    if METADATA_HOSTS.iter().any(|m| hl == *m) {
        return Err(format!("egress 拒绝:metadata 主机 {}", host));
    }
    let addrs: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("DNS 解析失败: {}", e))?
        .collect();
    if addrs.is_empty() {
        return Err(format!("egress 拒绝:{} 无解析结果", host));
    }
    for a in &addrs {
        if is_blocked_ip(a.ip()) {
            return Err(format!(
                "egress 拒绝:{} 解析到被禁 IP {}(private/loopback/link-local/metadata)",
                host,
                a.ip()
            ));
        }
    }
    Ok(addrs)
}

/// glob 匹配 path pattern:`*`=单段,`**`=任意;用于 HttpCap 的 path allowlist。
pub fn path_matches(pattern: &str, path: &str) -> bool {
    let pp: Vec<&str> = pattern.trim_matches('/').split('/').collect();
    let qp: Vec<&str> = path.trim_matches('/').split('/').collect();
    seg_match(&pp, &qp)
}

fn seg_match(pat: &[&str], q: &[&str]) -> bool {
    match (pat.first(), q.first()) {
        (None, None) => true,
        (Some(&"**"), _) => {
            // ** 吞 0..n 段
            (0..=q.len()).any(|i| seg_match(&pat[1..], &q[i..]))
        }
        (Some(&"*"), Some(_)) => seg_match(&pat[1..], &q[1..]),
        (Some(a), Some(b)) if a == b => seg_match(&pat[1..], &q[1..]),
        _ => false,
    }
}

pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// GET over 明文 HTTP,连接到**预解析的地址**(不再重解析,关 DNS-rebind);
/// Host 头固定为 cap 的 host;byte-limited;超时;**不跟随重定向**(避免跨 origin SSRF)。
/// https 需 TLS(离线无 rustls),此处只做 http://。
pub fn fetch_get(addr: SocketAddr, authority: &str, path: &str, max_bytes: usize) -> Result<HttpResponse, String> {
    // 防御:path/authority 必须已在上游校验无 CR/LF/control;此处再兜一层 fail-closed。
    if path.bytes().any(|b| b < 0x20 || b == 0x7f)
        || authority.bytes().any(|b| b < 0x20 || b == 0x7f || b == b' ')
    {
        return Err("fetch_get 拒绝:path/authority 含控制字符(注入防护)".into());
    }
    let mut stream =
        TcpStream::connect_timeout(&addr, Duration::from_secs(10)).map_err(|e| format!("connect 失败: {}", e))?;
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(10))).ok();
    let req = format!(
        "GET {} HTTP/1.0\r\nHost: {}\r\nUser-Agent: capable/0.1\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        path, authority
    );
    stream.write_all(req.as_bytes()).map_err(|e| format!("write 失败: {}", e))?;
    let mut raw = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = stream.read(&mut buf).map_err(|e| format!("read 失败: {}", e))?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&buf[..n]);
        if raw.len() > max_bytes {
            raw.truncate(max_bytes);
            break;
        }
    }
    parse_http_response(&raw)
}

fn parse_http_response(raw: &[u8]) -> Result<HttpResponse, String> {
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("HTTP 响应无 header 结束")?;
    let head = &raw[..sep];
    let body = raw[sep + 4..].to_vec();
    let first: &[u8] = head.split(|&c| c == b'\r' || c == b'\n').next().unwrap_or(&[]);
    let first_s = String::from_utf8_lossy(first);
    let status: u16 = first_s
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or("无法解析 HTTP status")?;
    Ok(HttpResponse { status, body })
}

#[cfg(test)]
mod t {
    use super::*;

    #[test]
    fn blocks_metadata_and_private() {
        assert!(resolve_checked("metadata.google.internal", 80).is_err());
        assert!(resolve_checked("169.254.169.254", 80).is_err());
        assert!(resolve_checked("10.0.0.1", 80).is_err());
        assert!(resolve_checked("192.168.1.1", 80).is_err());
        assert!(resolve_checked("127.0.0.1", 80).is_err());
        assert!(resolve_checked("localhost", 80).is_err()); // 解析到 loopback
    }

    #[test]
    fn ip_classification() {
        assert!(is_blocked_ip("169.254.169.254".parse().unwrap()));
        assert!(is_blocked_ip("10.1.2.3".parse().unwrap()));
        assert!(is_blocked_ip("::1".parse().unwrap()));
        assert!(is_blocked_ip("fe80::1".parse().unwrap()));
        assert!(!is_blocked_ip("93.184.216.34".parse().unwrap())); // example.com,公网
        assert!(!is_blocked_ip("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn path_glob() {
        assert!(path_matches("/v1/*", "/v1/models"));
        assert!(!path_matches("/v1/*", "/v1/models/x")); // * 只一段
        assert!(path_matches("/v1/**", "/v1/a/b/c"));
        assert!(path_matches("/v1/**", "/v1"));
        assert!(!path_matches("/v1/*", "/v2/models"));
    }

    #[test]
    fn canonical_target_and_injection_and_normalization() {
        // 正常
        assert_eq!(canonical_request_target("/v1/models").unwrap(), "/v1/models");
        assert_eq!(canonical_request_target("/v1/a/../b").unwrap(), "/v1/b"); // dot-segment 归并
        assert_eq!(canonical_request_target("/v1//models").unwrap(), "/v1/models"); // 冗余斜杠折叠
        assert_eq!(canonical_request_target("/v1/models?x=1").unwrap(), "/v1/models?x=1"); // query 保留
        // CRLF / NUL / 空白 / absolute / 不以 / 起始
        assert!(canonical_request_target("/a\r\nX-Original-URL: /admin").is_err());
        assert!(canonical_request_target("/a\0b").is_err());
        assert!(canonical_request_target("/a b").is_err());
        assert!(canonical_request_target("http://evil/").is_err());
        assert!(canonical_request_target("admin").is_err());
        // newton 的 4 个绕过样例 + //
        assert!(canonical_request_target("//host/x").is_err()); // authority 歧义
        assert!(canonical_request_target("/v1/%2e%2e/admin").is_err()); // %2e (.)
        assert!(canonical_request_target("/v1/%2f..%2fadmin").is_err()); // %2f (/)
        assert!(canonical_request_target("/v1/%5c..%5cadmin").is_err()); // %5c (\)
        assert!(canonical_request_target("/v1/\\..\\admin").is_err()); // 反斜杠
        assert!(canonical_request_target("/%GG").is_err()); // malformed escape
        assert!(canonical_request_target("/..").is_err()); // 穿越根之上
        // host —— 合法
        assert!(valid_host("api.example.com").is_ok());
        assert!(valid_host("a-b.example.com").is_ok());
        assert!(valid_host("x1.y2.z3").is_ok());
        assert!(valid_host("[2001:db8::1]").is_ok());
        assert!(valid_host("93.184.216.34").is_ok()); // IPv4 literal
        // host —— 非法(完整 grammar)
        assert!(valid_host("evil\r\nHost: x").is_err()); // CRLF 注入
        assert!(valid_host("a b").is_err()); // 空白
        assert!(valid_host("a..b").is_err()); // 连续点(空 label)
        assert!(valid_host(".example.com").is_err()); // 前导点
        assert!(valid_host("example.com.").is_err()); // 尾随点
        assert!(valid_host("-a.example.com").is_err()); // label 前导连字符
        assert!(valid_host("a-.example.com").is_err()); // label 尾随连字符
        assert!(valid_host("under_score.example.com").is_err()); // 下划线非法
        assert!(valid_host("1.2.3.4.5").is_err()); // 形似 IPv4 但非法(全数字点分)
        assert!(valid_host("999.1").is_err()); // 全数字非合法 IPv4
        assert!(valid_host("[2001:db8::1").is_err()); // IPv6 括号不匹配
        assert!(valid_host("[not-an-ip]").is_err()); // 括号内非 IPv6
        assert!(valid_host("a]b").is_err()); // 杂散括号
        assert!(valid_host("host:8080").is_err()); // 不接受内嵌端口
        assert!(valid_host(&"a".repeat(64)).is_err()); // label 超 63
    }

    #[test]
    fn blocks_reserved_and_multicast() {
        assert!(is_blocked_ip("0.0.0.1".parse().unwrap())); // 0/8
        assert!(is_blocked_ip("224.0.0.1".parse().unwrap())); // multicast
        assert!(is_blocked_ip("239.255.255.250".parse().unwrap())); // SSDP multicast
        assert!(is_blocked_ip("240.0.0.1".parse().unwrap())); // 240/4 reserved
        assert!(is_blocked_ip("255.255.255.255".parse().unwrap())); // broadcast
        assert!(is_blocked_ip("192.0.2.1".parse().unwrap())); // TEST-NET-1 documentation
        assert!(is_blocked_ip("ff02::1".parse().unwrap())); // ipv6 multicast
        assert!(!is_blocked_ip("93.184.216.34".parse().unwrap())); // 公网仍放行
    }
}
