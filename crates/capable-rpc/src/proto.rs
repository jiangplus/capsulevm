//! CapTP-lite 线协议:length-prefixed 帧 + tab 分隔文本 + base64 二进制。
//! cap 引用是会话绑定的不可伪造 token。请求作用在能力引用上(能力传递 RPC)。

use capable_broker::{parse_ops, Policy, Role, Session, Taint};
use std::io::{self, Read, Write};

pub const US: char = '\u{1f}'; // argv 分隔符(unit separator)

/// 单帧上限(8 MiB,覆盖最大 base64 膨胀)。攻击者可宣称任意 u32 长度,必须先校验再分配。
pub const MAX_FRAME: usize = 8 * 1024 * 1024;

// ---- 帧:4 字节大端长度 + body ----

pub fn write_frame<W: Write>(w: &mut W, body: &[u8]) -> io::Result<()> {
    let len = body.len() as u32;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(body)?;
    w.flush()
}

pub fn read_frame<R: Read>(r: &mut R) -> io::Result<Option<Vec<u8>>> {
    // 手动读 4 字节头,区分「干净 EOF(0 字节)」与「半个头(协议截断)」。
    let mut lenb = [0u8; 4];
    let mut got = 0;
    while got < 4 {
        match r.read(&mut lenb[got..]) {
            Ok(0) => {
                if got == 0 {
                    return Ok(None); // 干净 EOF:对端正常关闭
                }
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "帧头截断(协议错误)"));
            }
            Ok(n) => got += n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    let len = u32::from_be_bytes(lenb) as usize;
    if len > MAX_FRAME {
        // 先拒绝再分配:防单连接宣称 4GiB 帧耗尽内存
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("帧过大: {} > MAX_FRAME({})", len, MAX_FRAME),
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(Some(buf))
}

// ---- base64(标准字母表,std-only) ----

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn b64_encode(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32);
        out.push(B64[((n >> 18) & 63) as usize] as char);
        out.push(B64[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 { B64[((n >> 6) & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64[(n & 63) as usize] as char } else { '=' });
    }
    out
}

pub fn b64_decode(s: &str) -> Vec<u8> {
    let val = |c: u8| -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };
    let cs: Vec<u8> = s.bytes().filter(|&c| c != b'=').collect();
    let mut out = Vec::new();
    for chunk in cs.chunks(4) {
        let mut n = 0u32;
        let mut bits = 0;
        for &c in chunk {
            if let Some(v) = val(c) {
                n = (n << 6) | v;
                bits += 6;
            }
        }
        n <<= 24 - bits;
        let nbytes = (bits) / 8;
        for i in 0..nbytes {
            out.push(((n >> (16 - i * 8)) & 0xff) as u8);
        }
    }
    out
}

// ---- 请求分发 ----

/// 处理一条请求,返回一条回复(纯文本 body)。回复形态:
/// `CAP\t<ref>` | `OK\t<taint>\t<b64>` | `ERR\t<msg>`
pub fn handle(sess: &mut Session, policy: &Policy, body: &str) -> String {
    let f: Vec<&str> = body.split('\t').collect();
    let verb = f.first().copied().unwrap_or("");
    // guest wire 无任何 mint verb(newton P0):mint 仅 control 面;guest 用 BOOTSTRAP + DERIVE。
    let deny_guest_mint = |verb: &str| -> Result<(), String> {
        if policy.role == Role::Guest {
            Err(format!(
                "{}:guest 不能铸造能力。用 BOOTSTRAP 取预注入根 + DERIVE;mint 仅 control 面。",
                verb
            ))
        } else {
            Ok(())
        }
    };
    let res: Result<String, String> = (|| match verb {
        "BOOTSTRAP" => Ok(format!("CAP\t{}", sess.take_bootstrap()?)),
        "GRANT_DIR" => {
            deny_guest_mint("GRANT_DIR")?;
            let root = f.get(1).ok_or("GRANT_DIR 缺 root")?;
            let ops = parse_ops(f.get(2).unwrap_or(&"read"));
            let taint = Taint::parse(f.get(3).unwrap_or(&"project"));
            Ok(format!("CAP\t{}", sess.grant_dir(root, ops, taint)?))
        }
        "GRANT_SINK" => {
            deny_guest_mint("GRANT_SINK")?;
            let name = f.get(1).ok_or("GRANT_SINK 缺 name")?;
            Ok(format!("CAP\t{}", sess.grant_sink(name)))
        }
        "GRANT_HTTP" => {
            deny_guest_mint("GRANT_HTTP")?;
            // GRANT_HTTP\t<scheme>\t<host>\t<port>\t<methods csv>\t<paths \x1f>\t<max_bytes>
            let scheme = f.get(1).ok_or("GRANT_HTTP 缺 scheme")?;
            let host = f.get(2).ok_or("GRANT_HTTP 缺 host")?;
            let port: u16 = f.get(3).and_then(|s| s.parse().ok()).ok_or("GRANT_HTTP 缺/坏 port")?;
            let methods: Vec<String> = f.get(4).unwrap_or(&"GET").split(',').map(|s| s.trim().to_uppercase()).collect();
            let paths: Vec<String> = f.get(5).unwrap_or(&"/**").split(US).map(|s| s.to_string()).collect();
            let max_bytes: usize = f.get(6).and_then(|s| s.parse().ok()).unwrap_or(1_048_576);
            Ok(format!("CAP\t{}", sess.grant_http(scheme, host, port, methods, paths, max_bytes)?))
        }
        "GRANT_MSG" => {
            // 铸造新 mailbox = 凭空造接收者/授权,属 mint,guest 拒(但 guest 可用被委托的 MessageCap)
            deny_guest_mint("GRANT_MSG")?;
            let recipient = f.get(1).ok_or("GRANT_MSG 缺 recipient")?;
            Ok(format!("CAP\t{}", sess.grant_message(recipient)))
        }
        "GRANT_CMD" => {
            deny_guest_mint("GRANT_CMD")?;
            let cwd = f.get(1).ok_or("GRANT_CMD 缺 cwd_ref")?;
            let argv: Vec<String> = f
                .get(2)
                .unwrap_or(&"")
                .split(US)
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect();
            Ok(format!("CAP\t{}", sess.grant_command(cwd, argv)?))
        }
        "DERIVE" => {
            let r = f.get(1).ok_or("DERIVE 缺 ref")?;
            match *f.get(2).ok_or("DERIVE 缺 how")? {
                "sub" => Ok(format!("CAP\t{}", sess.derive_sub(r, f.get(3).ok_or("sub 缺 seg")?)?)),
                "readonly" => Ok(format!("CAP\t{}", sess.derive_readonly(r)?)),
                // MessageCap 衰减:msg_prefix=限定主题命名空间;msg_oneshot=单次投递 facet
                "msg_prefix" => Ok(format!("CAP\t{}", sess.derive_msg_prefix(r, f.get(3).ok_or("msg_prefix 缺 前缀")?)?)),
                "msg_oneshot" => Ok(format!("CAP\t{}", sess.derive_msg_oneshot(r)?)),
                other => Err(format!("未知 DERIVE {}", other)),
            }
        }
        "INVOKE" => {
            let r = f.get(1).ok_or("INVOKE 缺 ref")?;
            match *f.get(2).ok_or("INVOKE 缺 verb")? {
                "read" => {
                    let (t, data) = sess.read(r, f.get(3).unwrap_or(&""))?;
                    Ok(format!("OK\t{}\t{}", t.as_str(), b64_encode(&data)))
                }
                "list" => {
                    let data = sess.list(r, f.get(3).unwrap_or(&""))?;
                    Ok(format!("OK\tproject\t{}", b64_encode(&data)))
                }
                "exec" => {
                    let data = sess.exec(r)?;
                    Ok(format!("OK\tyellow\t{}", b64_encode(&data)))
                }
                "http_get" => {
                    let (t, data) = sess.http_get(r, f.get(3).unwrap_or(&"/"))?;
                    Ok(format!("OK\t{}\t{}", t.as_str(), b64_encode(&data)))
                }
                "send" => {
                    let taint = Taint::parse(f.get(3).unwrap_or(&"green"));
                    let data = b64_decode(f.get(4).unwrap_or(&""));
                    sess.send(r, taint, &data)?;
                    Ok("OK\t\t".to_string())
                }
                // MessageCap 投递字面文本:INVOKE <ref> post <subject> <body-b64>
                // taint 由服务端固定 Green —— wire **不能命名 taint**(关 IFC 洗白)。
                "post" => {
                    let subject = f.get(3).ok_or("post 缺 subject")?;
                    let body = String::from_utf8_lossy(&b64_decode(f.get(4).unwrap_or(&""))).into_owned();
                    sess.post(r, subject, &body)?;
                    Ok("OK\t\t".to_string())
                }
                // 转发投递:INVOKE <ref> post_from <subject> <src_ref> <rel>
                // taint 由服务端按源判定(secret 源 → Secret → IFC 拒)。
                "post_from" => {
                    let subject = f.get(3).ok_or("post_from 缺 subject")?;
                    let src = f.get(4).ok_or("post_from 缺 src_ref")?;
                    let rel = f.get(5).unwrap_or(&"");
                    sess.post_from(r, subject, src, rel)?;
                    Ok("OK\t\t".to_string())
                }
                // 读收件箱(仅收件 facet):OK\t\t<b64 of "taint\tsubject\tbody" per line>
                "mailbox_read" => {
                    let msgs = sess.mailbox_read(r)?;
                    let dump: String = msgs
                        .iter()
                        .map(|(subj, t, body)| format!("{}\t{}\t{}", t.as_str(), subj, body))
                        .collect::<Vec<_>>()
                        .join("\n");
                    Ok(format!("OK\t\t{}", b64_encode(dump.as_bytes())))
                }
                other => Err(format!("未知 INVOKE verb {}", other)),
            }
        }
        "REVOKE" => {
            sess.revoke(f.get(1).ok_or("REVOKE 缺 ref")?)?;
            Ok("OK\t\t".to_string())
        }
        // L5 JIT consent 审批:仅 control 面可批准/拒绝(guest 不能自批自己的请求)
        "CONSENT_APPROVE" => {
            if policy.role == Role::Guest {
                return Err("consent 审批仅 control 面".to_string());
            }
            let summary = sess.consent_approve(f.get(1).ok_or("CONSENT_APPROVE 缺 id")?)?;
            Ok(format!("OK\t\t{}", b64_encode(summary.as_bytes())))
        }
        "CONSENT_DENY" => {
            if policy.role == Role::Guest {
                return Err("consent 审批仅 control 面".to_string());
            }
            let summary = sess.consent_deny(f.get(1).ok_or("CONSENT_DENY 缺 id")?)?;
            Ok(format!("OK\t\t{}", b64_encode(summary.as_bytes())))
        }
        // 完整审批详情(argv/env/cwd,可能含 env 凭据)—— **仅 control 面**;requester 的 CONSENT 帧不含它
        "CONSENT_DESCRIBE" => {
            if policy.role == Role::Guest {
                return Err("consent 详情仅 control 面(含敏感 env)".to_string());
            }
            let detail = sess.consent_describe(f.get(1).ok_or("CONSENT_DESCRIBE 缺 id")?)?;
            Ok(format!("OK\t\t{}", b64_encode(detail.as_bytes())))
        }
        "CONSENT_LIST" => {
            if policy.role == Role::Guest {
                return Err("consent 列表仅 control 面".to_string());
            }
            let dump: String = sess
                .consent_list()
                .iter()
                .map(|(id, sess_key, detail)| format!("{}\t{}\t{}", id, sess_key, detail))
                .collect::<Vec<_>>()
                .join("\n");
            Ok(format!("OK\t\t{}", b64_encode(dump.as_bytes())))
        }
        "DESCRIBE" => Ok(format!("OK\t\t{}", sess.describe(f.get(1).ok_or("缺 ref")?)?)),
        "AUDIT" => {
            let mut out = String::new();
            for e in sess.audit_log() {
                out.push_str(&format!(
                    "#{:<3} {:<14} [{}] {}  {}\n",
                    e.seq,
                    e.op,
                    e.decision,
                    e.detail,
                    &e.hash[..12]
                ));
            }
            out.push_str(&format!(
                "in_process_chain_verify: {}(仅进程内完整性;持久化+锚点见 --audit-log)\n",
                if sess.verify_audit() { "ok" } else { "BROKEN" }
            ));
            Ok(format!("OK\t\t{}", b64_encode(out.as_bytes())))
        }
        other => Err(format!("未知 verb {}", other)),
    })();
    match res {
        Ok(s) => s,
        // L5 gate 需要 JIT 授权时返回 `__CONSENT__\t<id>\t<summary>` → 转成 CONSENT 帧
        // (区别于普通 ERR;客户端据此走审批流程后重放该动作)。
        Err(e) if e.starts_with(capable_broker::policy::CONSENT_REQUIRED) => {
            let rest = e.strip_prefix(capable_broker::policy::CONSENT_REQUIRED).unwrap_or("");
            format!("CONSENT{}", rest) // rest 已以 \t<id>\t<summary> 起始
        }
        Err(e) => format!("ERR\t{}", e),
    }
}

#[cfg(test)]
mod t {
    use super::*;
    use capable_broker::Session;

    #[test]
    fn guest_cannot_mint_bootstrap_oneshot_control_can() {
        let ws = std::env::temp_dir().join("proto_ws_test");
        std::fs::create_dir_all(&ws).unwrap();
        let ws = ws.to_string_lossy().into_owned();
        let mut sess = Session::new();
        sess.set_bootstrap(&ws);
        let pol = Policy::guest(&ws);
        // P0 回归:guest 的所有 mint verb 都被拒
        assert!(handle(&mut sess, &pol, &format!("GRANT_DIR\t{}\tread\tproject", ws)).starts_with("ERR"));
        assert!(handle(&mut sess, &pol, "GRANT_SINK\tx").starts_with("ERR"));
        assert!(handle(&mut sess, &pol, "GRANT_HTTP\thttp\texample.com\t80\tGET\t/**\t4096").starts_with("ERR"));
        assert!(handle(&mut sess, &pol, "GRANT_MSG\tagent:x").starts_with("ERR"), "guest 不得铸新 mailbox");
        // BOOTSTRAP 返回预注入根,且一次性
        let b = handle(&mut sess, &pol, "BOOTSTRAP");
        assert!(b.starts_with("CAP"), "BOOTSTRAP 应返回预注入根: {}", b);
        assert!(handle(&mut sess, &pol, "BOOTSTRAP").starts_with("ERR"), "BOOTSTRAP 必须一次性");
        // 拿到 dir ref 也不能 GRANT_CMD(否则 = 任意命令执行)
        let capref = b.split('\t').nth(1).unwrap();
        assert!(handle(&mut sess, &pol, &format!("GRANT_CMD\t{}\t/bin/sh", capref)).starts_with("ERR"));
        // control 面可 mint
        let mut csess = Session::new();
        let cpol = Policy::control();
        assert!(handle(&mut csess, &cpol, &format!("GRANT_DIR\t{}\tread\tproject", ws)).starts_with("CAP"));
        // control 铸 MessageCap → owner 字面投递 + 委托只投递 facet(禁字面)→ owner 读(端到端 over handle)
        let m = handle(&mut csess, &cpol, "GRANT_MSG\tagent:newton");
        let owner = m.split('\t').nth(1).unwrap().to_string();
        let body = b64_encode(b"green-msg");
        // owner(读+投递 facet)可字面投递自有 mailbox
        assert!(handle(&mut csess, &cpol, &format!("INVOKE\t{}\tpost\thi\t{}", owner, body)).starts_with("OK"));
        let d = handle(&mut csess, &cpol, &format!("DERIVE\t{}\tmsg_prefix\tbuild/", owner));
        let deleg = d.split('\t').nth(1).unwrap().to_string();
        // 委托(只投递)facet 禁止字面投递(防 taint 洗白)
        assert!(handle(&mut csess, &cpol, &format!("INVOKE\t{}\tpost\tbuild/ok\t{}", deleg, body)).starts_with("ERR"));
        // 只投递 facet 不能读收件箱
        assert!(handle(&mut csess, &cpol, &format!("INVOKE\t{}\tmailbox_read", deleg)).starts_with("ERR"));
        // owner 读到 1 条(自投的 hi)
        let inbox = handle(&mut csess, &cpol, &format!("INVOKE\t{}\tmailbox_read", owner));
        assert!(inbox.starts_with("OK"), "owner 应能读收件箱: {}", inbox);
    }

    #[test]
    fn oversized_frame_rejected_before_alloc() {
        let mut data = Vec::new();
        data.extend_from_slice(&(100u32 * 1024 * 1024).to_be_bytes()); // 声明 100 MiB
        let mut cur = std::io::Cursor::new(data);
        assert!(read_frame(&mut cur).is_err(), "超大帧必须在分配前被拒");
    }

    #[test]
    fn truncated_header_is_error_not_eof() {
        let mut cur = std::io::Cursor::new(vec![0u8, 0u8]); // 只有 2 字节头
        match read_frame(&mut cur) {
            Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof),
            Ok(_) => panic!("半个头必须报截断,而非静默 EOF"),
        }
    }

    #[test]
    fn clean_eof_is_none() {
        let mut cur = std::io::Cursor::new(Vec::<u8>::new());
        assert!(matches!(read_frame(&mut cur), Ok(None)), "干净 EOF 应为 None");
    }

    #[test]
    fn l5_consent_wire_flow_and_guest_cannot_self_approve() {
        use capable_broker::policy::{ConsentLedger, PolicyEngine};
        use std::sync::{Arc, Mutex};
        let root = std::env::temp_dir().join(format!("proto_l5_{}", capable_broker::rand_hex(6)));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("x"), b"x").unwrap();
        let root = root.to_string_lossy().into_owned();
        let ledger = Arc::new(Mutex::new(ConsentLedger::new()));

        // 请求方会话:策略要求 exec 需 JIT consent;共享 ledger(用 control policy 便于本地 mint)
        let mut g = Session::new();
        g.set_policy(PolicyEngine { prompt_exec: true, ..PolicyEngine::allow_all() });
        g.set_consent(ledger.clone());
        let cpol = Policy::control();
        let dref = {
            let d = handle(&mut g, &cpol, &format!("GRANT_DIR\t{}\tread,list,exec\tproject", root));
            d.split('\t').nth(1).unwrap().to_string()
        };
        let cref = {
            let c = handle(&mut g, &cpol, &format!("GRANT_CMD\t{}\t/bin/echo{}hi", dref, US));
            c.split('\t').nth(1).unwrap().to_string()
        };

        // exec → CONSENT 帧(而非 OK/ERR)
        let r = handle(&mut g, &cpol, &format!("INVOKE\t{}\texec", cref));
        assert!(r.starts_with("CONSENT\t"), "应回 CONSENT 帧: {}", r);
        let id = r.split('\t').nth(1).unwrap().to_string();

        // guest 面不能自批 consent,也不能读详情/列表(含敏感 env)
        let gpol = Policy::guest(&root);
        assert!(handle(&mut g, &gpol, &format!("CONSENT_APPROVE\t{}", id)).starts_with("ERR"), "guest 不得自批");
        assert!(handle(&mut g, &gpol, &format!("CONSENT_DESCRIBE\t{}", id)).starts_with("ERR"), "guest 不得读 consent 详情");
        assert!(handle(&mut g, &gpol, "CONSENT_LIST").starts_with("ERR"), "guest 不得列 consent");

        // 控制面(共享同一 ledger)批准
        let mut c = Session::new();
        c.set_consent(ledger.clone());
        assert!(handle(&mut c, &cpol, &format!("CONSENT_APPROVE\t{}", id)).starts_with("OK"));

        // 请求方重放 → OK(echo hi)
        let r2 = handle(&mut g, &cpol, &format!("INVOKE\t{}\texec", cref));
        assert!(r2.starts_with("OK"), "批准后 exec 应成功: {}", r2);
        // 一次性:再 exec 又回 CONSENT
        assert!(handle(&mut g, &cpol, &format!("INVOKE\t{}\texec", cref)).starts_with("CONSENT\t"));
    }
}
