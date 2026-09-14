//! 审计持久化(A4)。**全局** hash-chain 事件落 append-only 文件 + anchor(count+head)。
//! 链状态(seq/head)由 AuditSink 在同一把锁内持有并分配,多会话共享同一 sink 仍是一条
//! 全局连续链;每条事件写入 session identity 参与哈希。
//!
//! 崩溃恢复(newton P1):
//! - record:log append 后 `sync_data()`;anchor 走 临时文件 → `sync_all()` → 原子 rename →
//!   fsync 父目录。任一步失败 -> record 返回 Err -> 调用方 fail-closed(exec/send 不执行)。
//! - open:不盲信 anchor;重放并验证 log 得到 (count, head),要求 anchor 与之一致;
//!   log/anchor 缺失/损坏/不一致 -> 拒绝启动(不从伪 head 续坏链)。
//! - 崩溃状态矩阵:log 领先 anchor(record 中途崩)-> 重启时 replay 得到的 count 与 anchor 不符
//!   -> open 拒绝(fail-closed),需人工裁定。
//!
//! 诚实边界:append-only 完整性 + 锚点尾截检测,非完整 tamper-evident(对能同时改 log+anchor
//! 的写者需外部签名 DSSE/Sigstore,后续)。

use crate::sha256;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

pub struct AuditSink {
    log: File,
    log_path: String,
    anchor_path: String,
    count: u64,
    head: String,
}

/// 重放并验证 log,返回最终 (count, head);链畸形/断裂/被改 -> Err。
fn replay(log_path: &str) -> Result<(u64, String), String> {
    let f = File::open(log_path).map_err(|e| e.to_string())?;
    let mut prev = String::from("GENESIS");
    let mut count = 0u64;
    let mut head = String::from("GENESIS");
    for (i, line) in BufReader::new(f).lines().enumerate() {
        let line = line.map_err(|e| e.to_string())?;
        let p: Vec<&str> = line.split('\t').collect();
        if p.len() != 7 {
            return Err(format!("log 第 {} 行字段数≠7", i));
        }
        let seq: u64 = p[0].parse().map_err(|_| "bad seq".to_string())?;
        if seq != i as u64 || p[5] != prev {
            return Err(format!("log 断链于 seq={}", i));
        }
        let content = format!("{}|{}|{}|{}|{}|{}", p[0], p[1], p[2], p[3], p[4], p[5]);
        if sha256::sha256_hex(content.as_bytes()) != p[6] {
            return Err(format!("log 第 {} 行内容被改", i));
        }
        prev = p[6].to_string();
        head = p[6].to_string();
        count = seq + 1;
    }
    Ok((count, head))
}

/// 原子写 anchor:临时文件 + fsync + rename + fsync 父目录。
fn write_anchor_atomic(anchor_path: &str, count: u64, head: &str) -> std::io::Result<()> {
    let tmp = format!("{}.tmp", anchor_path);
    {
        let mut f = File::create(&tmp)?;
        f.write_all(format!("{}\t{}", count, head).as_bytes())?;
        f.sync_all()?; // 临时文件内容落盘
    }
    std::fs::rename(&tmp, anchor_path)?; // 原子替换
    if let Some(parent) = Path::new(anchor_path).parent() {
        // fsync 父目录,持久化 rename 本身
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

impl AuditSink {
    /// 打开(或续写),fail-closed:重放验证 log 得 (count, head),要求 anchor 一致。
    pub fn open(log_path: &str) -> std::io::Result<AuditSink> {
        let anchor_path = format!("{}.anchor", log_path);
        let log_exists = Path::new(log_path).exists();
        let anchor_exists = Path::new(&anchor_path).exists();
        let inval = |m: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, m.to_string());

        // 重放 log 得 (count, head)(不存在或空 = 0/GENESIS)
        let (c, h) = if log_exists {
            replay(log_path).map_err(|e| inval(&format!("log 重放失败: {}", e)))?
        } else {
            (0u64, "GENESIS".to_string())
        };
        // 只有当 log 非空 或 anchor 已存在时才要求 anchor 与 (c,h) 一致(fail-closed);
        // 空 log + 无 anchor(如中断/未写过)= 合法新起。
        if c > 0 || anchor_exists {
            let anchor = std::fs::read_to_string(&anchor_path)
                .map_err(|_| inval("anchor 缺失/不可读,fail-closed"))?;
            let a: Vec<&str> = anchor.trim().split('\t').collect();
            if a.len() != 2 || a[0].parse::<u64>().ok() != Some(c) || a[1] != h {
                return Err(inval("anchor 与 log 不一致,fail-closed"));
            }
        }
        let (count, head) = (c, h);

        let log = OpenOptions::new().create(true).append(true).open(log_path)?;
        Ok(AuditSink {
            log,
            log_path: log_path.to_string(),
            anchor_path,
            count,
            head,
        })
    }

    /// 全局链下分配 seq/prev 并 durable append(fsync log + 原子 anchor)。失败向上传播 -> fail-closed。
    pub fn record(&mut self, session: &str, op: &str, detail: &str, dec: &str) -> std::io::Result<()> {
        let seq = self.count;
        let prev = self.head.clone();
        let content = format!("{}|{}|{}|{}|{}|{}", seq, session, op, detail, dec, prev);
        let hash = sha256::sha256_hex(content.as_bytes());
        writeln!(
            self.log,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            seq, session, op, detail, dec, prev, hash
        )?;
        self.log.flush()?;
        self.log.sync_data()?; // log 落盘(durable intent 的前提)
        write_anchor_atomic(&self.anchor_path, seq + 1, &hash)?; // 原子 anchor
        self.count = seq + 1;
        self.head = hash;
        Ok(())
    }

    pub fn log_path(&self) -> &str {
        &self.log_path
    }
}

/// 校验持久化审计:重放全局链 + anchor 比对。fail-closed:任何缺失/畸形/不符判失败。
pub fn verify_persisted(log_path: &str) -> Result<bool, String> {
    let (count, head) = match replay(log_path) {
        Ok(x) => x,
        Err(_) => return Ok(false),
    };
    let anchor = match std::fs::read_to_string(format!("{}.anchor", log_path)) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };
    let a: Vec<&str> = anchor.trim().split('\t').collect();
    if a.len() != 2 {
        return Ok(false);
    }
    match a[0].parse::<u64>() {
        Ok(n) if n == count && a[1] == head => Ok(true),
        _ => Ok(false),
    }
}
