//! capvm.rs — Capable VM 的 **cap-indexed syscall ABI**(Model 4 内核语义,DESIGN §3)。
//!
//! 传统内核(agentos/secure-exec 现状)用**字符串指名 + scope 策略**:
//!   `open("/repo/src/main.ts")`、`fetch("https://api.x/v1")` —— 存在 ambient authority
//!   (进程能凭空写出一个路径/URL 去试)。这是评估框架的 Model 1.5–2。
//!
//! capvm 把资源**指名方式从字符串改为能力句柄索引**(cap handle),让 cap-indexed 成为
//! 内核**原生 ABI**:
//!   `cap_read(h, "main.ts")` —— `h` 是本进程 C-list 里的一个句柄,指向 Broker 中的真实能力。
//!   **不存在** `open(路径字符串)` 这类 ambient 接口 —— 指名即授权,无句柄即无权。
//!
//! ## host / guest 边界(newton 复审 446936be)
//!
//! 关键:guest 拿到的 syscall 面**必须不含 Session/CapRef/install** —— 否则 guest 可
//! `sess.grant_dir(...)` 凭空铸能力,"只见 usize"就是空话。因此:
//!   - `GuestProcess` = **host 侧门面**:内部持有 `CList` + `&mut Session`。host/loader 用它
//!     `install`(把 Broker 能力装入 C-list)。Session 封在门面里,guest 触碰不到。
//!   - `Syscalls` = **交给 guest 的面**:方法**不接收 Session**,只按已装入句柄操作;
//!     无 `install`、无法取得 `CapRef`、无法 mint/derive raw 引用。把 `&mut dyn Syscalls`
//!     交给 guest 代码,即在**类型层面**把 guest 关进"只能用 loader 给的句柄集"。
//!
//! C-list(仿 Unix fd 表但不可伪造):guest 只见 `usize`;句柄每进程;零权限起步;
//! 装入仅 host/loader 侧。落地复用 Broker(openat2 RESOLVE_BENEATH + C1 沙箱 + L5 gate)为 L2 底层。
//! 内嵌进 secure-exec V8-isolate 内核(guest JS 永不持 Rust 引用、只经此 ABI)是更深集成
//! (需 fork,DESIGN §3 D-capvm)—— 此处先把内核语义 + host/guest 类型边界做实并单测。

use crate::{CapRef, Session, Taint};

type R<T> = Result<T, String>;

/// 能力表(C-list):句柄 = 下标;`None` = 空/已关闭槽位。纯数据 —— 不含 Session/mint 能力。
struct CList {
    entries: Vec<Option<CapRef>>,
}

impl CList {
    fn new() -> Self {
        CList { entries: Vec::new() }
    }
    /// 装入能力,返回句柄(复用空槽,否则追加;句柄小而稠密,像 fd)。
    fn install(&mut self, cap: CapRef) -> usize {
        if let Some(i) = self.entries.iter().position(|e| e.is_none()) {
            self.entries[i] = Some(cap);
            i
        } else {
            self.entries.push(Some(cap));
            self.entries.len() - 1
        }
    }
    /// 句柄 → CapRef。越界/已关闭 → 拒(伪造/悬垂句柄无授权)。
    fn resolve(&self, h: usize) -> R<CapRef> {
        self.entries
            .get(h)
            .and_then(|e| e.clone())
            .ok_or_else(|| format!("capvm: 句柄 {} 无效(越界/已关闭/伪造)—— 无 ambient authority", h))
    }
    fn close(&mut self, h: usize) -> R<()> {
        match self.entries.get_mut(h) {
            Some(slot @ Some(_)) => {
                *slot = None;
                Ok(())
            }
            _ => Err(format!("capvm: 关闭无效句柄 {}", h)),
        }
    }
    fn live(&self) -> usize {
        self.entries.iter().filter(|e| e.is_some()).count()
    }
}

/// **host 侧门面**:持 C-list + Session。零权限起步(空 C-list)。
/// host/loader 用 `install` 把能力带进进程;把 `syscalls()` 的 `&mut dyn Syscalls` 交给 guest。
pub struct GuestProcess<'a> {
    clist: CList,
    sess: &'a mut Session,
}

impl<'a> GuestProcess<'a> {
    /// 新进程:零权限(空 C-list)。Session 由 host 提供并封在门面内。
    pub fn new(sess: &'a mut Session) -> Self {
        GuestProcess { clist: CList::new(), sess }
    }

    /// **host/loader 侧接口**(guest 无此能力):把 Broker 能力装入 C-list,返回句柄。
    /// 这是唯一把 authority 带进进程的途径 —— 对应内核替你 open 后给你 fd。
    pub fn install(&mut self, cap: CapRef) -> usize {
        self.clist.install(cap)
    }

    /// 本进程当前活跃句柄数(confinement 断言用:进程 authority = 恰好其 C-list)。
    pub fn live_handles(&self) -> usize {
        self.clist.live()
    }

    /// 交给 guest 的 syscall 面:`&mut dyn Syscalls` —— 无 Session、无 CapRef、无 install。
    pub fn syscalls(&mut self) -> &mut dyn Syscalls {
        self
    }
}

/// **guest 侧 syscall 面**:只暴露按已装入句柄操作的 syscall。方法**不接收 Session**,
/// 因而 guest 代码(拿 `&mut dyn Syscalls`)在**类型层面**无法 `install`、无法取得 `CapRef`、
/// 无法 `grant_*`/`derive` 出裸引用 —— 只能在 loader 给的句柄集内活动。
///
/// 这是 Model 4 对不可信 guest 的强制面。内嵌 V8 后,guest JS 经此 ABI(永不持 Rust 引用);
/// 当前纯 Rust 切片中,把 `&mut dyn Syscalls`(而非 `&mut Session`)交给 guest 即等价边界。
pub trait Syscalls {
    /// cap_read(h, rel):经句柄 h 指向的 DirCap 读 rel。指名 = 句柄,不是任意路径。
    fn cap_read(&mut self, h: usize, rel: &str) -> R<(Taint, Vec<u8>)>;
    /// cap_list(h, rel):列目录。
    fn cap_list(&mut self, h: usize, rel: &str) -> R<Vec<u8>>;
    /// cap_exec(h):执行 CommandCap 句柄(经 C1 L1 沙箱 + L5 gate)。
    fn cap_exec(&mut self, h: usize) -> R<Vec<u8>>;
    /// cap_derive_sub(h, seg):从句柄派生**衰减**子能力,装入新句柄并返回(不影响父句柄)。
    fn cap_derive_sub(&mut self, h: usize, seg: &str) -> R<usize>;
    /// cap_close(h):收回本进程对该句柄的访问(C-list 置空)。≠ 撤销能力本身(用 Broker revoke)。
    fn cap_close(&mut self, h: usize) -> R<()>;
}

impl Syscalls for GuestProcess<'_> {
    fn cap_read(&mut self, h: usize, rel: &str) -> R<(Taint, Vec<u8>)> {
        let cap = self.clist.resolve(h)?;
        self.sess.read(&cap, rel)
    }
    fn cap_list(&mut self, h: usize, rel: &str) -> R<Vec<u8>> {
        let cap = self.clist.resolve(h)?;
        self.sess.list(&cap, rel)
    }
    fn cap_exec(&mut self, h: usize) -> R<Vec<u8>> {
        let cap = self.clist.resolve(h)?;
        self.sess.exec(&cap)
    }
    fn cap_derive_sub(&mut self, h: usize, seg: &str) -> R<usize> {
        let cap = self.clist.resolve(h)?;
        let child = self.sess.derive_sub(&cap, seg)?;
        Ok(self.clist.install(child))
    }
    fn cap_close(&mut self, h: usize) -> R<()> {
        self.clist.close(h)
    }
}

#[cfg(test)]
mod t {
    use super::*;
    use crate::{parse_ops, Session};
    use std::fs;

    fn ws() -> String {
        let dir = std::env::temp_dir().join(format!("capvm_{}", crate::rand_hex(6)));
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(dir.join("main.txt"), b"hello capvm").unwrap();
        fs::write(dir.join("src/secret.txt"), b"API_KEY=sk-zzz").unwrap();
        dir.to_string_lossy().into_owned()
    }

    #[test]
    fn fresh_process_has_zero_authority() {
        let mut sess = Session::new();
        let mut p = GuestProcess::new(&mut sess);
        // 空 C-list:任何句柄都无效 —— 无 ambient authority(不存在 open(路径) 接口)
        assert!(p.syscalls().cap_read(0, "main.txt").is_err());
        assert!(p.syscalls().cap_read(7, "main.txt").is_err());
        assert_eq!(p.live_handles(), 0);
    }

    #[test]
    fn cap_indexed_read_and_bounds_and_forge() {
        let root = ws();
        let mut sess = Session::new();
        let dircap = sess.grant_dir(&root, parse_ops("read,list"), Taint::Project).unwrap();
        let mut p = GuestProcess::new(&mut sess);
        let h = p.install(dircap); // host/loader 装入 DirCap → 句柄
        // 经句柄读 cwd 内文件 OK
        let (_, data) = p.syscalls().cap_read(h, "main.txt").unwrap();
        assert_eq!(&data, b"hello capvm");
        // 越界仍受 Broker DirCap 边界约束(openat2 RESOLVE_BENEATH):绝对/.. 拒
        assert!(p.syscalls().cap_read(h, "/etc/passwd").is_err());
        assert!(p.syscalls().cap_read(h, "../../etc/passwd").is_err());
        // 伪造句柄(未 install 的下标)无授权
        assert!(p.syscalls().cap_read(h + 99, "main.txt").is_err());
    }

    #[test]
    fn cap_derive_attenuates_and_close_revokes_handle() {
        let root = ws();
        let mut sess = Session::new();
        let dircap = sess.grant_dir(&root, parse_ops("read,list"), Taint::Project).unwrap();
        let mut p = GuestProcess::new(&mut sess);
        let h = p.install(dircap);
        // 派生子句柄:限定到 src/(衰减);新句柄只能看 src 下
        let sub = p.syscalls().cap_derive_sub(h, "src").unwrap();
        let (t, _) = p.syscalls().cap_read(sub, "secret.txt").unwrap();
        assert_eq!(t, Taint::Secret, "src/secret.txt 应升级 Secret");
        assert_eq!(p.live_handles(), 2); // 父 + 子
        // 关闭子句柄:本进程不再能用它(收回 authority)
        p.syscalls().cap_close(sub).unwrap();
        assert!(p.syscalls().cap_read(sub, "secret.txt").is_err(), "关闭后句柄失效");
        assert!(p.syscalls().cap_close(sub).is_err(), "重复关闭无效句柄应拒");
        // 父句柄不受影响
        assert!(p.syscalls().cap_read(h, "main.txt").is_ok());
    }

    #[test]
    fn guest_surface_has_no_session_no_mint_no_install() {
        // guest 只拿 &mut dyn Syscalls:能按句柄读,但**类型层面**无 Session/install/grant/CapRef。
        let root = ws();
        let mut sess = Session::new();
        let dircap = sess.grant_dir(&root, parse_ops("read,list"), Taint::Project).unwrap();
        let mut p = GuestProcess::new(&mut sess);
        let h = p.install(dircap); // host/loader 装入

        // 模拟 guest 代码:签名只给 &mut dyn Syscalls —— 没有 Session 参数
        fn guest_code(sys: &mut dyn Syscalls, h: usize) -> R<Vec<u8>> {
            // 以下都编译不过(guest 面根本没有这些方法),故不能凭空 mint / 取 CapRef / install:
            //   sys.grant_dir(..)          // 无:Session 未暴露
            //   sys.install(some_ref)      // 无:install 在 host 门面上
            //   let _: CapRef = ...        // 无:guest 拿不到任何 CapRef
            // guest 只能在给定句柄集内活动:
            let (_, data) = sys.cap_read(h, "main.txt")?;
            assert!(sys.cap_read(h + 5, "main.txt").is_err()); // 未装入句柄无授权
            // 甚至派生也只得到一个 usize 句柄,拿不到底层引用
            let sub = sys.cap_derive_sub(h, "src")?;
            assert!(sys.cap_read(sub, "secret.txt").is_ok());
            Ok(data)
        }
        let data = guest_code(p.syscalls(), h).unwrap();
        assert_eq!(&data, b"hello capvm");
    }

    #[test]
    fn host_loader_installs_capability_guest_cannot() {
        // 诚实边界:把能力带进进程是 **host/loader** 的职责(它持有 Session/CapRef);
        // guest(&mut dyn Syscalls)做不到 —— 见 guest_surface_has_no_session_no_mint_no_install。
        let root = ws();
        let mut sess = Session::new();
        let dircap = sess.grant_dir(&root, parse_ops("read,list"), Taint::Project).unwrap();
        let mut p = GuestProcess::new(&mut sess);
        let h = p.install(dircap); // host/loader 侧装入其持有的 ref
        assert!(p.syscalls().cap_read(h, "main.txt").is_ok());
    }

    #[test]
    fn handles_are_per_process_not_global() {
        let root = ws();
        let mut sess = Session::new();
        let dircap = sess.grant_dir(&root, parse_ops("read,list"), Taint::Project).unwrap();
        // 进程 A 装入得到句柄 ha
        let ha = {
            let mut a = GuestProcess::new(&mut sess);
            a.install(dircap)
        };
        // 进程 B 空 C-list:同一个数值句柄 ha 在 B 里无授权(句柄非全局命名,不可凭数值跨进程重用)
        let mut b = GuestProcess::new(&mut sess);
        assert!(b.syscalls().cap_read(ha, "main.txt").is_err(), "别的进程不能凭相同数值句柄借用能力");
    }
}
