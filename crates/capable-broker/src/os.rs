//! os.rs — 原子路径解析(openat2 RESOLVE_BENEATH)+ **稳定 root 目录 fd**。
//! 关闭 DirCap 的 symlink/.. TOCTOU 以及 root/path-identity 重解析越界(newton):
//! Cap 持有授予时打开的目录 fd,read/list/derive 全部以该 fd 作 openat2 anchor,
//! 不再从可变字符串路径重开 root —— 授予/派生后替换路径不再影响已持有的 inode。
//!
//! 纯 std + `core::arch::asm!` 直发系统调用,零依赖。
//! **fail-closed**:openat2 不可用(ENOSYS)/非 x86_64-linux → **拒绝访问**,无回退。

use std::fs::File;
use std::io::Read;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};

pub enum ResolveErr {
    Unavailable,
    Denied(String),
}

/// exec 子进程的身份/资源策略。配置了但施加失败 -> 拒绝执行(fail-closed,newton)。
#[derive(Clone, Copy)]
pub struct SandboxPolicy {
    pub drop_uid: Option<u32>,        // setuid(需 root);非 root 配置即 fail-closed
    pub drop_gid: Option<u32>,        // setgid + 清空 supplementary groups(需 root)
    pub rlimit_nproc: Option<u64>,    // RLIMIT_NPROC 进程数
    pub rlimit_fsize_bytes: Option<u64>, // RLIMIT_FSIZE 写文件上限
    pub rlimit_cpu_secs: Option<u64>, // RLIMIT_CPU CPU 秒
}

impl SandboxPolicy {
    /// 默认:无掉权(Broker 常非 root),但设保守 rlimits(DoS 兜底,无需 root)。
    pub fn default_limits() -> SandboxPolicy {
        SandboxPolicy {
            drop_uid: None,
            drop_gid: None,
            rlimit_nproc: Some(256),
            rlimit_fsize_bytes: Some(256 * 1024 * 1024),
            rlimit_cpu_secs: Some(60),
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SYS_OPENAT2: usize = 437;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SYS_GETDENTS64: usize = 217;

const O_RDONLY: u64 = 0;
const O_DIRECTORY: u64 = 0o200000;
const O_PATH: u64 = 0o10000000;
const O_CLOEXEC: u64 = 0o2000000;
const RESOLVE_BENEATH: u64 = 0x08;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const ENOSYS: isize = 38;

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
unsafe fn syscall4(n: usize, a1: usize, a2: usize, a3: usize, a4: usize) -> isize {
    let ret: isize;
    core::arch::asm!(
        "syscall",
        inlateout("rax") n as isize => ret,
        in("rdi") a1, in("rsi") a2, in("rdx") a3, in("r10") a4,
        lateout("rcx") _, lateout("r11") _,
        options(nostack, preserves_flags)
    );
    ret
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
unsafe fn syscall5(n: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) -> isize {
    let ret: isize;
    core::arch::asm!(
        "syscall",
        inlateout("rax") n as isize => ret,
        in("rdi") a1, in("rsi") a2, in("rdx") a3, in("r10") a4, in("r8") a5,
        lateout("rcx") _, lateout("r11") _,
        options(nostack, preserves_flags)
    );
    ret
}

// ---- L1 exec 沙箱:Landlock fs 限制 + fchdir 到持有的 cwd fd(#1) ----
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod sandbox {
    use super::syscall5;
    use std::os::unix::io::RawFd;

    const SYS_PRCTL: usize = 157;
    const SYS_FCHDIR: usize = 81;
    const SYS_OPEN: usize = 2;
    const SYS_CLOSE: usize = 3;
    const SYS_CLOSE_RANGE: usize = 436;
    const CLOSE_RANGE_CLOEXEC: usize = 4; // 标 CLOEXEC(execve 时才关),不立即关(否则会关掉 pre_exec 同步管道)
    const SYS_LANDLOCK_CREATE_RULESET: usize = 444;
    const SYS_LANDLOCK_ADD_RULE: usize = 445;
    const SYS_LANDLOCK_RESTRICT_SELF: usize = 446;
    const SYS_SETRLIMIT: usize = 160;
    const SYS_SETGROUPS: usize = 116;
    const SYS_SETGID: usize = 106;
    const SYS_SETUID: usize = 105;
    const RLIMIT_CPU: usize = 0;
    const RLIMIT_FSIZE: usize = 1;
    const RLIMIT_NPROC: usize = 6;
    const PR_SET_NO_NEW_PRIVS: usize = 38;

    unsafe fn setrlimit(resource: usize, limit: u64) -> bool {
        #[repr(C)]
        struct Rlimit {
            cur: u64,
            max: u64,
        }
        let rl = Rlimit {
            cur: limit,
            max: limit,
        };
        syscall5(SYS_SETRLIMIT, resource, &rl as *const Rlimit as usize, 0, 0, 0) == 0
    }

    // Landlock ABI v1 fs 访问位;handled=全 v1(未显式 allow 的一律拒)
    const FS_EXECUTE: u64 = 1 << 0;
    const FS_READ_FILE: u64 = 1 << 2;
    const FS_READ_DIR: u64 = 1 << 3;
    const FS_V1_ALL: u64 = 0x1FFF;
    const RULE_PATH_BENEATH: usize = 1;
    const O_PATH: usize = 0o10000000;
    const O_DIRECTORY: usize = 0o200000;
    const O_CLOEXEC: usize = 0o2000000;

    #[repr(C)]
    struct RulesetAttr {
        handled_access_fs: u64,
    }
    #[repr(C, packed)]
    struct PathBeneathAttr {
        allowed_access: u64,
        parent_fd: i32,
    }

    // ---- seccomp 网络 default-deny(BPF)----
    const PR_SET_SECCOMP: usize = 22;
    const SECCOMP_MODE_FILTER: usize = 2;
    const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_JEQ_K: u16 = 0x15;
    const BPF_RET_K: u16 = 0x06;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
    const SECCOMP_RET_KILL: u32 = 0x8000_0000; // KILL_PROCESS
    const EACCES: u32 = 13;

    #[repr(C)]
    struct SockFilter {
        code: u16,
        jt: u8,
        jf: u8,
        k: u32,
    }
    #[repr(C)]
    struct SockFprog {
        len: u16,
        filter: *const SockFilter,
    }

    const fn sf(code: u16, jt: u8, jf: u8, k: u32) -> SockFilter {
        SockFilter { code, jt, jf, k }
    }

    /// 安装 seccomp:先校验 arch(非 x86_64 KILL),对网络 + 跨进程 syscall 返回 EACCES,其余 ALLOW。
    /// 栈上定长数组,无堆分配。需先 no_new_privs。返回是否成功。
    ///
    /// 网络 default-deny 的正确性论证(newton C1 复审):子进程要拿到 socket fd 只有几条路,
    /// 全部封死 → 之后无 socket fd 可 read/write(无法按 nr 过滤 read/write,故必须封"取得"这一步):
    ///   1. socket(41)/socketpair(53)               → deny
    ///   2. accept(43)/accept4(288)/bind/listen      → deny(且无法先建监听 socket)
    ///   3. io_uring 的 IORING_OP_SOCKET(绕过 socket())→ deny io_uring_setup/enter/register
    ///   4. 继承 socket fd                            → close_range(CLOEXEC)在 execve 时关闭
    ///   5. SCM_RIGHTS 收 fd / pidfd_getfd 偷父进程 fd → deny(需先有 unix socket / 已 deny pidfd)
    ///   6. open("/proc/<pid>/fd/N")                  → Landlock 只放行 cwd+系统只读,/proc 不可达
    /// 跨进程操纵(同 uid 父进程):ptrace/process_vm_*/kcmp/pidfd_* deny —— 但真正的进程隔离
    /// 保证需要独立 uid(见 SandboxPolicy.drop_uid,部署应配专用 worker uid),此处为纵深防御。
    unsafe fn install_seccomp_deny() -> bool {
        let errno = SECCOMP_RET_ERRNO | EACCES;
        // 每个被拒 syscall:JEQ(nr,0,1)=命中落到下一条 RET(EACCES),否则跳过下一条继续比对。
        // 该 jt/jf 与被拒条数无关,故可安全增删条目。
        let prog: [SockFilter; 47] = [
            sf(BPF_LD_W_ABS, 0, 0, 4),                 // A = arch(offset 4)
            sf(BPF_JEQ_K, 1, 0, AUDIT_ARCH_X86_64),    // x86_64 -> +1 否则 -> KILL
            sf(BPF_RET_K, 0, 0, SECCOMP_RET_KILL),
            sf(BPF_LD_W_ABS, 0, 0, 0),                 // A = nr(offset 0)
            // -- 网络 family --
            sf(BPF_JEQ_K, 0, 1, 41), sf(BPF_RET_K, 0, 0, errno), // socket
            sf(BPF_JEQ_K, 0, 1, 42), sf(BPF_RET_K, 0, 0, errno), // connect
            sf(BPF_JEQ_K, 0, 1, 43), sf(BPF_RET_K, 0, 0, errno), // accept
            sf(BPF_JEQ_K, 0, 1, 44), sf(BPF_RET_K, 0, 0, errno), // sendto
            sf(BPF_JEQ_K, 0, 1, 45), sf(BPF_RET_K, 0, 0, errno), // recvfrom
            sf(BPF_JEQ_K, 0, 1, 46), sf(BPF_RET_K, 0, 0, errno), // sendmsg
            sf(BPF_JEQ_K, 0, 1, 47), sf(BPF_RET_K, 0, 0, errno), // recvmsg
            sf(BPF_JEQ_K, 0, 1, 49), sf(BPF_RET_K, 0, 0, errno), // bind
            sf(BPF_JEQ_K, 0, 1, 50), sf(BPF_RET_K, 0, 0, errno), // listen
            sf(BPF_JEQ_K, 0, 1, 53), sf(BPF_RET_K, 0, 0, errno), // socketpair
            sf(BPF_JEQ_K, 0, 1, 288), sf(BPF_RET_K, 0, 0, errno), // accept4
            // -- io_uring(IORING_OP_SOCKET 可不经 socket() 建网络 socket)--
            sf(BPF_JEQ_K, 0, 1, 425), sf(BPF_RET_K, 0, 0, errno), // io_uring_setup
            sf(BPF_JEQ_K, 0, 1, 426), sf(BPF_RET_K, 0, 0, errno), // io_uring_enter
            sf(BPF_JEQ_K, 0, 1, 427), sf(BPF_RET_K, 0, 0, errno), // io_uring_register
            // -- 跨进程 inspection/操纵(同 uid 纵深防御)--
            sf(BPF_JEQ_K, 0, 1, 101), sf(BPF_RET_K, 0, 0, errno), // ptrace
            sf(BPF_JEQ_K, 0, 1, 310), sf(BPF_RET_K, 0, 0, errno), // process_vm_readv
            sf(BPF_JEQ_K, 0, 1, 311), sf(BPF_RET_K, 0, 0, errno), // process_vm_writev
            sf(BPF_JEQ_K, 0, 1, 312), sf(BPF_RET_K, 0, 0, errno), // kcmp
            sf(BPF_JEQ_K, 0, 1, 424), sf(BPF_RET_K, 0, 0, errno), // pidfd_send_signal
            sf(BPF_JEQ_K, 0, 1, 434), sf(BPF_RET_K, 0, 0, errno), // pidfd_open
            sf(BPF_JEQ_K, 0, 1, 438), sf(BPF_RET_K, 0, 0, errno), // pidfd_getfd
            sf(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW),
        ];
        let fprog = SockFprog {
            len: prog.len() as u16,
            filter: prog.as_ptr(),
        };
        syscall5(
            SYS_PRCTL,
            PR_SET_SECCOMP,
            SECCOMP_MODE_FILTER,
            &fprog as *const SockFprog as usize,
            0,
            0,
        ) == 0
    }

    unsafe fn add_beneath(rs: RawFd, dir_fd: RawFd, access: u64) -> bool {
        let pb = PathBeneathAttr {
            allowed_access: access,
            parent_fd: dir_fd,
        };
        syscall5(
            SYS_LANDLOCK_ADD_RULE,
            rs as usize,
            RULE_PATH_BENEATH,
            &pb as *const PathBeneathAttr as usize,
            0,
            0,
        ) == 0
    }

    /// 测试助手:fork 子进程,装 seccomp deny 后逐一尝试每类绕过路径 —— socket、socketpair、
    /// io_uring_setup、pidfd_open、ptrace 全部必须被拒(返回 <0)才 exit 0。任一条被放行即 exit 1。
    /// 覆盖 newton 复审点:不能仅拦 socket()——io_uring / pidfd / ptrace 家族也不得留缺口。
    #[cfg(test)]
    pub fn seccomp_denies_socket_in_child() -> bool {
        const SYS_FORK: usize = 57;
        const SYS_EXIT: usize = 60;
        const SYS_WAIT4: usize = 61;
        const SYS_SOCKET: usize = 41;
        const SYS_SOCKETPAIR: usize = 53;
        const SYS_IO_URING_SETUP: usize = 425;
        const SYS_PIDFD_OPEN: usize = 434;
        const SYS_PTRACE: usize = 101;
        unsafe {
            let pid = syscall5(SYS_FORK, 0, 0, 0, 0, 0);
            if pid == 0 {
                syscall5(SYS_PRCTL, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
                let ok = install_seccomp_deny();
                // 每条路径都必须返回负值(被 seccomp EACCES 拒绝);任一 >=0 表示留了缺口
                let mut blocked = ok;
                blocked &= (syscall5(SYS_SOCKET, 2, 1, 0, 0, 0) as isize) < 0; // AF_INET,SOCK_STREAM
                blocked &= (syscall5(SYS_SOCKETPAIR, 1, 1, 0, 0, 0) as isize) < 0; // AF_UNIX
                let mut params = [0u8; 120]; // io_uring_params 占位
                blocked &= (syscall5(SYS_IO_URING_SETUP, 1, params.as_mut_ptr() as usize, 0, 0, 0)
                    as isize)
                    < 0;
                blocked &= (syscall5(SYS_PIDFD_OPEN, 1, 0, 0, 0, 0) as isize) < 0;
                blocked &= (syscall5(SYS_PTRACE, 0, 0, 0, 0, 0) as isize) < 0; // PTRACE_TRACEME
                syscall5(SYS_EXIT, if blocked { 0 } else { 1 }, 0, 0, 0, 0);
                loop {}
            } else {
                let mut status: i32 = 0;
                syscall5(SYS_WAIT4, pid as usize, &mut status as *mut i32 as usize, 0, 0, 0);
                (status & 0x7f) == 0 && ((status >> 8) & 0xff) == 0
            }
        }
    }

    /// 在 fork 后的子进程(execve 前)调用:no_new_privs + Landlock 限 fs 到 cwd + 系统只读目录 +
    /// fchdir(cwd fd)+ close_range(继承 fd)+ seccomp 网络 deny。
    /// 必须 async-signal-safe:只做系统调用,错误路径 alloc-free。任一步失败 -> fail-closed(Err)。
    pub fn apply(cwd_fd: RawFd, policy: &super::SandboxPolicy) -> std::io::Result<()> {
        // pre_exec(fork 后)错误路径 alloc-free:用 from_raw_os_error(不 Box)。EPERM 兜底。
        let oserr = |e: isize| std::io::Error::from_raw_os_error(if e < 0 { (-e) as i32 } else { 1 });
        let perm = || std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        unsafe {
            let r = syscall5(SYS_PRCTL, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            if r != 0 {
                return Err(oserr(r));
            }
            // rlimits(可降不可升,无需 root);配置了但失败 -> fail-closed
            if let Some(n) = policy.rlimit_nproc {
                if !setrlimit(RLIMIT_NPROC, n) {
                    return Err(perm());
                }
            }
            if let Some(f) = policy.rlimit_fsize_bytes {
                if !setrlimit(RLIMIT_FSIZE, f) {
                    return Err(perm());
                }
            }
            if let Some(c) = policy.rlimit_cpu_secs {
                if !setrlimit(RLIMIT_CPU, c) {
                    return Err(perm());
                }
            }
            let attr = RulesetAttr {
                handled_access_fs: FS_V1_ALL,
            };
            let rs = syscall5(
                SYS_LANDLOCK_CREATE_RULESET,
                &attr as *const RulesetAttr as usize,
                core::mem::size_of::<RulesetAttr>(),
                0,
                0,
                0,
            );
            if rs < 0 {
                return Err(oserr(rs)); // Landlock 不可用 -> fail-closed
            }
            let rs = rs as RawFd;
            let ro = FS_READ_FILE | FS_READ_DIR | FS_EXECUTE;
            // cwd:只读 + exec(不给写/删/创建)
            if !add_beneath(rs, cwd_fd, ro) {
                return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
            }
            // 系统只读目录(binary/lib 加载需要);不含 /etc。open 失败=目录不存在则跳过;
            // open 成功但 add_beneath 失败=真失败 -> abort(fail-closed,newton #3)。
            let sys: [&[u8]; 4] = [b"/usr\0", b"/bin\0", b"/lib\0", b"/lib64\0"];
            for p in sys {
                let fd = syscall5(
                    SYS_OPEN,
                    p.as_ptr() as usize,
                    O_PATH | O_DIRECTORY | O_CLOEXEC,
                    0,
                    0,
                    0,
                );
                if fd >= 0 {
                    let ok = add_beneath(rs, fd as RawFd, ro);
                    syscall5(SYS_CLOSE, fd as usize, 0, 0, 0, 0);
                    if !ok {
                        return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
                    }
                }
            }
            if syscall5(SYS_LANDLOCK_RESTRICT_SELF, rs as usize, 0, 0, 0, 0) != 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
            }
            syscall5(SYS_CLOSE, rs as usize, 0, 0, 0, 0);
            // chdir 到持有的 cwd fd(fd-identity:cwd 路径事后被 swap 也无效)
            let r = syscall5(SYS_FCHDIR, cwd_fd as usize, 0, 0, 0, 0);
            if r != 0 {
                return Err(oserr(r));
            }
            // 把所有 >= 3 的继承 fd 标 **CLOEXEC**(execve 时才关闭),而非立即关闭 ——
            // 立即关会连 std 用于回传 pre_exec 错误的同步管道一起关掉,破坏 fail-closed。
            // 标 CLOEXEC 后:pre_exec 期间同步管道仍可用(错误可回传),execve 时继承 fd
            // (cwd_fd、其它 cap dir_fd、审计 log fd、监听 socket…)全部关闭,exec 程序拿不到。
            let r = syscall5(SYS_CLOSE_RANGE, 3, 0xffff_ffff, CLOSE_RANGE_CLOEXEC, 0, 0);
            if r != 0 {
                return Err(oserr(r));
            }
            // seccomp default-deny(网络 + io_uring + 跨进程;继承 socket 已 close_range,再叠结构性禁网)。
            if !install_seccomp_deny() {
                return Err(perm());
            }
            // 掉权(最后一步):清 supplementary groups -> setgid -> setuid;配置了但失败 -> fail-closed。
            if policy.drop_gid.is_some() || policy.drop_uid.is_some() {
                if syscall5(SYS_SETGROUPS, 0, 0, 0, 0, 0) != 0 {
                    return Err(perm()); // 清 groups 需 root;非 root 配置掉权即拒执行
                }
            }
            if let Some(g) = policy.drop_gid {
                if syscall5(SYS_SETGID, g as usize, 0, 0, 0, 0) != 0 {
                    return Err(perm());
                }
            }
            if let Some(u) = policy.drop_uid {
                if syscall5(SYS_SETUID, u as usize, 0, 0, 0, 0) != 0 {
                    return Err(perm());
                }
            }
        }
        Ok(())
    }
}

/// exec 前在子进程施加 L1 沙箱(仅 x86_64-linux;其它平台 fail-closed)。
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn exec_sandbox(cwd_fd: RawFd, policy: &SandboxPolicy) -> std::io::Result<()> {
    sandbox::apply(cwd_fd, policy)
}

/// 测试:fork 子进程装 seccomp 网络 deny 后尝试 socket(),验证被拒(返回 true=已拒)。
#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
pub fn test_seccomp_denies_socket() -> bool {
    sandbox::seccomp_denies_socket_in_child()
}
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
pub fn exec_sandbox(_cwd_fd: RawFd, _policy: &SandboxPolicy) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        "exec 沙箱仅 x86_64-linux,fail-closed",
    ))
}

/// openat2(dir_fd, rel(空=当前目录), RESOLVE_BENEATH|NO_MAGICLINKS, extra_flags)。
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn openat2_at(dir_fd: RawFd, rel: &str, extra_flags: u64) -> Result<OwnedFd, ResolveErr> {
    let rel = if rel.is_empty() { "." } else { rel }; // 空 rel = 目录本身(保留原语义)
    let mut cpath: Vec<u8> = rel.as_bytes().to_vec();
    cpath.push(0);
    let how = OpenHow {
        flags: extra_flags | O_CLOEXEC,
        mode: 0,
        resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS,
    };
    let ret = unsafe {
        syscall4(
            SYS_OPENAT2,
            dir_fd as usize,
            cpath.as_ptr() as usize,
            &how as *const OpenHow as usize,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if ret >= 0 {
        Ok(unsafe { OwnedFd::from_raw_fd(ret as RawFd) })
    } else if -ret == ENOSYS {
        Err(ResolveErr::Unavailable)
    } else {
        Err(ResolveErr::Denied(format!(
            "openat2 拒绝 {}(errno={},越界/不存在)",
            rel, -ret
        )))
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn openat2_at(_dir_fd: RawFd, _rel: &str, _extra: u64) -> Result<OwnedFd, ResolveErr> {
    Err(ResolveErr::Unavailable)
}

fn fail_closed(rel: &str) -> String {
    format!("openat2 不可用,fail-closed 拒绝 {}(非 x86_64-linux 或内核过旧)", rel)
}

/// 授予时可信打开 root 目录得到稳定 fd(此刻跟随 path;之后替换 path 不影响已持有 inode)。
pub fn open_dir_fd(path: &str) -> Result<OwnedFd, String> {
    let f = File::open(path).map_err(|e| format!("打开目录 {} 失败: {}", path, e))?;
    Ok(OwnedFd::from(f))
}

/// 以持有的 root fd 为 anchor 原子读 rel。
pub fn read_at(dir_fd: RawFd, rel: &str) -> Result<Vec<u8>, String> {
    match openat2_at(dir_fd, rel, O_RDONLY) {
        Ok(fd) => {
            let mut f = File::from(fd);
            let mut buf = Vec::new();
            f.read_to_end(&mut buf).map_err(|e| format!("read failed: {}", e))?;
            Ok(buf)
        }
        Err(ResolveErr::Denied(m)) => Err(m),
        Err(ResolveErr::Unavailable) => Err(fail_closed(rel)),
    }
}

/// 从父 fd 原子派生子目录 fd(RESOLVE_BENEATH 保证在父下,swap 无效)。
pub fn derive_dir_at(parent_fd: RawFd, seg: &str) -> Result<OwnedFd, String> {
    match openat2_at(parent_fd, seg, O_PATH | O_DIRECTORY) {
        Ok(fd) => Ok(fd),
        Err(ResolveErr::Denied(m)) => Err(m),
        Err(ResolveErr::Unavailable) => Err(fail_closed(seg)),
    }
}

/// 以持有的 root fd 为 anchor 原子列 rel 目录(openat2 + getdents64,fd 上枚举)。
pub fn list_at(dir_fd: RawFd, rel: &str) -> Result<Vec<String>, String> {
    let fd = match openat2_at(dir_fd, rel, O_RDONLY | O_DIRECTORY) {
        Ok(fd) => fd,
        Err(ResolveErr::Denied(m)) => return Err(m),
        Err(ResolveErr::Unavailable) => return Err(fail_closed(rel)),
    };
    getdents_names(fd.as_raw_fd())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn getdents_names(fd: RawFd) -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = unsafe { syscall4(SYS_GETDENTS64, fd as usize, buf.as_mut_ptr() as usize, buf.len(), 0) };
        if n < 0 {
            return Err(format!("getdents64 errno={}", -n));
        }
        if n == 0 {
            break;
        }
        let mut off = 0usize;
        let end = n as usize;
        // getdents64 每次返回完整记录;残缺/越界记录 -> fail-closed 报错(newton follow-up #3)
        while off < end {
            if off + 19 > end {
                return Err("getdents64 记录截断(头部越界)".into());
            }
            let reclen = u16::from_ne_bytes([buf[off + 16], buf[off + 17]]) as usize;
            if reclen < 19 || off + reclen > end {
                return Err("getdents64 记录畸形(reclen 非法)".into());
            }
            let name: Vec<u8> = buf[off + 19..off + reclen]
                .iter()
                .take_while(|&&c| c != 0)
                .copied()
                .collect();
            let s = String::from_utf8_lossy(&name).into_owned();
            if s != "." && s != ".." {
                names.push(s);
            }
            off += reclen;
        }
    }
    names.sort();
    Ok(names)
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn getdents_names(_fd: RawFd) -> Result<Vec<String>, String> {
    Err("getdents64 仅 x86_64-linux".into())
}

#[cfg(test)]
mod t {
    use super::*;
    #[test]
    fn openat2_fd_blocks_symlink_and_swap() {
        let dir = std::env::temp_dir().join(format!("capos_{}", crate::rand_hex(6)));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("ok.txt"), b"inside").unwrap();
        std::os::unix::fs::symlink("/etc", dir.join("escape")).unwrap();
        let root = dir.to_string_lossy().into_owned();
        let fd = open_dir_fd(&root).unwrap();
        // 根内正常读 OK
        assert_eq!(read_at(fd.as_raw_fd(), "ok.txt").unwrap(), b"inside");
        // 经 symlink 读根外必须被拒
        assert!(read_at(fd.as_raw_fd(), "escape/passwd").is_err());
        assert!(derive_dir_at(fd.as_raw_fd(), "escape").is_err());
    }

    #[test]
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn seccomp_blocks_network_socket() {
        // 子进程装 seccomp 网络 deny 后 socket() 必须被拒(EACCES)
        assert!(super::test_seccomp_denies_socket(), "seccomp 应拒绝子进程建 socket");
    }
}
