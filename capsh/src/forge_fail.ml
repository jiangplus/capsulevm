(* forge_fail.ml — 反向证明:伪造能力【必须编译失败】。
   本文件故意编译不通过。Makefile 的 `make forge-check` 断言它无法编译;
   若某天它能编译,说明能力可被伪造 —— D-encap / 不变量 14 失效,是安全回归。 *)

(* (1) 用记录字面量凭空构造一个 DirCap —— 失败:Cap.dir Cap.t 是抽象类型,签名外无构造子。 *)
let _forged : Cap.dir Cap.t = { root = "/"; writable = true }

(* (2) 把普通字符串当 DirCap 读 —— 失败:string 不是 dir t(指名即授权,裸字符串不是权限)。 *)
let _ = Cap.read "/etc/passwd" "shadow"
