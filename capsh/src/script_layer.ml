(* script_layer.ml — 模拟不可信 capsh 脚本层的 TCB 边界。
   脚本层拿到的是 Cap 的【窄签名】:类型相等(能力可从 TCB 流入),
   但【没有 Trusted / minter / mint_*】—— 因此结构上无法铸造能力,只能使用被传入的。
   这就是「强封装放在 capsh 侧」的落地(D-encap)。 *)

module ScriptCap : sig
  type dir  = Cap.dir      (* 类型相等:能力可从 Broker 流进来 *)
  type sink = Cap.sink
  type 'k t = 'k Cap.t     (* 仍抽象(Cap.t 抽象)-> 不可伪造 *)
  exception Capability_violation of string
  val read      : dir t -> string -> string Taint.t
  val send      : sink t -> string Taint.t -> unit
  val sub       : dir t -> string -> dir t
  val read_only : dir t -> dir t
  val describe  : 'k t -> string
  (* 注意:没有 Trusted、没有 mint、没有 minter —— 脚本层拿不到铸造能力 *)
end = Cap

(* 一段「脚本」:只能用被授予的能力工作,无法凭空获得新权限。 *)
let run (repo : ScriptCap.dir ScriptCap.t) : int =
  let c = ScriptCap.read repo "main.ml" in
  String.length c.Taint.value
