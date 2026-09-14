(* cap.mli — 能力的对外签名。
   Capable 的 D-encap 决策落地:'k t 是 ABSTRACT type,签名外无法构造/匹配/序列化,
   因此不可伪造(不变量 14)、不可序列化(不变量 8)—— 由类型系统在编译期结构性保证。
   见 docs/capsh-language.md §2.3。 *)

(* ENOTCAPABLE 的类比:能力违规统一异常,携带可解释信息(DESIGN §4.6)。 *)
exception Capability_violation of string

(* ---- phantom 种类标签:编码能力类型,read 只收 dir t,不收 sink t ---- *)
type dir
type file
type command
type sink

(* 抽象能力类型。'k 是 phantom 参数(种类)。表示被隐藏。 *)
type 'k t

type op = Read | Write | Delete | Exec | List

(* 运行期存在类型:抹去 phantom 种类,供求值器统一持有能力值。
   投影(as_dir/as_sink)在运行期按种类判定,仍不暴露表示。 *)
type any
val any_dir       : dir t -> any
val any_sink      : sink t -> any
val any_cmd       : command t -> any
val as_dir        : any -> dir t option
val as_sink       : any -> sink t option
val as_cmd        : any -> command t option
val any_describe  : any -> string
val any_is_active : any -> bool
val any_kind      : any -> string
val any_taint     : any -> Taint.label   (* 该能力读出的数据污点(用于 confine 区室规则) *)

(* ======== 使用(USE)—— 不可信 capsh 脚本层可调 ======== *)

(* 只读的显示占位 id(不变量 14:泄露≠授权,脱离 Broker 上下文不可调用)。 *)
val id       : 'k t -> string
val describe : 'k t -> string
val is_active : 'k t -> bool

(* DirCap 读:只接受相对路径;越界(绝对路径 / ..)抛 Capability_violation。
   返回带 taint 的字节(taint 来自该 cap 的策略)。 *)
val read : dir t -> string -> string Taint.t
val list : dir t -> string -> string list

(* 外发 sink(HttpCap POST / MessageCap send 的抽象):
   信息流检查 —— secret 污点数据流入被拒(除非先 declassify)。 *)
val send : sink t -> string Taint.t -> unit

(* CommandCap:固定 argv 模板(非 $PATH 任意解析),在 cwd(绑定的 DirCap 根)内执行,
   env allowlist,无 shell(execvpe 直接执行 argv)—— 从结构上杜绝 shell 注入。
   输出标 Yellow(本地确定性工具输出)。 *)
val exec    : command t -> string Taint.t
val root_of : dir t -> string          (* 读 DirCap 的根(非机密),供 CommandCap 绑定 cwd *)

(* ======== 衰减(ATTENUATE)—— 返回更窄的新 cap,单向不可逆(D10=A) ======== *)

val sub       : dir t -> string -> dir t   (* 收窄到子目录(相对,deny_parent_escape) *)
val read_only : dir t -> dir t             (* 去掉写/删 *)

(* ======== 可撤销 forwarder(Redell 1974 / DESIGN §4.4) ======== *)

type revoker
val make_revocable : 'k t -> 'k t * revoker
val revoke : revoker -> unit               (* 断链;撤销沿祖先链级联 *)

(* ======== declassify —— 需要能力,Agent 自己不能批准(不变量) ======== *)

type declassifier
val declassify : declassifier -> string Taint.t -> string Taint.t

(* ======== 铸造(MINT)—— 仅 TCB(Broker)可用:需 minter/declassifier 能力 ========
   这些能力本身也是不可伪造抽象类型,只能由 create_* 得到,Broker 私有持有。
   capsh 脚本层拿不到 minter,因此即便能引用 Trusted 也无法铸造。 *)

type minter

module Trusted : sig
  val create_minter      : unit -> minter
  val create_declassifier : of_:Taint.label -> declassifier

  val mint_dir  : minter -> root:string -> writable:bool -> taint:Taint.label -> dir t
  val mint_sink : minter -> name:string -> sink t
  val mint_command :
    minter -> argv:string list -> cwd:string -> env:string list -> command t
end
