(* backend.ml — capsh 求值器的能力后端接口。
   同一门语言,可跑在进程内 Cap(Backend_local)或远端 Rust Broker(Backend_rpc)之上。 *)

module type BACKEND = sig
  type cap
  val grant_dir  : root:string -> writable:bool -> secret:bool -> cap
  val grant_sink : name:string -> cap
  val grant_cmd  : cwd:cap -> argv:string list -> cap
  val sub        : cap -> string -> cap
  val readonly   : cap -> cap
  val read       : cap -> string -> string Taint.t
  val list       : cap -> string -> string
  val send       : cap -> string Taint.t -> unit
  val exec       : cap -> string Taint.t
  val describe   : cap -> string
  val kind       : cap -> string
  val taint      : cap -> Taint.label
end
