(* backend_rpc.ml — 远端后端:capsh 走 CapTP-lite socket 到 Rust capable-rpc Broker。
   cap = opaque ref + 客户端侧记的 kind/taint(用于 confine 结构检查);
   真实能力/枚举/执行都在 Rust Broker,capsh 只持 ref(不可伪造、会话绑定)。 *)

module Make (C : sig
  val conn : Rpc_client.conn
end) : Backend.BACKEND = struct
  type cap = { r : string; k : string; t : Taint.label }

  let grant_dir ~root ~writable ~secret =
    let ops = if writable then "read,write,list,delete" else "read,list" in
    let ts = if secret then "secret" else "project" in
    { r = Rpc_client.grant_dir C.conn ~root ~ops ~taint:ts;
      k = "dir";
      t = (if secret then Taint.Secret else Taint.Project) }

  let grant_sink ~name =
    { r = Rpc_client.grant_sink C.conn ~name; k = "sink"; t = Taint.Green }

  let grant_cmd ~cwd ~argv =
    { r = Rpc_client.grant_cmd C.conn ~cwd:cwd.r ~argv; k = "command"; t = Taint.Yellow }

  let sub c seg = { c with r = Rpc_client.derive_sub C.conn c.r seg }
  let readonly c = { c with r = Rpc_client.derive_readonly C.conn c.r }

  let read c rel =
    let ts, d = Rpc_client.read C.conn c.r rel in
    Taint.tag ~prov:[ c.r ^ ":" ^ rel ] [ Taint.of_string ts ] d

  let list c rel =
    let _, d = Rpc_client.list C.conn c.r rel in
    d

  let send c v =
    let ts = if Taint.is_sensitive v then "secret" else "project" in
    Rpc_client.send C.conn c.r ~taint:ts ~data:v.Taint.value

  let exec c =
    let _, d = Rpc_client.exec C.conn c.r in
    Taint.tag ~prov:[ c.r ] [ Taint.Yellow ] d

  let describe c = Rpc_client.describe C.conn c.r
  let kind c = c.k
  let taint c = c.t
end
