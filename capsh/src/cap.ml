(* cap.ml — 能力的实现(表示对外隐藏)。
   TCB 的一部分:这里能看到 raw 表示并铸造能力;签名 cap.mli 只暴露使用/衰减,
   把表示藏起来 —— 这就是「不可伪造」的来源。 *)

exception Capability_violation of string

type dir
type file
type command
type sink

type op = Read | Write | Delete | Exec | List

(* 真实表示。外部通过 cap.mli 看不到这个结构。 *)
type raw = {
  rid       : string;                 (* 不可猜测 id(随机 hex);仅审计/显示用 *)
  mutable revoked : bool;
  kind      : string;                 (* "dir" | "sink" | ... 仅用于 describe *)
  root      : string;                 (* dir/file 的绝对根 *)
  ops       : op list;
  taint     : Taint.label;            (* 经此 cap 读出的数据的污点 *)
  ttl       : float option;           (* 过期 epoch 秒;None=不过期 *)
  name      : string;                 (* sink 名 / 标签 *)
  argv      : string list;            (* CommandCap:固定 argv 模板 *)
  cenv      : string list;            (* CommandCap:env allowlist *)
  parent    : raw option;             (* 祖先(衰减派生链),供撤销级联 *)
}

type 'k t = raw                       (* phantom 'k;对外抽象 *)

type minter = Minter                  (* 铸造权威(抽象);持有即可铸造 *)
type declassifier = { dc_of : Taint.label }
type revoker = { target : raw }

(* --- 不可猜测 id(简化:用 Random 生成 128bit hex;真实实现用 HMAC(session_key,...)) --- *)
let () = Random.self_init ()
let fresh_id () =
  let b = Buffer.create 32 in
  for _ = 1 to 16 do Buffer.add_string b (Printf.sprintf "%02x" (Random.int 256)) done;
  Buffer.contents b

let now () = Unix.gettimeofday ()

(* 活性:未撤销、未过期、祖先链上无已撤销/过期节点(撤销级联的基础)。 *)
let rec active r =
  (not r.revoked)
  && (match r.ttl with Some e -> now () < e | None -> true)
  && (match r.parent with Some p -> active p | None -> true)

let is_active (r : 'k t) = active r
let id (r : 'k t) = "cap:" ^ r.rid
let describe (r : 'k t) =
  Printf.sprintf "<%s %s root=%s taint=%s%s>"
    (id r) r.kind r.root (Taint.label_to_string r.taint)
    (if active r then "" else " REVOKED")

let ensure_active r =
  if not (active r) then
    raise (Capability_violation
             (Printf.sprintf "cap %s is revoked/expired (ENOTCAPABLE)" (id r)))

let has_op r o = List.mem o r.ops

(* --- 路径安全:只接受相对路径,拒绝绝对与 .. 逃逸(deny_parent_escape) --- *)
let safe_join root rel =
  if String.length rel > 0 && rel.[0] = '/' then
    raise (Capability_violation
             (Printf.sprintf "absolute path not allowed: %s (held DirCap root=%s)" rel root));
  let parts = String.split_on_char '/' rel in
  List.iter (fun p ->
      if p = ".." then
        raise (Capability_violation
                 (Printf.sprintf "path escapes capability root: %s (root=%s)" rel root)))
    parts;
  let cleaned = List.filter (fun p -> p <> "" && p <> ".") parts in
  Filename.concat root (String.concat "/" cleaned)

let read_file path =
  let ic = open_in_bin path in
  Fun.protect ~finally:(fun () -> close_in ic)
    (fun () -> really_input_string ic (in_channel_length ic))

(* ======== USE ======== *)

let read (r : dir t) rel =
  ensure_active r;
  if not (has_op r Read) then
    raise (Capability_violation (Printf.sprintf "DirCap %s lacks Read" (id r)));
  let path = safe_join r.root rel in
  let data =
    try read_file path
    with Sys_error m -> raise (Capability_violation ("read failed: " ^ m))
  in
  Taint.tag ~prov:[ Printf.sprintf "%s:%s" (id r) rel ] [ r.taint ] data

let list (r : dir t) rel =
  ensure_active r;
  if not (has_op r List) then
    raise (Capability_violation (Printf.sprintf "DirCap %s lacks List" (id r)));
  let path = safe_join r.root rel in
  try Array.to_list (Sys.readdir path)
  with Sys_error m -> raise (Capability_violation ("list failed: " ^ m))

let root_of (r : dir t) = r.root

(* 直接执行 argv(execvpe,无 shell)—— 结构上无 shell 注入。捕获 stdout。 *)
let run_argv ~cwd ~env argv =
  match argv with
  | [] -> raise (Capability_violation "CommandCap 的 argv 为空")
  | prog :: _ ->
    flush stdout;                                (* 防 fork 复制父进程缓冲 *)
    let (rd, wr) = Unix.pipe () in
    let argv_a = Array.of_list argv and env_a = Array.of_list env in
    let pid = Unix.fork () in
    if pid = 0 then begin
      (try Unix.chdir cwd with _ -> ());         (* cwd 绑定到 DirCap 根 *)
      Unix.dup2 wr Unix.stdout;
      Unix.close rd; Unix.close wr;
      (try Unix.execvpe prog argv_a env_a with _ -> exit 127)
    end else begin
      Unix.close wr;
      let buf = Buffer.create 256 and chunk = Bytes.create 4096 in
      let rec loop () =
        let n = Unix.read rd chunk 0 4096 in
        if n > 0 then (Buffer.add_subbytes buf chunk 0 n; loop ()) in
      (try loop () with _ -> ());
      Unix.close rd;
      ignore (Unix.waitpid [] pid);
      Buffer.contents buf
    end

let exec (r : command t) =
  ensure_active r;
  if not (has_op r Exec) then
    raise (Capability_violation (Printf.sprintf "CommandCap %s lacks Exec" (id r)));
  let out = run_argv ~cwd:r.root ~env:r.cenv r.argv in
  (* 本地确定性工具输出 => Yellow(三色信任) *)
  Taint.tag ~prov:[ Printf.sprintf "%s:%s" (id r) (String.concat " " r.argv) ]
    [ Taint.Yellow ] out

(* 外发 sink:信息流检查 —— secret 污点不能外发(DESIGN §7、confinement)。 *)
let send (r : sink t) (v : string Taint.t) =
  ensure_active r;
  if Taint.is_sensitive v then
    raise (Capability_violation
             (Printf.sprintf
                "IFC violation: secret-tainted data cannot flow to outbound sink %s (%s). \
                 next: obtain a declassify capability."
                (id r) r.name));
  (* 真实实现走 net helper;这里模拟外发。 *)
  Printf.printf "  [sink %s] sent %d bytes (taint=[%s])\n"
    r.name (String.length v.Taint.value)
    (String.concat "," (List.map Taint.label_to_string v.Taint.labels))

(* ======== ATTENUATE(单向,派生新 cap,parent 指向原 cap) ======== *)

let sub (r : dir t) seg : dir t =
  ensure_active r;
  let _ = safe_join r.root seg in           (* 复用越界检查 *)
  { r with rid = fresh_id ();
           root = safe_join r.root seg;
           parent = Some r }

let read_only (r : dir t) : dir t =
  { r with rid = fresh_id ();
           ops = List.filter (fun o -> o = Read || o = List) r.ops;
           parent = Some r }

(* ======== 可撤销 forwarder ======== *)

let make_revocable (r : 'k t) : 'k t * revoker =
  let f = { r with rid = fresh_id (); parent = Some r } in
  (f, { target = f })

let revoke (rv : revoker) = rv.target.revoked <- true

(* ======== declassify(需能力) ======== *)

let declassify (dc : declassifier) (v : string Taint.t) : string Taint.t =
  { v with Taint.labels =
             List.filter (fun l -> l <> dc.dc_of) v.Taint.labels }

(* ======== MINT(仅 TCB) ======== *)

(* ======== 存在类型:抹去 phantom,供求值器统一持有 ======== *)

type any = raw
let any_dir (r : dir t) : any = r
let any_sink (r : sink t) : any = r
let any_cmd (r : command t) : any = r
let as_dir (a : any) : dir t option = if a.kind = "dir" then Some a else None
let as_sink (a : any) : sink t option = if a.kind = "sink" then Some a else None
let as_cmd (a : any) : command t option = if a.kind = "command" then Some a else None
let any_describe (a : any) = describe a
let any_is_active (a : any) = is_active a
let any_kind (a : any) = a.kind
let any_taint (a : any) = a.taint

module Trusted = struct
  let create_minter () = Minter
  let create_declassifier ~of_ = { dc_of = of_ }

  let mint_dir (_ : minter) ~root ~writable ~taint : dir t =
    { rid = fresh_id (); revoked = false; kind = "dir"; root;
      ops = (if writable then [ Read; Write; Delete; List ] else [ Read; List ]);
      taint; ttl = None; name = ""; argv = []; cenv = []; parent = None }

  let mint_sink (_ : minter) ~name : sink t =
    { rid = fresh_id (); revoked = false; kind = "sink"; root = "";
      ops = []; taint = Taint.Green; ttl = None; name; argv = []; cenv = []; parent = None }

  let mint_command (_ : minter) ~argv ~cwd ~env : command t =
    { rid = fresh_id (); revoked = false; kind = "command"; root = cwd;
      ops = [ Exec ]; taint = Taint.Yellow; ttl = None; name = String.concat " " argv;
      argv; cenv = env; parent = None }
end
