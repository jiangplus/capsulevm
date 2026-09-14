(* rpc_client.ml — capsh 侧的 CapTP-lite 客户端(OCaml)。
   通过 Unix socket 驱动 Rust capable-rpc Broker。
   capsh 只持有 opaque cap ref(会话绑定,不可伪造);真实能力活在 Broker。 *)

type conn = { fd : Unix.file_descr }

exception Rpc_error of string

(* ---- 帧:4 字节大端长度 + body ---- *)

let write_all fd b =
  let n = Bytes.length b in
  let rec loop off = if off < n then loop (off + Unix.write fd b off (n - off)) in
  loop 0

let read_exact fd n =
  let b = Bytes.create n in
  let rec loop off =
    if off < n then begin
      let r = Unix.read fd b off (n - off) in
      if r = 0 then raise (Rpc_error "连接关闭(eof)");
      loop (off + r)
    end
  in
  loop 0; b

let send_frame c (s : string) =
  let len = String.length s in
  let h = Bytes.create 4 in
  Bytes.set h 0 (Char.chr ((len lsr 24) land 0xff));
  Bytes.set h 1 (Char.chr ((len lsr 16) land 0xff));
  Bytes.set h 2 (Char.chr ((len lsr 8) land 0xff));
  Bytes.set h 3 (Char.chr (len land 0xff));
  write_all c.fd h;
  write_all c.fd (Bytes.of_string s)

let recv_frame c =
  let h = read_exact c.fd 4 in
  let len =
    (Char.code (Bytes.get h 0) lsl 24)
    lor (Char.code (Bytes.get h 1) lsl 16)
    lor (Char.code (Bytes.get h 2) lsl 8)
    lor Char.code (Bytes.get h 3)
  in
  Bytes.to_string (read_exact c.fd len)

(* ---- base64 ---- *)

let b64_alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

let b64_decode s =
  let val_of c =
    if c >= 'A' && c <= 'Z' then Char.code c - 65
    else if c >= 'a' && c <= 'z' then Char.code c - 71
    else if c >= '0' && c <= '9' then Char.code c + 4
    else if c = '+' then 62 else if c = '/' then 63 else -1 in
  let buf = Buffer.create (String.length s) in
  let acc = ref 0 and bits = ref 0 in
  String.iter (fun c ->
      let v = val_of c in
      if v >= 0 then begin
        acc := (!acc lsl 6) lor v; bits := !bits + 6;
        if !bits >= 8 then begin
          bits := !bits - 8;
          Buffer.add_char buf (Char.chr ((!acc lsr !bits) land 0xff))
        end
      end) s;
  Buffer.contents buf

let b64_encode s =
  let n = String.length s in
  let buf = Buffer.create ((n + 2) / 3 * 4) in
  let byte i = if i < n then Char.code s.[i] else 0 in
  let i = ref 0 in
  while !i < n do
    let b0 = byte !i and b1 = byte (!i + 1) and b2 = byte (!i + 2) in
    let x = (b0 lsl 16) lor (b1 lsl 8) lor b2 in
    Buffer.add_char buf b64_alpha.[(x lsr 18) land 63];
    Buffer.add_char buf b64_alpha.[(x lsr 12) land 63];
    Buffer.add_char buf (if !i + 1 < n then b64_alpha.[(x lsr 6) land 63] else '=');
    Buffer.add_char buf (if !i + 2 < n then b64_alpha.[x land 63] else '=');
    i := !i + 3
  done;
  Buffer.contents buf

(* ---- 连接 + 调用 ---- *)

let connect path =
  let fd = Unix.socket Unix.PF_UNIX Unix.SOCK_STREAM 0 in
  Unix.connect fd (Unix.ADDR_UNIX path);
  { fd }

let close c = (try Unix.close c.fd with _ -> ())

let split_tab s = String.split_on_char '\t' s

(* 原始调用:发请求,返回回复字段列表。 *)
let call c req = split_tab (send_frame c req; recv_frame c)

(* 期望 CAP\t<ref>,否则 Rpc_error。 *)
let expect_cap = function
  | [ "CAP"; r ] -> r
  | "ERR" :: msg -> raise (Rpc_error (String.concat "\t" msg))
  | other -> raise (Rpc_error ("期望 CAP,得到 " ^ String.concat " " other))

(* 期望 OK\t<taint>\t<b64>,返回 (taint, 解码后字节)。 *)
let expect_ok = function
  | "OK" :: taint :: rest -> (taint, b64_decode (String.concat "\t" rest))
  | "ERR" :: msg -> raise (Rpc_error (String.concat "\t" msg))
  | other -> raise (Rpc_error ("期望 OK,得到 " ^ String.concat " " other))

(* ---- 高层能力操作(作用在 opaque ref 上)---- *)

let grant_dir c ~root ~ops ~taint =
  expect_cap (call c (Printf.sprintf "GRANT_DIR\t%s\t%s\t%s" root ops taint))

let grant_sink c ~name = expect_cap (call c (Printf.sprintf "GRANT_SINK\t%s" name))

let grant_cmd c ~cwd ~argv =
  let argv_s = String.concat "\x1f" argv in
  expect_cap (call c (Printf.sprintf "GRANT_CMD\t%s\t%s" cwd argv_s))

let derive_sub c r seg = expect_cap (call c (Printf.sprintf "DERIVE\t%s\tsub\t%s" r seg))
let derive_readonly c r = expect_cap (call c (Printf.sprintf "DERIVE\t%s\treadonly" r))

let read c r rel = expect_ok (call c (Printf.sprintf "INVOKE\t%s\tread\t%s" r rel))
let list c r rel = expect_ok (call c (Printf.sprintf "INVOKE\t%s\tlist\t%s" r rel))
let exec c r = expect_ok (call c (Printf.sprintf "INVOKE\t%s\texec" r))

let send c r ~taint ~data =
  match call c (Printf.sprintf "INVOKE\t%s\tsend\t%s\t%s" r taint (b64_encode data)) with
  | "OK" :: _ -> ()
  | "ERR" :: msg -> raise (Rpc_error (String.concat "\t" msg))
  | other -> raise (Rpc_error ("send 未知回复 " ^ String.concat " " other))

let revoke c r =
  match call c (Printf.sprintf "REVOKE\t%s" r) with
  | "OK" :: _ -> () | "ERR" :: m -> raise (Rpc_error (String.concat "\t" m))
  | _ -> ()

let describe c r =
  match call c (Printf.sprintf "DESCRIBE\t%s" r) with
  | "OK" :: _ :: rest -> String.concat "\t" rest
  | other -> String.concat " " other
