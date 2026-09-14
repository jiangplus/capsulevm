(* remote_demo.ml — capsh 侧(OCaml)驱动 Rust capable-rpc Broker 的端到端 demo。
   用法:remote_demo <sock> <workspace_root>
   证明:capsh 只持 opaque ref,真实能力在 Rust Broker;操作全走 CapTP-lite socket。 *)

let () =
  let sock = Sys.argv.(1) and root = Sys.argv.(2) in
  let c = Rpc_client.connect sock in
  let sec s = Printf.printf "\n== %s ==\n" s in
  let ok s = Printf.printf "  [ok]   %s\n" s in
  let deny s = Printf.printf "  [deny] %s\n" s in
  let expect_deny label f =
    try f (); Printf.printf "  [FAIL] %s 本应被拒\n" label
    with Rpc_client.Rpc_error m -> deny (label ^ " -> " ^ m) in

  sec "1. grant DirCap + 相对路径读(OCaml->socket->Rust Broker)";
  let repo = Rpc_client.grant_dir c ~root ~ops:"read,list,write" ~taint:"project" in
  Printf.printf "  granted %s\n" (Rpc_client.describe c repo);
  let (t, data) = Rpc_client.read c repo "main.txt" in
  ok (Printf.sprintf "read main.txt [%s] %s" t (String.trim data));

  sec "2. 越界访问被 Broker 拒绝";
  expect_deny "读 /etc/passwd" (fun () -> ignore (Rpc_client.read c repo "/etc/passwd"));
  expect_deny "../ 穿越" (fun () -> ignore (Rpc_client.read c repo "../../etc/passwd"));

  sec "3. 衰减(sub + readonly)后读";
  let ro = Rpc_client.derive_readonly c (Rpc_client.derive_sub c repo "src") in
  let (t2, d2) = Rpc_client.read c ro "secret.txt" in
  ok (Printf.sprintf "read src/secret.txt(经衰减) [%s] %s" t2 (String.trim d2));

  sec "4. taint IFC:secret 不能外发";
  let vault = Rpc_client.grant_dir c ~root ~ops:"read" ~taint:"secret" in
  let (t3, d3) = Rpc_client.read c vault "src/secret.txt" in
  ok (Printf.sprintf "读出 secret [%s] %s" t3 (String.trim d3));
  let sink = Rpc_client.grant_sink c ~name:"https://collector.example.com" in
  Rpc_client.send c sink ~taint:"project" ~data:"harmless";
  ok "普通数据外发 OK";
  expect_deny "secret 数据外发" (fun () -> Rpc_client.send c sink ~taint:"secret" ~data:d3);

  sec "5. CommandCap:固定 argv,无 shell";
  let echo = Rpc_client.grant_cmd c ~cwd:repo ~argv:[ "echo"; "hello-via-socket" ] in
  let (t4, d4) = Rpc_client.exec c echo in
  ok (Printf.sprintf "exec [%s] %s" t4 (String.trim d4));

  sec "6. 撤销 + 级联";
  let child = Rpc_client.derive_sub c repo "src" in
  Rpc_client.revoke c repo;
  expect_deny "撤销祖先后派生 cap 失效" (fun () -> ignore (Rpc_client.read c child "secret.txt"));

  Printf.printf "\ncapsh(OCaml) <-> capable-rpc(Rust) 端到端跑通。\n";
  Rpc_client.close c
