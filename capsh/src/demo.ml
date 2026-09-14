(* demo.ml — 可运行 demo:把 Capable 的核心论点变成能跑的事实。
   演示:grant / 相对路径读 / 越界拒绝 / 衰减(sub, read_only)/ 撤销级联 /
   taint 信息流(secret 不能外发)/ declassify 需能力。
   注意:capsh 脚本层在这里由「只用 Cap 的 USE/ATTENUATE API」的代码模拟;
   它拿不到 minter,也无法构造 Cap.t(见 forge_fail.ml 的编译期证明)。 *)

let section name = Printf.printf "\n== %s ==\n" name
let ok m = Printf.printf "  [ok]   %s\n" m
let deny m = Printf.printf "  [deny] %s\n" m

let expect_violation label f =
  try f (); Printf.printf "  [FAIL] %s —— 本应被拒却通过了!\n" label
  with Cap.Capability_violation msg -> deny (label ^ " -> " ^ msg)

let () =
  (* 准备一个沙箱工作目录 *)
  let root = Filename.concat (Filename.get_temp_dir_name ()) "capable_demo" in
  (try Sys.mkdir root 0o755 with Sys_error _ -> ());
  let write rel content =
    let oc = open_out (Filename.concat root rel) in
    output_string oc content; close_out oc in
  write "main.ml" "let () = print_endline \"hello\"\n";
  (try Sys.mkdir (Filename.concat root "src") 0o755 with Sys_error _ -> ());
  write "src/secret.txt" "API_KEY=sk-supersecret\n";

  let broker = Broker.create () in

  section "1. grant DirCap + 相对路径读(指名即授权)";
  let repo = Broker.grant_dir broker ~root ~writable:true ~taint:Taint.Project in
  Printf.printf "  granted %s\n" (Cap.describe repo);
  let content = Cap.read repo "main.ml" in
  ok (Printf.sprintf "read main.ml -> %s" (Taint.to_string content));

  section "2. 越界访问被拒(裸路径不是权限)";
  expect_violation "读绝对路径 /etc/passwd" (fun () -> ignore (Cap.read repo "/etc/passwd"));
  expect_violation "../ 路径穿越" (fun () -> ignore (Cap.read repo "../../etc/passwd"));

  section "3. 衰减(单向收窄):sub + read_only";
  let src_ro = Cap.read_only (Cap.sub repo "src") in
  Printf.printf "  derived %s\n" (Cap.describe src_ro);
  let secret = Cap.read src_ro "secret.txt" in
  ok (Printf.sprintf "读 src/secret.txt(经衰减 cap)-> taint=[%s]"
        (String.concat "," (List.map Taint.label_to_string secret.Taint.labels)));
  (* read_only 后仍能读,但结构上无写(ops 已去掉 Write)——写通道在类型/ops 层不可达 *)

  section "4. taint 信息流:secret 不能流入外发 sink(confinement)";
  let out = Broker.grant_sink broker ~name:"https://collector.example.com" in
  (* 把一个显式标 secret 的读:重铸一个 taint=Secret 的 cap 演示 *)
  let vault = Broker.grant_dir broker ~root ~writable:false ~taint:Taint.Secret in
  let apikey = Cap.read (Cap.sub vault "src") "secret.txt" in
  ok (Printf.sprintf "读出 secret(taint=[%s])"
        (String.concat "," (List.map Taint.label_to_string apikey.Taint.labels)));
  expect_violation "把 secret 数据发到外发 sink" (fun () -> Cap.send out apikey);

  section "5. declassify 需要能力(Agent 不能自铸)";
  let dc = Broker.grant_declassifier broker ~of_:Taint.Secret in
  let declassified = Cap.declassify dc apikey in
  Cap.send out declassified;
  ok "declassify 后(持 declassify 能力)可外发,并留审计";

  section "6. 可撤销 forwarder:撤销后 ENOTCAPABLE(撤销级联)";
  let repo_f, rv = Cap.make_revocable repo in
  (* 在 forwarder 仍活跃时,派生一个子 cap —— 之后撤销祖先,验证级联失效 *)
  let child = Cap.sub repo_f "src" in
  ok (Printf.sprintf "经 forwarder 读 main.ml -> %d bytes"
        (String.length (Cap.read repo_f "main.ml").Taint.value));
  ok (Printf.sprintf "派生 child 读 src/secret.txt(撤销前)-> %d bytes"
        (String.length (Cap.read child "secret.txt").Taint.value));
  Cap.revoke rv;
  expect_violation "撤销后再经 forwarder 读" (fun () -> ignore (Cap.read repo_f "main.ml"));
  expect_violation "撤销祖先后,派生 child 也失效(级联)" (fun () -> ignore (Cap.read child "secret.txt"));

  Printf.printf "\nDemo 完成:能力不可伪造(见 forge_fail.ml)、指名即授权、衰减/撤销/taint 全部生效。\n"
