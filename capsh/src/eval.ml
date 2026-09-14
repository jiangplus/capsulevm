(* eval.ml — capsh 求值器,对能力后端 B 参数化(函子)。
   同一份求值逻辑,既可跑进程内 Cap(Backend_local),也可跑远端 Broker(Backend_rpc)。
   求值器是 TCB:脚本只能通过 B 暴露的操作触达资源。 *)

open Value

module Make (B : Backend.BACKEND) = struct
  type env = { vars : (string, B.cap Value.t) Hashtbl.t }

  let create_env () = { vars = Hashtbl.create 32 }

  let lookup env name =
    match Hashtbl.find_opt env.vars name with
    | Some v -> v
    | None ->
      raise (Capsh_error (name ^ " 未定义(没有全局命名空间;只有词法在作用域或被传入的能力可达)"))

  (* quasi:字面片段 + 插值拼接。path 的每个 ${x} 必须是单一安全路径段(杀路径注入)。 *)
  let eval_quasi env kind segs =
    let taints = ref [] and provs = ref [] in
    let buf = Buffer.create 32 in
    List.iter
      (fun seg ->
        match seg with
        | Ast.QLit s -> Buffer.add_string buf s
        | Ast.QInterp name ->
          let v = as_data (lookup env name) in
          let s = v.Taint.value in
          (match kind with
           | Ast.QPath ->
             if String.contains s '/' || s = ".." || s = "." || s = "" then
               raise (Capsh_error
                        (Printf.sprintf "path quasi 插值 ${%s}=%S 不是单一安全路径段(注入被拒)" name s))
           | Ast.QSh -> ());
          taints := Taint.join !taints v.Taint.labels;
          provs := s :: !provs;
          Buffer.add_string buf s)
      segs;
    let labels = if !taints = [] then [ Taint.Green ] else !taints in
    VData (Taint.tag ~prov:(List.rev !provs) labels (Buffer.contents buf))

  (* sh quasi -> argv:字面按空白切分;插值恒为【单个】argv 元素(杀 shell 注入)。 *)
  let argv_of_sh env segs =
    let args = ref [] and cur = Buffer.create 16 and have = ref false in
    let flush () =
      if !have then (args := Buffer.contents cur :: !args; Buffer.clear cur; have := false) in
    List.iter
      (function
        | Ast.QLit s ->
          String.iter
            (fun c ->
              if c = ' ' || c = '\t' || c = '\n' then flush ()
              else (Buffer.add_char cur c; have := true))
            s
        | Ast.QInterp name ->
          let v = as_data (lookup env name) in
          Buffer.add_string cur v.Taint.value; have := true)
      segs;
    flush ();
    List.rev !args

  let rec eval env (e : Ast.expr) : B.cap Value.t =
    match e with
    | Ast.EStr s -> VData (Taint.tag ~prov:[ "literal" ] [ Taint.Green ] s)
    | Ast.EQuasi (k, segs) -> eval_quasi env k segs
    | Ast.EVar x -> lookup env x
    | Ast.EGrantDir (path, ops) ->
      let writable = List.mem "write" ops in
      let contains hay needle =
        let hl = String.length hay and nl = String.length needle in
        let rec go i =
          if i + nl > hl then false
          else if String.sub hay i nl = needle then true
          else go (i + 1) in
        nl > 0 && go 0 in
      let secret =
        List.mem "secret" ops
        || List.exists (contains path) [ "secret"; "vault"; ".ssh"; ".env" ] in
      VCap (B.grant_dir ~root:path ~writable ~secret)
    | Ast.EGrantSink name -> VCap (B.grant_sink ~name)
    | Ast.EGrantCmd (segs, fields) ->
      let argv = argv_of_sh env segs in
      let cwd =
        match List.assoc_opt "cwd" fields with
        | Some e -> as_cap (eval env e)
        | None -> raise (Capsh_error "grant command 需要 cwd") in
      VCap (B.grant_cmd ~cwd ~argv)
    | Ast.EMethod (recv, m, args) ->
      eval_method (as_cap (eval env recv)) m (List.map (eval env) args)
    | Ast.ECall (name, args) -> eval_builtin name (List.map (eval env) args)

  and eval_method cap m args =
    let arg0 () =
      match args with a :: _ -> as_data a | [] -> raise (Capsh_error ("." ^ m ^ " 缺参数")) in
    match m with
    | "read" -> VData (B.read cap (arg0 ()).Taint.value)
    | "list" -> VData (Taint.tag [ Taint.Project ] (B.list cap (arg0 ()).Taint.value))
    | "sub" -> VCap (B.sub cap (arg0 ()).Taint.value)
    | "readonly" -> VCap (B.readonly cap)
    | "send" -> B.send cap (arg0 ()); VUnit
    | "describe" -> VData (Taint.tag [ Taint.Green ] (B.describe cap))
    | _ -> raise (Capsh_error ("能力无方法 ." ^ m ^ "(或类型不符)"))

  and eval_builtin name args =
    match (name, args) with
    | "print", [ v ] ->
      let s =
        match v with
        | VData d -> Taint.to_string d
        | VCap c -> B.describe c
        | VUnit -> "()" in
      print_endline ("  " ^ s); VUnit
    | "print", _ -> raise (Capsh_error "print 需要 1 个参数")
    | "run", [ v ] -> VData (B.exec (as_cap v))
    | "run", _ -> raise (Capsh_error "run 需要 1 个参数")
    | _ -> raise (Capsh_error ("未知内置函数:" ^ name))

  let rec exec_stmt env = function
    | Ast.SLet (name, e) -> Hashtbl.replace env.vars name (eval env e)
    | Ast.SExpr e -> ignore (eval env e)
    | Ast.SScope (kind, label, binds, body) ->
      let bound = List.map (fun (n, e) -> (n, eval env e)) binds in
      let caps = List.filter_map (fun (_, v) -> match v with VCap c -> Some c | _ -> None) bound in
      if kind = Ast.Confine then begin
        let has_secret = List.exists (fun c -> B.taint c = Taint.Secret) caps in
        let has_sink = List.exists (fun c -> B.kind c = "sink") caps in
        if has_secret && has_sink then
          raise (Capsh_error
                   (Printf.sprintf
                      "confine 区室 %S 违反 confinement:不能同时持有敏感读(Secret)与外发 sink"
                      label))
      end;
      let child = { vars = Hashtbl.create 16 } in
      List.iter (fun (n, v) -> Hashtbl.replace child.vars n v) bound;
      Printf.printf "  [%s %S] 委托 %d 项能力(仅列出的可见;其余不可达)\n"
        (match kind with Ast.Confine -> "confine" | Ast.Spawn -> "spawn")
        label (List.length bound);
      List.iter (exec_stmt child) body

  let run_program src =
    let env = create_env () in
    List.iter (exec_stmt env) (Parser.parse_program src)
end
