(* backend_local.ml — 进程内后端:直接用 OCaml capsh-core 的 Cap/Broker。 *)

module M : Backend.BACKEND = struct
  type cap = Cap.any

  let broker = Broker.create ()

  let dir_of c =
    match Cap.as_dir c with
    | Some d -> d
    | None -> raise (Value.Capsh_error "需要 DirCap")

  let grant_dir ~root ~writable ~secret =
    let taint = if secret then Taint.Secret else Taint.Project in
    Cap.any_dir (Broker.grant_dir broker ~root ~writable ~taint)

  let grant_sink ~name = Cap.any_sink (Broker.grant_sink broker ~name)

  let grant_cmd ~cwd ~argv =
    let d = dir_of cwd in
    Cap.any_cmd
      (Broker.grant_command broker ~argv ~cwd:(Cap.root_of d)
         ~env:[ "PATH=/usr/bin:/bin:/usr/local/bin"; "HOME=/tmp/capsh-sandbox" ])

  let sub c seg = Cap.any_dir (Cap.sub (dir_of c) seg)
  let readonly c = Cap.any_dir (Cap.read_only (dir_of c))
  let read c rel = Cap.read (dir_of c) rel
  let list c rel = String.concat "\n" (Cap.list (dir_of c) rel)

  let send c v =
    match Cap.as_sink c with
    | Some s -> Cap.send s v
    | None -> raise (Value.Capsh_error "需要 sink")

  let exec c =
    match Cap.as_cmd c with
    | Some cmd -> Cap.exec cmd
    | None -> raise (Value.Capsh_error "需要 CommandCap")

  let describe = Cap.any_describe
  let kind = Cap.any_kind
  let taint = Cap.any_taint
end
