(* main.ml — capsh 解释器 CLI。
     capsh <program.capsh>                     进程内后端(Backend_local)
     CAPSH_BROKER=<sock> capsh <program.capsh> 远端后端(Backend_rpc,走 Rust Broker)*)

let () =
  match Array.to_list Sys.argv with
  | _ :: file :: _ ->
    let ic = open_in_bin file in
    let src = really_input_string ic (in_channel_length ic) in
    close_in ic;
    let run () =
      match Sys.getenv_opt "CAPSH_BROKER" with
      | Some sock ->
        let conn = Rpc_client.connect sock in
        let module B = Backend_rpc.Make (struct
          let conn = conn
        end) in
        let module E = Eval.Make (B) in
        E.run_program src
      | None ->
        let module E = Eval.Make (Backend_local.M) in
        E.run_program src
    in
    (try run () with
     | Value.Capsh_error m -> Printf.eprintf "capsh error: %s\n" m; exit 1
     | Cap.Capability_violation m -> Printf.eprintf "ENOTCAPABLE: %s\n" m; exit 1
     | Rpc_client.Rpc_error m -> Printf.eprintf "ENOTCAPABLE(remote): %s\n" m; exit 1
     | Lexer.Lex_error m -> Printf.eprintf "lex error: %s\n" m; exit 1
     | Parser.Parse_error m -> Printf.eprintf "parse error: %s\n" m; exit 1)
  | _ ->
    prerr_endline "usage: capsh <program.capsh>  (set CAPSH_BROKER=<sock> for remote broker)";
    exit 2
