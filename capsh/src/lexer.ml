(* lexer.ml — 手写词法分析器(无 ocamllex 依赖)。 *)

type token =
  | TIdent of string
  | TStr   of string
  | TQuasi of Ast.quasi_kind * Ast.quasi_seg list
  | TLParen | TRParen | TLBrace | TRBrace | TComma | TDot | TEq | TColon
  | TEOF

exception Lex_error of string

type st = { src : string; mutable pos : int; len : int }

let mk src = { src; pos = 0; len = String.length src }
let peek st = if st.pos < st.len then Some st.src.[st.pos] else None
let peek2 st = if st.pos + 1 < st.len then Some st.src.[st.pos + 1] else None
let adv st = st.pos <- st.pos + 1

let is_id_start c = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c = '_'
let is_id c = is_id_start c || (c >= '0' && c <= '9') || c = '-'

let rec skip_trivia st =
  match peek st with
  | Some (' ' | '\t' | '\r' | '\n') -> adv st; skip_trivia st
  | Some '#' ->                                     (* # 行注释 *)
    let rec eol () = match peek st with
      | Some '\n' | None -> () | Some _ -> adv st; eol () in
    eol (); skip_trivia st
  | _ -> ()

let read_string st =
  adv st;                                           (* 吃掉开引号 *)
  let b = Buffer.create 16 in
  let rec loop () =
    match peek st with
    | None -> raise (Lex_error "字符串未闭合")
    | Some '"' -> adv st
    | Some '\\' ->
      adv st;
      (match peek st with
       | Some 'n' -> Buffer.add_char b '\n'; adv st
       | Some 't' -> Buffer.add_char b '\t'; adv st
       | Some c   -> Buffer.add_char b c; adv st
       | None -> raise (Lex_error "转义未闭合"));
      loop ()
    | Some c -> Buffer.add_char b c; adv st; loop ()
  in
  loop (); TStr (Buffer.contents b)

(* 读 quasi 体:`...${ident}...`。假定当前字符是开反引号。 *)
let read_quasi st kind =
  adv st;                                           (* 吃掉开 ` *)
  let segs = ref [] in
  let lit = Buffer.create 16 in
  let flush () =
    if Buffer.length lit > 0 then
      (segs := Ast.QLit (Buffer.contents lit) :: !segs; Buffer.clear lit) in
  let rec loop () =
    match peek st with
    | None -> raise (Lex_error "quasi 未闭合")
    | Some '`' -> adv st
    | Some '$' when peek2 st = Some '{' ->
      flush (); adv st; adv st;                     (* 吃 ${ *)
      let idb = Buffer.create 8 in
      let rec rid () = match peek st with
        | Some '}' -> adv st
        | Some c when is_id c -> Buffer.add_char idb c; adv st; rid ()
        | _ -> raise (Lex_error "插值 ${...} 未闭合或非法标识符") in
      rid ();
      segs := Ast.QInterp (Buffer.contents idb) :: !segs;
      loop ()
    | Some c -> Buffer.add_char lit c; adv st; loop ()
  in
  loop (); flush ();
  TQuasi (kind, List.rev !segs)

let quasi_kind_of = function
  | "path" -> Some Ast.QPath
  | "sh"   -> Some Ast.QSh
  | _ -> None

let read_ident st =
  let b = Buffer.create 8 in
  let rec loop () = match peek st with
    | Some c when is_id c -> Buffer.add_char b c; adv st; loop ()
    | _ -> () in
  loop ();
  let name = Buffer.contents b in
  (* ident 紧跟反引号 => quasi-literal(如 path`...`) *)
  match peek st, quasi_kind_of name with
  | Some '`', Some k -> read_quasi st k
  | _ -> TIdent name

let next st =
  skip_trivia st;
  match peek st with
  | None -> TEOF
  | Some '"' -> read_string st
  | Some '(' -> adv st; TLParen
  | Some ')' -> adv st; TRParen
  | Some '{' -> adv st; TLBrace
  | Some '}' -> adv st; TRBrace
  | Some ',' -> adv st; TComma
  | Some '.' -> adv st; TDot
  | Some ':' -> adv st; TColon
  | Some '=' -> adv st; TEq
  | Some '`' -> raise (Lex_error "裸反引号:quasi 必须带 tag,如 path`...`")
  | Some c when is_id_start c -> read_ident st
  | Some c -> raise (Lex_error (Printf.sprintf "非法字符 %C" c))

(* 全部 token 化(便于回看)。 *)
let tokenize src =
  let st = mk src in
  let rec loop acc =
    match next st with
    | TEOF -> List.rev (TEOF :: acc)
    | t -> loop (t :: acc)
  in
  Array.of_list (loop [])
