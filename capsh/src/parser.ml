(* parser.ml — 手写递归下降解析器。
   文法:
     program := { stmt }
     stmt    := "let" IDENT "=" expr | expr
     expr    := postfix
     postfix := primary { "." IDENT "(" [args] ")" }
     primary := STR | QUASI | grant | IDENT "(" [args] ")" | IDENT | "(" expr ")"
     grant   := "grant" ("dir" STR "{" [opset] "}" | "sink" STR)
     args    := expr { "," expr }
*)

open Lexer
exception Parse_error of string

type st = { toks : token array; mutable p : int }

let mk toks = { toks; p = 0 }
let cur st = st.toks.(st.p)
let adv st = st.p <- st.p + 1

let tok_str = function
  | TIdent s -> "ident " ^ s | TStr _ -> "string" | TQuasi _ -> "quasi"
  | TLParen -> "(" | TRParen -> ")" | TLBrace -> "{" | TRBrace -> "}"
  | TComma -> "," | TDot -> "." | TEq -> "=" | TColon -> ":" | TEOF -> "<eof>"

let expect st t =
  if cur st = t then adv st
  else raise (Parse_error (Printf.sprintf "期望 %s,得到 %s" (tok_str t) (tok_str (cur st))))

let expect_ident st =
  match cur st with
  | TIdent s -> adv st; s
  | t -> raise (Parse_error ("期望标识符,得到 " ^ tok_str t))

let expect_str st =
  match cur st with
  | TStr s -> adv st; s
  | t -> raise (Parse_error ("期望字符串,得到 " ^ tok_str t))

let is_ident st name = match cur st with TIdent s -> s = name | _ -> false

let rec parse_expr st : Ast.expr = parse_postfix st

and parse_postfix st =
  let recv = ref (parse_primary st) in
  let continue = ref true in
  while !continue do
    match cur st with
    | TDot ->
      adv st;
      let m = expect_ident st in
      expect st TLParen;
      let args = parse_args st in
      expect st TRParen;
      recv := Ast.EMethod (!recv, m, args)
    | _ -> continue := false
  done;
  !recv

and parse_args st : Ast.expr list =
  if cur st = TRParen then []
  else begin
    let rec loop acc =
      let e = parse_expr st in
      match cur st with
      | TComma -> adv st; loop (e :: acc)
      | _ -> List.rev (e :: acc)
    in
    loop []
  end

and parse_primary st : Ast.expr =
  match cur st with
  | TStr s -> adv st; Ast.EStr s
  | TQuasi (k, segs) -> adv st; Ast.EQuasi (k, segs)
  | TLParen -> adv st; let e = parse_expr st in expect st TRParen; e
  | TIdent "grant" -> adv st; parse_grant st
  | TIdent name ->
    adv st;
    if cur st = TLParen then begin              (* 内置调用 name(args) *)
      adv st; let args = parse_args st in expect st TRParen;
      Ast.ECall (name, args)
    end else Ast.EVar name                       (* 变量引用 *)
  | t -> raise (Parse_error ("表达式起始处非法 token:" ^ tok_str t))

and parse_grant st : Ast.expr =
  if is_ident st "dir" then begin
    adv st;
    let path = expect_str st in
    expect st TLBrace;
    let ops = parse_opset st in
    expect st TRBrace;
    Ast.EGrantDir (path, ops)
  end else if is_ident st "sink" then begin
    adv st;
    let name = expect_str st in
    Ast.EGrantSink name
  end else if is_ident st "command" then begin
    adv st;
    (match cur st with
     | TQuasi (Ast.QSh, segs) ->
       adv st;
       let fields = if cur st = TLBrace then parse_fields st else [] in
       Ast.EGrantCmd (segs, fields)
     | t -> raise (Parse_error ("grant command 后需 sh`...`,得到 " ^ tok_str t)))
  end else
    raise (Parse_error "grant 后需 dir / sink / command")

and parse_fields st : (string * Ast.expr) list =
  expect st TLBrace;
  if cur st = TRBrace then (adv st; [])
  else
    let rec loop acc =
      let k = expect_ident st in
      expect st TColon;
      let v = parse_expr st in
      match cur st with
      | TComma -> adv st; loop ((k, v) :: acc)
      | _ -> expect st TRBrace; List.rev ((k, v) :: acc)
    in
    loop []

and parse_opset st : string list =
  if cur st = TRBrace then []
  else
    let rec loop acc =
      let o = expect_ident st in
      match cur st with
      | TComma -> adv st; loop (o :: acc)
      | _ -> List.rev (o :: acc)
    in
    loop []

and parse_block st : Ast.stmt list =
  expect st TLBrace;
  let rec loop acc =
    if cur st = TRBrace then (adv st; List.rev acc)
    else loop (parse_stmt st :: acc)
  in
  loop []

and parse_scope st kind : Ast.stmt =
  let label = expect_str st in
  if not (is_ident st "with") then raise (Parse_error "confine/spawn 后需 with { ... }");
  adv st;
  let binds = parse_fields st in            (* with { name: capexpr, ... } *)
  let body = parse_block st in
  Ast.SScope (kind, label, binds, body)

and parse_stmt st : Ast.stmt =
  if is_ident st "let" then begin
    adv st;
    let name = expect_ident st in
    expect st TEq;
    let e = parse_expr st in
    Ast.SLet (name, e)
  end else if is_ident st "confine" then (adv st; parse_scope st Ast.Confine)
  else if is_ident st "spawn" then (adv st; parse_scope st Ast.Spawn)
  else Ast.SExpr (parse_expr st)

let parse_program src : Ast.program =
  let st = mk (Lexer.tokenize src) in
  let rec loop acc =
    if cur st = TEOF then List.rev acc
    else loop (parse_stmt st :: acc)
  in
  loop []
