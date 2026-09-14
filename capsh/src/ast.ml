(* ast.ml — capsh 抽象语法树。 *)

type quasi_kind = QPath | QSh          (* 注入安全模板种类 *)

type quasi_seg =
  | QLit of string                     (* 字面片段 *)
  | QInterp of string                  (* ${ident} 插值:恒为数据,不改变结构 *)

type expr =
  | EStr    of string                  (* "..." 字符串字面量 *)
  | EQuasi  of quasi_kind * quasi_seg list
  | EVar    of string
  | EGrantDir  of string * string list (* grant dir "PATH" {ops} *)
  | EGrantSink of string               (* grant sink "NAME" *)
  | EGrantCmd  of quasi_seg list * (string * expr) list
                                       (* grant command sh`...` {cwd: e, ...} *)
  | EMethod of expr * string * expr list  (* recv.method(args) —— 使用/衰减 *)
  | ECall   of string * expr list      (* 内置自由函数,如 print(x) *)

type scope_kind = Confine | Spawn   (* confine=信息流区室;spawn=衰减委托的子主体 *)

type stmt =
  | SLet   of string * expr
  | SExpr  of expr
  | SScope of scope_kind * string * (string * expr) list * stmt list
              (* kind "label" with { name: capexpr, ... } { body } *)

type program = stmt list
