(* value.ml — capsh 运行期值。对能力类型 'c 多态(本地 Cap.any 或远端 ref)。 *)

type 'c t =
  | VData of string Taint.t     (* 普通值:字符串 + 污点。永远不能直接访问资源。 *)
  | VCap  of 'c                 (* 能力:不可伪造对象引用(后端决定表示)。 *)
  | VUnit

exception Capsh_error of string

let type_name = function VData _ -> "Data" | VCap _ -> "Cap" | VUnit -> "Unit"

let as_data = function
  | VData d -> d
  | v -> raise (Capsh_error ("期望 Data,得到 " ^ type_name v))

let as_cap = function
  | VCap c -> c
  | v -> raise (Capsh_error ("期望 Cap,得到 " ^ type_name v ^ "(裸值不是能力:指名即授权)"))
