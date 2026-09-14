(* taint.ml — 运行期 taint 标签 + 信息流检查(决策 D-taint:运行期起步)。
   对应 DESIGN §7 / capsh-language.md §6。 *)

(* 三色信任 + 细粒度污点。格(lattice)语义:join = 取并集(更受限的一方胜出)。 *)
type label =
  | Green            (* 用户直接输入 / 显式确认 —— 可驱动行动 *)
  | Yellow           (* 本地确定性工具输出 *)
  | Red              (* 网页/外部/子 Agent 输出 —— 只作数据 *)
  | Secret           (* 本地敏感读(.env / 私钥)*)
  | Project          (* 项目内代码/数据 *)
  | External         (* 外部不可信 *)
  | Agent_generated  (* Agent 自身推理结论(不变量 16:视同红)*)

let of_string = function
  | "yellow" -> Yellow | "red" -> Red | "secret" -> Secret
  | "project" -> Project | "external" -> External
  | "agent_generated" -> Agent_generated | _ -> Green

let label_to_string = function
  | Green -> "green" | Yellow -> "yellow" | Red -> "red"
  | Secret -> "secret" | Project -> "project"
  | External -> "external" | Agent_generated -> "agent_generated"

(* 一个携带 taint 与 provenance(来源链)的值。 *)
type 'a t = { value : 'a; labels : label list; prov : string list }

let pure ?(prov = []) value = { value; labels = [ Green ]; prov }

let tag ?(prov = []) labels value = { value; labels; prov }

let dedup xs = List.sort_uniq compare xs

(* join:合并两个 tainted 值的标签与来源链(拼接/组合时用)。 *)
let join a b = dedup (a @ b)

let map f x = { x with value = f x.value }

(* 两个 tainted 值组合(如字符串拼接):值合并 + 标签取并 + 来源链合并。 *)
let combine f x y =
  { value = f x.value y.value;
    labels = join x.labels y.labels;
    prov = dedup (x.prov @ y.prov) }

let has label x = List.mem label x.labels

let is_sensitive x = has Secret x

(* 是否可作为「可驱动行动的绿色依据」:只有纯绿、无红/黄/agent 污染。 *)
let is_green x = x.labels = [ Green ]

let to_string x =
  Printf.sprintf "<%s | taint=[%s]%s>"
    (String.escaped x.value)
    (String.concat "," (List.map label_to_string x.labels))
    (if x.prov = [] then "" else " | prov=" ^ String.concat "<-" x.prov)
