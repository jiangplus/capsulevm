(* broker.ml — 最小 Capability Broker(L3)。
   持有唯一的 minter(铸造权威),是能力的唯一来源(powerbox / grant)。
   consumer(capsh 脚本层)拿到能力,但永远拿不到 minter —— 因此无法铸造。
   见 DESIGN §4。 *)

type t = { minter : Cap.minter }

let create () = { minter = Cap.Trusted.create_minter () }

(* grant:powerbox 授权入口。真实实现会先经 L5/L6 consent;此处直接铸造。 *)
let grant_dir (b : t) ~root ~writable ~taint : Cap.dir Cap.t =
  Cap.Trusted.mint_dir b.minter ~root ~writable ~taint

let grant_sink (b : t) ~name : Cap.sink Cap.t =
  Cap.Trusted.mint_sink b.minter ~name

(* grant CommandCap:固定 argv、绑定 cwd、env allowlist(D9:一命令一卡)。 *)
let grant_command (b : t) ~argv ~cwd ~env : Cap.command Cap.t =
  Cap.Trusted.mint_command b.minter ~argv ~cwd ~env

(* 颁发 declassify 能力(代表用户/策略的显式去敏授权,Agent 不能自铸)。 *)
let grant_declassifier (_ : t) ~of_ : Cap.declassifier =
  Cap.Trusted.create_declassifier ~of_
