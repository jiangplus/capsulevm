# capfish 语言设计 v0.1

> **capfish** = fish 的表面语法 + capsh 的能力语义。
> 目标(jiangplus):在**语法与使用方式上接近现有 shell(fish)**,同时**尽量保留 capsh 的全部功能**;
> 冲突处给出取舍说明。后端不变:仍是 newton 复审通过的 L3 Broker(能力模型 + C1 沙箱 + L5 consent + capvm ABI),
> capfish 只是换掉前端语言。规范谱系:E 语言对象能力 + Capsicum + 本仓库 16 条不变量;
> 参见 [capsh-language.md](capsh-language.md)、[capsh-on-fish-eval.md](capsh-on-fish-eval.md)。

---

## 0. 一个核心设计:管道传递「带污点的类型化值」

fish 的管道天生是"值流水线"。capfish 把这条管道从**纯字符串**升级为**类型化 + 带污点**的值:

- 管道里流动的是 **Data(带 taint/provenance)** 或 **Cap(不可伪造句柄)**,不是裸字节。
- **能力的"衰减"= 把 Cap 通过一串收窄 filter**(`$repo | sub src | readonly`)—— 正是 capsh 的
  `.sub().readonly()` 方法链,写成 fish 最地道的管道。
- **信息流(IFC)在管道末端的 sink 处强制**:`$vault read secret.txt | $out send` —— Secret 污点数据
  流进外发 sink,**结构性拒绝**(与 capsh 完全一致)。

这一条让 capfish 既像 shell,又不丢 capsh 的任何语义。

---

## 1. 两个宇宙:Data 与 Cap(不变量 2,保留)

fish 的值默认是字符串;capfish 扩展值模型为两个宇宙:

| 宇宙 | 例子 | 能力 |
|---|---|---|
| **Data** | `"hi"`、`42`、`(cat 之类的输出)`、列表 `a b c` | 计算/拼接/比较/模式匹配;**带 taint**;**永不能直接访问资源** |
| **Cap** | DirCap / FileCap / CommandCap / HttpCap / SinkCap / MessageCap / Revoker | 只能对它发**动词**;不可伪造、不可序列化、不可打印为可重放 token |

```fish
set p "../.ssh/id_rsa"        # Data(字符串)
$p read                        # ✗ 错误:字符串不是能力,没有动词可发
set src (grant dir "./src" read)
$src read main.ts              # ✓ 指名即授权
```

> **取舍**:capsh 用 OCaml abstract type 在**编译期**保证不可伪造;capfish 是动态 shell,
> 不可伪造由 **Broker 句柄模型**强制(Cap 值是会话绑定的 opaque 句柄,真实引用只活在 Broker,
> 换会话即失效 —— 与现在的 `Backend_rpc` 一致)。得:shell 手感;失:编译期类型证明降为运行期 + 结构封装。

---

## 2. 绑定与作用域:用 fish 的 `set`(保留 fish 手感)

```fish
set repo (grant dir "." read write)     # 局部绑定一个 Cap
set -g log (grant sink "audit://local") # 全局
```

- 沿用 fish 的 `set` / `set -l` / `set -g`(作用域)。**没有 `$PATH`、没有全局命名空间**:一个名字只有在
  词法作用域里或被显式 `--grant` 传入时才可达(不变量:无对象引用即无权限)。
- **取舍**:capsh 的 `let` 是单赋值(不可变);fish 的 `set` 可重绑。capfish 规定:**Cap 绑定单向只能变窄**
  —— 允许 `set repo ($repo | readonly)`(重绑到更窄 facet),但没有任何"加宽"路径(要更宽只能重新 `grant`,
  触发新的 consent)。数据绑定沿用 fish 语义。

---

## 3. grant —— 铸造能力(唯一授权入口)

`grant <kind> <args…>` 是 builtin,返回一个 Cap 值(用 `set x (grant …)` 捕获)。权限用 fish 的花括号展开写:

```fish
set repo  (grant dir  "." {read,write})              # DirCap;{read,write} 花括号展开为两个权限词
set vault (grant dir  "./src" {read,secret})         # secret 权限 => 读出的数据带 Secret 污点
set out   (grant sink "https://collector.example.com")
set api   (grant http "https://api.example.com" --methods GET --paths /v1/**)
set hello (grant command echo hello-from-capvm --cwd $repo)   # 一命令一卡、固定 argv、无 shell(D9)
set inbox (grant mailbox "agent:newton")             # MessageCap(owner facet)
```

- `grant` 在 control/可信面或 profile 里可用;不可信子区室(见 §8)**无 grant**,只能用被委托的能力。
- **取舍**:capsh 用 quasi-literal `sh\`echo ${x}\`` 构造命令;capfish 直接用 fish 的词法:
  `grant command echo $x` —— 因为 **fish 不做 word-splitting**,`$x`(即便含空格/元字符)就是**单个 argv 元素**,
  配合 CommandCap 的**无 shell execvp**,注入天然被杀(见 §6)。省了专门的 quasi 语法,换来纯 shell 手感。

---

## 4. 使用能力:`<cap> <动词> [参数]`(像 `git commit` / `docker run`)

能力在**命令位**出现即"对它发消息";第一个参数是动词。这与 shell 的子命令习惯一致,也正好落在 fish 的
"命令名解析" choke 上:capfish 的命令解析器先看该词是不是作用域内的 Cap → 派发到能力动词;否则看是不是被 grant 的
CommandCap → 执行;否则**报错(无 ambient `$PATH` 搜索)**。

```fish
$repo read main.ts               # DirCap 读 => 输出 Data(带 project 污点)到 stdout
$repo list src                   # 列目录
$repo describe                   # 打印占位符 <cap:… read,write @/…>(不可重放)
set content ($repo read main.ts) # 用命令替换把输出捕获为带污点的 Data
$hello run                       # 运行 CommandCap(输出 Yellow);裸 $hello 亦可
$api get /v1/models              # HttpCap GET(经 SSRF/注入防护)
$inbox post build/ok "green msg" # MessageCap 投递(owner facet 可字面投递)
$inbox read                      # 读收件箱(仅 owner facet)
```

动词分两类:**访问/副作用**(`read`/`list`/`run`/`get`/`send`/`post`/`describe`)与**衰减**(§5)。

---

## 5. 衰减 = 把 Cap 通过收窄 filter 管道(保留 capsh 全部衰减,改写成管道)

`$cap | filter1 | filter2 …` 逐级返回**更窄的新 facet**;原能力不变;**单向不可逆**(D10)。

```fish
set srcRO ($repo | sub src | readonly)                 # 收窄到子目录 + 只读
set noEnv ($repo | exclude **/.env **/.git/hooks/**)   # 收窄可见集
set api2  ($api  | methods GET | paths /v1/** | rate 10/min | bytes 1mb)
set tmp   ($repo | ttl 5min)                            # 生命周期收窄
set 1shot ($hello | once)                               # 单次使用
set tainted ($logs | taint external)                   # 声明输出污点
```

衰减 filter(与 capsh 一一对应):

| filter | 适用 | 语义 |
|---|---|---|
| `readonly` | Dir/File/Db | 去写/删 |
| `sub SEG` | Dir | 收窄到子目录(相对,禁止逃逸根) |
| `include GLOB…` / `exclude GLOB…` | Dir | 收窄可见集 |
| `methods …` / `paths …` | Http | 收窄 method / path pattern |
| `rate N/PERIOD` / `bytes N` | Http/Message/Db | 配额 facet |
| `ttl DUR` / `once` / `uses N` | 任意 | 生命周期收窄 |
| `taint TAG` | 任意读能力 | 声明其输出污点 |
| `prefix SUBJ` | Message | 收窄到主题命名空间(委托只投递 facet) |

> **取舍**:capsh 是 `.sub("src").readonly()`(方法链);capfish 是 `| sub src | readonly`(管道)。
> 语义等价;fish 无方法调用语法,管道是其最地道的链式表达。可读性从"对象.方法"变为"值 | 过滤器"。

---

## 6. 命令执行与注入防护(CommandCap:固定 argv、无 shell)

```fish
set msg "oops; rm -rf /; echo pwned"
set echo2 (grant command echo $msg --cwd $repo)
$echo2 run          # $msg 作为【单个】argv 元素传给 echo(execvp,无 shell)
                    # => 元字符原样打印,绝不被解释执行
```

- 无 `$PATH`:`ls`、`cat` 不是 ambient —— 它们要么来自 profile 预 grant 的 CommandCap,要么显式 `grant command`。
- CommandCap = 一命令一卡、argv 在 grant 时固定、cwd 绑定 DirCap、env 剥离(只 PATH)、经 **C1 L1 沙箱**
  (Landlock 限 fs 到 cwd + seccomp 默认禁网/io_uring/跨进程)。
- **注入被杀两处**:① fish 无 word-splitting → 不可信数据是单 argv 元素;② 无 shell 解释。

> **取舍**:capsh 用 `sh\`echo ${msg}\`` quasi 显式标注"这里插值只是数据";capfish 依赖 fish 语义 +
> CommandCap 构造达到同样效果,但**少了那个显式的语法记号**。想要显式记号的可保留可选 `sh(...)` 构造 builtin。

## 7. 路径安全(能力边界即防逃逸)

```fish
set evil "../../etc/passwd"
$repo read $evil        # ✗ DirCap 的 openat2 RESOLVE_BENEATH 直接拒:逃不出授权根
```

- 路径注入由**能力边界**杀死(DirCap 持稳定 fd + openat2 RESOLVE_BENEATH),不依赖字符串检查。
- 可选 `path(...)` builtin 做"单一安全路径段"校验(等价 capsh 的 `path\`\``),用于更早失败 + 明确报错。

## 8. 区室与委托:spawn / confine(保留)

子主体默认**零权限**,只拿显式 `--grant` 委托的(衰减后)能力。

```fish
spawn linter --grant src=($repo | sub src | readonly)
    $src read note.txt        # 只看得到 $src;看不到 $repo、无 sink、无法写
end

confine reader --grant v=$vault
    $v read secret.txt        # 合法:持敏感读、无外发 sink
end

confine leaky --grant v=$vault --grant net=$out
    $v read secret.txt | $net send   # ✗ 同区室既持敏感读又持外发 sink => 结构性拒绝
end
```

- `spawn` = 新 vat(可并发,eventual send 通信,对应 capvm 的独立 C-list 进程);`confine` = 同进程静态区室检查。
- **取舍**:capsh 用 `spawn "x" with { … } { … }`;capfish 用 `spawn x --grant k=v … ; … ; end`(fish 的
  `--flag` + `begin/end` 块风格)。语义等价,委托即传入衰减能力。

## 9. 信息流(taint / IFC,保留)

值带 taint(格 lattice);污点随数据流取上确界传播;`secret` 数据流入外发 sink 必须 `declassify`(需能力)。

```fish
set readme ($api get /README)     # Data<red, external>
set note "run: $readme"           # 拼接后仍 red
$vault read secret.txt | $out send    # ✗ Secret -> sink:ENOTCAPABLE
$vault read secret.txt | declassify $dcap | $out send   # declassify 需用户授予的能力
```

- 污点三色(green/yellow/red)+ 细粒度(secret/project/external/agent_generated),与 Broker 服务端判定一致
  (敏感路径读一律升 Secret,不信客户端自报)。

## 10. 控制流与函数(直接用 fish,基本不变)

```fish
function build --argument-names target
    if $repo list src | contains $target
        $repo read src/$target
    else
        echo "no such target: $target"
    end
end

for f in ($repo list src)
    echo processing $f
end
```

- `if/for/while/switch/function … end`、`and`/`or`/`not`、`$argv`、`(命令替换)` 全部沿用 fish。
- 唯一区别:命令位的名字**不经 `$PATH`**,只解析到作用域内的 Cap / CommandCap。

## 11. L5 JIT consent(运行期行为,保留)

高风险动词(`run`/`get`/`post` 等)按策略可要求**人类实时授权**:capfish 触发时打印
`需审批 <verb> on <cap>(id …)`,由控制面审批者 `consent approve <id>` 后重放放行(一次性、签名绑定副作用参数、
requester 看不到含凭据的详情 —— 全部已在 L5 实现)。这是运行期语义,不是语法。

---

## 12. 完整示例(把 capsh 的 hello + confine 用 capfish 重写)

```fish
# hello.capfish
set repo (grant dir "examples/workspace" {read,write})
$repo describe

set who "main"
set content ($repo read $who.ml)          # 指名即授权;$who 是单段,无法逃逸
echo $content

set src ($repo | sub src | readonly)      # 衰减:子目录 + 只读
$src read note.txt

set vault (grant dir "examples/workspace/src" {read,secret})
set key ($vault read secret.txt)          # Secret 污点

set out (grant sink "https://collector.example.com")
echo $content | $out send                 # project 数据可发
echo $key | $out send                     # ✗ Secret -> sink:ENOTCAPABLE,程序终止

# confine.capfish
spawn linter --grant src=($repo | sub src | readonly)
    $src read note.txt
end
confine leaky --grant v=$vault --grant net=$out
    $v read secret.txt | $net send        # ✗ 结构性拒绝
end
```

---

## 13. 取舍总表(capsh 功能 → capfish 呈现 → 说明)

| capsh 功能 | capfish 呈现 | 取舍/说明 |
|---|---|---|
| `let x = …` 单赋值 | `set x (…)` | 用 fish `set`;Cap 绑定规定只能变窄,无加宽 |
| Data/Cap 两宇宙 | 保留;管道传类型化+带污点值 | 不变量 2 保留 |
| Cap 不可伪造(OCaml abstract type) | Broker 句柄模型强制 | **编译期证明 → 运行期 + 结构封装**(同 Backend_rpc) |
| `.sub().readonly()` 方法链 | `$cap \| sub src \| readonly` 管道 | 等价;fish 无方法语法,管道最地道 |
| `grant dir "p" {read}` | 同(`grant` builtin) | 基本一致 |
| `path\`${x}\`` quasi | 依赖能力边界(RESOLVE_BENEATH)+ 可选 `path(...)` 校验 | 少一个显式语法记号,靠能力边界兜底 |
| `sh\`echo ${m}\`` quasi | `grant command echo $m`(fish 无 word-split + 无 shell) | 注入同样被杀,少显式记号 |
| taint / IFC | 管道传污点,sink 处 IFC | 完全保留 |
| `spawn/confine with {…}` | `spawn/confine --grant k=v … ; … ; end` | 等价,fish 块风格 |
| CommandCap(D9) | `grant command …`(固定 argv/cwd/无 shell/C1 沙箱) | 完全保留 |
| MessageCap | `grant mailbox` + `$m post/read` + `\| prefix` 衰减 | 完全保留 |
| capvm cap-indexed | 命令位 Cap 派发 = C-list 句柄语义 | 完全保留(loader 装入) |
| L5 consent | 运行期审批 + `consent approve <id>` | 完全保留 |
| `print(cap)` | `echo $cap` / `$cap describe`(打占位符) | 不可序列化保留 |

**净结论**:capsh 的**语义功能几乎全部保留**;主要取舍是 ① 不可伪造从"编译期类型证明"降为"Broker 句柄 + 运行期强制"
(换来动态 shell 手感),② quasi-literal 的**显式语法记号**被 fish 语义 + 能力边界替代(注入仍被杀,只是少了那个可见标记)。
两者都是"手感 vs 形式化程度"的权衡,不丢安全性。

---

## 14. 后端不变(复用已复审资产)

capfish 前端经 **CapTP-lite** 连同一个 Rust Broker,和现在的 OCaml capsh 完全一样:
能力注册表 / 会话绑定不可伪造 ref / DirCap openat2 / CommandCap C1 沙箱 / HttpCap SSRF / MessageCap /
L5 policy+consent / capvm C-list —— **全部原样复用,一行不改**。落地路径见
[capsh-on-fish-eval.md](capsh-on-fish-eval.md) §5–7(在 fish 的 6 个 choke 处做 trait 切口接 Broker)。
