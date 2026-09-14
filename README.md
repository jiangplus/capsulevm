# Capable

**Capable** 是一个基于 Object Capability（OCap）安全模型的 VM 运行环境，以及一个 capability-native 的交互 shell（`capsh`，对标设计文档中的 capshell）。

它的一句话定位：

> 把 agentos / secure-exec 已经做好的「V8 isolate 微型 VM + kernel 全中介 + deny-by-default」执行基座，升级为一个**真正的 Model 4 对象能力运行时**——没有 capability 就没有资源，指名即授权，权限可衰减、可委托、可撤销、可审计，敏感读与任意外发之间有结构性 confinement。

## 为什么不是「增强 agentos」

agentos / secure-exec 的隔离基座非常好（进程内 V8 隔离、每个 guest syscall 都经 kernel、6 scope deny-by-default 权限、sidecar 作为唯一 TCB），但它的权限模型本质是**对命名 scope 的策略/ACL（≈Model 1.5–2）**：权限仍以「路径字符串 / host 模式」为参数，不是不可伪造的对象引用，没有衰减委托链、没有 forwarder 撤销、没有 taint 信息流、没有 prepare/commit。

Capable 保留 agentos 的隔离基座，替换它的权限语义层：把「带路径参数的 syscall + scope 策略」换成「cap-indexed syscall + Capability Broker」。

## 文档

- [DESIGN.md](./DESIGN.md) — 具体设计方案（主交付物）
- [CHANGELOG.md](./CHANGELOG.md) — 开发变更记录
- `docs/` — 后续拆分的分册设计（syscall ABI、capsh 语言规范、cap 类型目录等）

## 设计依据

- `/home/ubuntu/capo/design/secure-agent-harness-report.md` — 16 条不变量、6 层参考架构、M0–M4 路线图、D1–D15 决策
- `/home/ubuntu/capo/design/ocap-shell-vm-design.md` — capability-native shell / VM syscall 设计
- `/home/ubuntu/capo/design/ocap-security-model-evaluation-framework.md` — 红线门禁 + 量化评分 + 红队用例
- `/home/ubuntu/capo/agentos/overview.md`（及 `secure-exec/overview.md`）— 复用的 VM 执行基座

状态：**设计阶段（pre-alpha）**。尚无实现代码。
