# v4 开发与本地验证记录

日期：2026-09-29。依据：工作区根目录 `13_v4开发计划与验收标准.md`。

**状态：v4 功能开发版；不标为“完整 v4 已验收”，也不标为“v4 核心阶段完成”。** 原计划要求真实动态阻断、目标机、全部 P1、成本分解、公平对照和一小时稳定性；当前仍有缺口。构建和已执行的本地检查均有原始证据，未执行项单列。

## 1. 复制与冻结

`ebpf-monitor-v4/` 从 v3 复制。排除 `.git`、旧 build、out 和顶层缓存；保留源码、规则、文档和历史结果。旧源码摘要、配置、依赖文件、构建及输出文件摘要在 `V3_BASELINE_SHA256.json`，最终复核在本轮 `source-sha256.json`。继承的历史结果仍是 v3 结果，不能计入 v4。

实际本地内核是 WSL Ubuntu 24.04、6.6.87.2-microsoft-standard-WSL2，x86-64。BTF、clang、libbpf 和实际 bpftool 可用，BPF 审计程序已真实加载。固定依赖声明沿用 PyYAML==6.0.2；实际 WSL 安装版本为6.0.1，已如实冻结；尚未在6.0.2独立环境重验，不能仅凭 requirements 文件宣称依赖已匹配。

在私有挂载命名空间读取 securityfs，活动 LSM 列表为 `capability,landlock,yama,safesetid,selinux`，没有 bpf。CONFIG_BPF_LSM=y 不能替代活动检查。没有修改启动配置；真实动态验收返回 77/unavailable。该 WSL 不是 config/target.json 中的 VMware Ubuntu 6.8 目标机。

## 2. 按计划的实现状态

| 任务 | 当前状态 | 具体实现与验收边界 |
|---|---|---|
| V4-001、002、004、005 | 本地通过 | v3 文件摘要、独立目录、实验合同、同机 v3 测试和五轮基线；目标 VMware 复现另计 |
| V4-003 | 本地核验；目标机待验 | WSL BTF、挂点、编译和加载已验证；活动 LSM 不含 bpf；本地与 Windows 挂载输出分别测量 |
| V4-101 | 本地通过 | JSON schema 2，独立控制版本 1，规则版本独立；旧 v3 适配及非法版本拒绝；事件/告警/证据/请求/生命周期 schema |
| V4-102、104 | 本地通过；目标机待验 | 内核 fork/exec 令牌、TGID＋启动身份，exec 清旧策略；事件/入口/接收/判定/提交时间；身份启动时钟与事件时钟分开 |
| V4-103 | 本地通过 | 必需阶段、字段错误、身份未知、迟到、缺证据和丢失区间禁止处置；分类状态，不用概率分数 |
| V4-105 | 部分本地通过 | 线程 exec、快速退出、祖先 exec/缓存、不同启动身份、会话与快照覆盖；强制模式下实际 PID 复用及 namespace 全矩阵未验 |
| V4-201—204 | 本地通过 | R04 前置与 C01 后续分开；历史来源、服务原始事件、shell 窗口、对象/结果；正常/失败/例外测试；四部分 HTML 报告 |
| V4-301—304 | 限定范围本地通过 | x86 mmap 入口＋内核 file 对象＋出口；配置/打开/成功映射/后续行为分别显示；失败或未知不能声称映射成功 |
| V4-305 | 部分本地通过 | 硬/符号链接、相对打开、FD 复用、多线程已实测；任意库路径变更、无环境变量加载和其他架构不在声明范围 |
| V4-306 | 本地通过；范围有限 | 自建子进程 ptrace 写成功、非存在目标失败、读请求对照、精确 exe＋UID＋规则例外；不是所有注入检测 |
| V4-401、402 | 代码及模拟 map 本地通过 | 受限 seqpacket、对端 PID/UID、数字/范围/版本、幂等、QUERY/REVOKE、固定对象、TTL、容量、独立 map；模拟测试不算真实 LSM 验收 |
| V4-403 | 本地通过 | 三轮真实 shadow：前置证据满足即记录请求参数，后续打开继续成功，无真实拒绝 |
| V4-404—407 | 已接线；真实验收受阻/未完成 | file_open 校验令牌、UID、cgroup、对象和 TTL；记录 map 应用区间、拒绝、撤销/到期；验收脚本含零间隔初始操作、确认后操作、既有 fd、TTL 和非匹配实例；实际强制与完整故障矩阵未执行 |
| V4-501、504、505 | 部分本地通过 | 同合同五轮 B0/B3、解码/规则/存储/流水线诊断；500 条或250 ms事务提交；仅存储过滤与真实输入等价；完整内核/编码/传输/策略阶段分解未完成 |
| V4-502、503 | 部分实现 | 已声明每条规则必需证据，保留全部身份/生命周期分析；rule_related 只减少落盘，尚未实现并验收内核规则相关过滤/状态驱动增强 |
| V4-506 | 部分本地通过 | 暂停造成可观测过载、恢复及退出；1000 次打开/秒、10 秒烟测；不能当作一小时稳定性完成 |
| V4-601—606 | 未完成完整交付 | 已有统一验收入口、环境/源码/原始事件/数据库/报告和缺口清单；Falco/Tracee/Tetragon 等价实测、v4 消融和干净目标机复现未执行 |

接口的精确范围和限制见 `PROTOCOL_V4.md`，不将上述“本地通过”提升为目标机或全计划通过。

## 3. 本地证据索引

本轮根目录：`experiments/results/v4-wsl-2026-09-29/`。

| 检查 | 原始结果 | 已观察结果 |
|---|---|---|
| v3 基线 | `v3-baseline-tests.log`、`baseline-v3/result.json` | 60 项测试，五轮 B0/B3 |
| v4 编译与回归 | `build.log`、`build-final.log`、`tests-final.log`、统一验收的 `unit.log` | clang BPF、C -Werror 编译；最终77项Linux测试通过；统一验收快照为此前75项 |
| 普通用户场景 A/B | `mapping-integration/result.json` | UID 1000 三轮；六条规则各三次；正常对照 0 告警；三个成功映射阶段链 |
| 质量降级 | `mapping-final/alerts.db`、`mapping-final/report.html` | 原 execl 样例 shell 入口 path/argv 读取失败；R04 处置资格拒绝，历史错误不抹去 |
| 可处置前置与 shadow | `acceptance-localfs/shadow/result.json`、`alerts.db`、`report.html` | 使用栈上可读取的 exec 参数样例；三轮符合身份/质量门槛，记录三个 shadow 请求；没有 sleep 保证初始敏感操作等待策略 |
| 身份/对象边界 | `acceptance-localfs/edges/result.json` | execveat、线程组 exec 令牌换代、快速失败、ptrace 自建目标、链接、相对路径、UTF-8、线程/进程退出 |
| 映射边界 | `acceptance-localfs/mapping/result.json` | 成功与失败 mmap、直接文件对象、硬/符号链接、FD 复用对象区分、非主线程同一 exec token、零意外丢失 |
| 控制处理 | `unit.log` 中 test_control/test_v4 | 真实 C 处理器＋模拟 BPF maps；幂等/冲突、过期重放、撤销、身份错误、对象替换、数字溢出、超时 QUERY；不是实际拒绝证据 |
| 丢失与恢复 | `recovery/result.json`、`acceptance-localfs/recovery/result.json` | 故意暂停分析器，保留 queue_lost 和恢复事件；故意过载不要求零丢失 |
| 退出预算 | `shutdown/result.json`、`shutdown-batched/result.json`、`shutdown-localfs/result.json` | Windows v9fs 的10k积压在5s预算失败；Linux本地同门槛通过；正常Ctrl+C与ACK超时对照均保留 |
| 存储等价 | `equivalence.json`（首次失败）、`equivalence-final.json`、统一验收 `equivalence.json` | 首次跳过分析更新改变来源；修正后全部更新照常，仅减少落盘；同输入告警、证据和质量相同；134条→82条的早期样本不代表全局收益 |
| 短时持续输入 | `stability-smoke/result.json`、统一验收 `stability/result.json` | 请求1000次打开/秒、10秒，10000次全部保存；不宣称一小时稳定 |
| 实际响应 | `response-acceptance/result.json`、统一验收 `enforce/result.json` | unavailable、passed=false；活动 LSM 无 bpf，不计算任何真实阻断率 |
| 源码与保留基线 | `source-sha256.json` | 源码/构建摘要、实际依赖、环境、v3 摘要逐项复核 |

`acceptance-final/` 是 Windows 挂载输出的一次失败总验收，恢复健康记录未在15秒内落盘；后续 `acceptance-localfs/` 改为 Linux 临时本地存储执行后归档，未覆盖或删掉失败记录。不能将两种文件系统的耗时直接归为纯代码优化。

## 4. 性能与未达标结果

冻结合同 `EXPERIMENT_CONTRACT.json`：2000 次打开、20 次 exec，预热后五轮，各版本内部交替 B0/B3。打开对象为 Linux 临时文件；五轮微基准输出落在工作区 Windows v9fs。版本顺序未随机交替，内核/后台负载/启动状态及尾部落盘均有影响；只分别报告各组，不从中宣称 v4 比 v3 快。

| 版本与采集组 | B0耗时中位数 | B3耗时中位数 | 耗时增加 | 固定工作量吞吐下降 |
|---|---:|---:|---:|---:|
| 本机重跑 v3 | 0.052354 s | 0.072691 s | 38.845% | 27.977% |
| v4 批量存储测量快照 | 0.055490 s | 0.071690 s | 29.194% | 22.597% |

这不是代表性业务、VMware 或新增映射的成本结论。完整审计微基准的下降显著高于5%，没有达到“低开销目标完成”。每次测量对应 result.json 内的源码摘要；其后增加了跨会话响应索引和控制终态/健康计数修正，新增处置路径成本未实测。逐轮CPU、RSS采样、2000条目标事件保存和排空记录在对应 result.json，RSS不是峰值，用户态CPU不是整机/内核总成本。

3,332条真实尾部样本的诊断：decode约0.046s、engine约0.033s、storage约2.305s、pipeline约2.554s。这些独立运行阶段不能相加或用差值做精准归因；样本来自轮转日志尾部，不是全部10k积压。

事务默认500条或250ms到下次事件时提交，闲时与退出仍强制提交；requested在实际发送前单独提交。它扩大未提交事件的上限，不能宣称异常断电一定保留全部内存/未提交日志。排空只有收到最终COMMITTED才通过。

Windows输出的两轮5s退出失败均完整持久化了monitor_stop，但ACK超时仍算失败。不能因为数据最后保存了就改成passed。Linux本地复验约3.06s通过，是存储环境差异，不算每事件代码成本降低的证据。

## 5. 复现与剩余门槛

```bash
bash scripts/build.sh -j2
python3 scripts/acceptance_v4.py --native-data --stability-seconds 10 --out out/v4-local-acceptance
# 下列仅在已经配置好的活动BPF LSM专用环境运行，不调整启动配置
python3 scripts/verify_response.py --out out/v4-response
# 正式稳定性；本次没有运行这一小时测试
python3 scripts/stability.py --seconds 3600 --opens-per-second 1000 --out out/v4-stability
```

统一本地验收明确分开 local_functional_verified、enforcement_verified 和 full_v4_plan_verified。即使本地功能通过，full_v4_plan_verified仍为false，不能自动提升为正式发布。

下一阶段须获得具备活动BPF LSM的目标Linux实验环境：先核验线程组/namespace/快速复用，再执行真实策略生效后拒绝、非匹配/例外放行、TTL、exec/退出、满容量、ACK丢失/重启和对象替换全矩阵，保存无sleep初始操作的逃过率。随后补内核规则相关过滤及等价性、完整阶段成本、代表性业务、一小时负载、v4消融、公平竞品对照与干净部署复现。上述任务仍未完成。
