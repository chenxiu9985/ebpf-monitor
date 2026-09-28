# v3 开发记录：分析开销与可靠退出

日期：2026-09-26。软件版本：`0.3.0`，目录版本名为 v3；事件 schema 仍为 1，新增可选确认字段。本轮从完整 v2 副本开始，落实上次审查优先级最高的分析开销、带积压退出及验证工具。

## 1. 复制与开发范围

- 原目录 `ebpf-monitor-v2` 保留。完整复制源码、配置、构建产物和历史实验到 `ebpf-monitor-v3`，再仅修改 v3。
- [复制基线][baseline]记录 83 个源码、文档及精简证据文件的 SHA-256；开发后重新核对，v2 这些文件均未改变。基线未包含 build、out 和 Python 缓存。
- 复制过来的旧实验不能作为 v3 新验证。当前结果位于 [v3 精简归档][review]，完整事件、数据库及源码快照位于 [v3 原始结果目录][raw]。
- 本轮未修改 eBPF 内核探针或六条规则的匹配条件；没有新增提权、Rootkit、容器逃逸、共享库加载证明或序列阻断能力。

## 2. 已实现的改动

### 2.1 分析器不再对每条事件扫描所有进程

v2 的 `Engine.process()` 每次都遍历整个进程缓存，检查已经退出的进程是否过期。大量文件打开来自少数进程时，这项工作仍然重复执行。

v3 使用按退出时间排序的堆，只处理到期退出记录。保留原来的事件时间和严格过期边界；配置重载后使用新的保留时长；缓存淘汰后残留的堆项不能误删重新建立的进程对象。堆超过有界阈值后压缩，避免旧项无限积累。实现见 [engine.py][engine]，边界验证见 [test_expiry.py][expiry-tests]。

本轮没有将已有的“每 100 个事件提交一次 SQLite 事务”重复当作新功能。固定负载实测支持先修复进程缓存扫描；后续真实主机仍可能受磁盘、日志序列化或其他关联状态维护限制。

### 2.2 采集器与分析器建立退出确认

v2 停止时只做有限次发送，可能留下未发送消息；即使队列为空，也只能说明数据交给了套接字，不能证明分析器处理和提交完成。

v3 的 socket 退出顺序为：

1. 停止捕获并拆卸本次探针。
2. 启动一个总排空预算，先排已有发送队列，再消费剩余 ring 事件。此阶段遇到背压会等待，而不是沿用运行期队列满即丢弃的行为。
3. 发送带 `shutdown_ack_required=true` 的 `monitor_stop`，然后半关闭发送方向。
4. 分析器收到完整 EOF，校验没有截断帧，完成重排队列处理、SQLite 提交及 JSONL flush/close。
5. 分析器返回包含该 stop 事件唯一 ID 的 `COMMITTED` 确认。采集器只接受匹配确认；确认错误、缺失、对端退出或预算耗尽均返回非零。

实现见 [transport.h][transport]、[采集器][collector]和[分析器入口][main]。传输模块可独立编译测试，无需加载 BPF。

`--drain-timeout-ms` 默认 10000，范围 1–60000，预算从拆卸探针之后开始，覆盖 socket 排空与确认。实际从按 Ctrl+C 到退出的时间还包括探针拆卸和进程调度。stdout JSONL 模式检查输出刷新错误，不使用这个 socket 确认协议。

**确认只证明本次连接中已收到的完整事件完成处理与提交，不补回运行期间已经丢弃的数据，也不承诺断电下 SQLite 和多个日志文件之间的原子一致性。** 实际磁盘 flush/提交失败时不会返回成功确认。

### 2.3 监督启动与一次 Ctrl+C

[run.sh][run]交给[监督启动器][supervisor]统一管理。分析器使用独立会话；采集器保留认证时的终端会话，但使用独立进程组，终端 Ctrl+C 先到监督启动器，由其通知采集器停止；分析器保持运行直到处理完 EOF，随后自行退出。异常路径有有限等待和失败记录。

默认每次创建新目录 `out/live-v3/<时间-PID>/`，避免不同运行混用数据库。健康消息保存在 `collector.log`，分析统计保存在 `analyzer.log`；终端打印实际目录及最终结果。普通用户启动时仅采集器通过 sudo 运行，分析器保持调用用户身份；本轮真实内核验证是在本地 WSL root 测试上下文中执行的，目标 VM 普通用户 sudo 启动仍须复验。

`session.json` 的两个结论分开解释：

| 字段 | 含义 |
|---|---|
| `passed` | 本次启动、退出和提交确认成功 |
| `capture_loss_free` | 在前项成功的基础上，相关采集/传输质量计数均为 0 |
| `shutdown_acknowledged` | 收到匹配本次 stop ID 的提交确认 |
| `shutdown_unsent` | 最终发送队列残留数量；独立为 0 不代表退出成功 |
| `shutdown_error` | 排空/确认错误码，0 为无此类错误 |
| `shutdown_queue_lost` | 退出汇总中的会话累计队列丢失，不是仅退出阶段的丢失 |

v3 socket 采集器必须与 v3 分析器配套；v2 分析器不支持确认，混用会超时失败。

### 2.4 证据质量和验证入口

- 新增发送断线计数 `transport_disconnects`。分析器收到该计数或 `unpaired` 增长后清空序列状态，与已有 ring/map/queue 丢失处理一致。这是保守的证据质量处理，没有修复 v2 那次 `unpaired=1` 的未知根因。
- 集成测试检查两端退出状态，过载恢复测试同时检查残留和确认，避免只看曾经产生过事件就判通过。
- [analysis_benchmark.py][analysis-bench]比较解码、规则引擎、存储和完整分析管线；默认合成数据，也可指定 JSONL 和规则进行离线诊断。
- [verify_shutdown.py][shutdown-script]验证真实内核积压恢复、确认超时和一次终端进程组 Ctrl+C。
- [load_sweep.py][sweep-script]按固定速率产生无害文件打开，逐项核对发起量、保存量、丢失计数和退出确认。

## 3. 最终验证结果

环境为本地 Ubuntu 24.04 / WSL2、Linux `6.6.87.2-microsoft-standard-WSL2`、Python 3.12.3、libbpf 1.3.0。测试数据库和负载位于 Linux 临时目录，源码/构建位于 Windows 工作区映射；每项结束后立即复制归档。该环境与用户的 VMware 6.8、3.8 GiB 环境不同。

本轮归档前曾发现旧临时结果目录不可用，因此以下结论采用集中复跑并即时归档的最终结果，早先聊天中的耗时仅作为过程观察。

| 项目 | 最终结果 | 边界 |
|---|---|---|
| Linux 自动回归 | **57 项全通过，无跳过** | 包括原有规则、重载，以及新增过期、C 传输背压、错误/缺失确认、对端断开、截断帧、日志写失败测试；见 [unit.log][unit-log] |
| UID1000 真实内核集成 | 5 轮，六规则各覆盖 5 个工作进程，例外样例告警 0；P95 **254.81 ms** | 受控组合场景，不能估计真实攻击检出率；见 [integration.json][integration-result] |
| 内核边界 | 12 项全部通过，ring/map/queue/unpaired/发送断线为 0 | WSL 当前内核的固定边界；见 [edges.json][edges-result] |
| 带积压退出 | 暂停分析器并产生 10000 次打开，停止后恢复；最终残留 0、确认成功、stop 事件已提交 | 暂停期间已丢 8885 条队列消息，退出成功不能抹去这些丢失；见 [shutdown.json][shutdown-result] |
| 确认超时 | 队列即使为空，仍因未收到确认以错误 -110、退出码 1 结束 | 这个负例“通过”指正确报告失败 |
| 一次终端 Ctrl+C | 监督启动器、采集器和分析器正常结束，确认成功、残留 0 | 模拟发送给前台进程组的 SIGINT，非仅给单个采集器发信号 |
| 过载恢复 | 恢复采集可见，最终确认成功、队列清空 | 人为暂停时累计队列丢失 18744 条；见 [recovery.json][recovery-result] |

### 3.1 完整链路的短时受控速率

每个速率持续 3 秒，保持分析器正常消费；比较专用测试文件的发起次数与数据库实际保存次数。三组均正常确认退出，ring/map/queue/unpaired/发送断线计数均为 0。

| 目标打开速率 | 发起次数 | 保存次数 | 结果 |
|---:|---:|---:|---|
| 500 次/秒 | 1500 | 1500 | 通过 |
| 2000 次/秒 | 6000 | 6000 | 通过 |
| 5000 次/秒 | 15000 | 15000 | 通过 |

证据：[load-sweep.json][sweep-result]。这说明该 WSL 环境中这些短时负载完整保存，不证明 5000 次/秒是最大容量，也不证明一小时运行、任意进程数量或目标 VMware 同样无丢失。

### 3.2 v2 与 v3 同输入分析对照

默认合成集含 1500 个进程、20000 次普通文件打开和 7 条关联验证事件，共 21507 条；各三轮，输出位于同类 Linux 临时文件系统。

| 阶段（中位耗时） | v2 | v3 |
|---|---:|---:|
| 帧/JSON 解码 | 0.04749 s | 0.04923 s |
| 完整规则引擎，含进程缓存建立 | 1.66143 s | 0.04186 s |
| SQLite 事件存储与最终提交 | 0.38326 s | 0.36263 s |
| 完整离线分析：校验、重排、规则、JSONL、SQLite、最终刷新 | **2.34455 s** | **0.58843 s** |

两版输入摘要和配置完全相同，三轮各生成 6 条告警，完整告警内容的摘要也相同，见 [analysis-comparison.json][comparison]。性能改善主要体现在规则引擎，符合去除逐事件进程缓存全遍历的预期。

这是顺序运行的诊断比较，各阶段不是可加的部件成本；合成集也没有覆盖所有真实负载。不能将约 0.59 秒解释成实时告警延迟，不能据此宣布整套系统低于 5% 开销。新测量不与 v2 的 VMware B0/B1 微基准直接混算。

## 4. 在目标 VMware 上使用 v3

将 v3 整个目录复制到独立的 `~/ebpf-monitor-v3` 后，以普通用户进入该目录执行：

```bash
bash scripts/build.sh -B
python3 -m unittest discover -s tests -v
bash scripts/run.sh
```

必须在目标机重建，不使用从 Windows/WSL 复制过去的已有二进制。正常运行后按一次 Ctrl+C 并等待结束，检查终端显示的结果目录内 `session.json`。这个默认入口不会启用 LSM 阻断。

随后依次运行专项验证，每次使用新的输出目录：

```bash
sudo python3 scripts/verify_shutdown.py --out out/target-v3-shutdown-01
sudo python3 scripts/load_sweep.py --out out/target-v3-load-01 --rates 500,2000,5000 --seconds 3
sudo python3 scripts/integration.py --out out/target-v3-integration-01 --repetitions 30 --uid 1000
```

前两个脚本包含短时受控压力/暂停场景；故意暂停阶段出现队列丢失是预期观察，不能只看脚本 `passed` 就认定全过程零丢失。已有目录不会被覆盖。

## 5. 剩余工作

| 待办 | 当前状态 |
|---|---|
| VMware 的 v3 受控负载、普通用户 sudo 启动、带积压退出 | 尚未执行，必须独立复验 |
| 完整链路稳定容量、CPU/RSS、磁盘与真实应用开销 | 增加了诊断入口和短时速率样例，尚未完成完整 B0–B3/业务实验 |
| v2 原始 `unpaired=1` 根因 | 未证实；本轮样例为 0 不等于已找到并修复原问题 |
| 一小时稳定性、真实磁盘空间耗尽、异常杀进程 | 尚未完整验收；`/dev/full` 测试只验证日志 flush 失败不会伪造确认 |
| LD_PRELOAD 无害加载/符号覆盖证据、普通 bash 临时程序场景 | 保留为下一功能工作包 |
| 专门提权/Rootkit/容器逃逸规则、LSM 实际拒绝、序列自动联动 | 未在本轮实现或完成验收 |

本轮的准确状态是：**v3 第一工作包已开发并通过本地针对性验证，目标 VMware 复验和后续功能扩展仍待执行。**

## 6. 文件与归档说明

实现重点：进程过期处理、传输模块、分析器 EOF 确认、监督启动器。新增测试直接检查真实 C 传输与 Python 分析器之间的状态、数据库提交、日志错误和退出结果，未靠文本匹配源码来证明行为。

[source-sha256.json][hashes]记录最终源码及二进制摘要；[原始结果目录][raw]同时保存对应源码快照、事件、数据库和日志。性能阶段的临时数据库不保留，保留完整逐轮 JSON、输入摘要、参数及告警摘要，可用脚本重新生成。本轮未将针对性验证包装成包含 LSM、竞品及一小时工作负载的完整 acceptance。

[baseline]: D:/work/研究生/演武堂/基于eBPF的Linux内核攻击监控方案/ebpf-monitor-v3/docs/V2_BASELINE_SHA256.json
[review]: D:/work/研究生/演武堂/基于eBPF的Linux内核攻击监控方案/ebpf-monitor-v3/experiments/results/v3-wsl-2026-09-26/review.json
[raw]: D:/work/研究生/演武堂/基于eBPF的Linux内核攻击监控方案/ebpf-monitor-v3/out/v3-wsl-20260926
[engine]: D:/work/研究生/演武堂/基于eBPF的Linux内核攻击监控方案/ebpf-monitor-v3/monitor/engine.py
[expiry-tests]: D:/work/研究生/演武堂/基于eBPF的Linux内核攻击监控方案/ebpf-monitor-v3/tests/test_expiry.py
[transport]: D:/work/研究生/演武堂/基于eBPF的Linux内核攻击监控方案/ebpf-monitor-v3/collector/transport.h
[collector]: D:/work/研究生/演武堂/基于eBPF的Linux内核攻击监控方案/ebpf-monitor-v3/collector/main.c
[main]: D:/work/研究生/演武堂/基于eBPF的Linux内核攻击监控方案/ebpf-monitor-v3/monitor/__main__.py
[run]: D:/work/研究生/演武堂/基于eBPF的Linux内核攻击监控方案/ebpf-monitor-v3/scripts/run.sh
[supervisor]: D:/work/研究生/演武堂/基于eBPF的Linux内核攻击监控方案/ebpf-monitor-v3/scripts/run_live.py
[analysis-bench]: D:/work/研究生/演武堂/基于eBPF的Linux内核攻击监控方案/ebpf-monitor-v3/scripts/analysis_benchmark.py
[shutdown-script]: D:/work/研究生/演武堂/基于eBPF的Linux内核攻击监控方案/ebpf-monitor-v3/scripts/verify_shutdown.py
[sweep-script]: D:/work/研究生/演武堂/基于eBPF的Linux内核攻击监控方案/ebpf-monitor-v3/scripts/load_sweep.py
[unit-log]: D:/work/研究生/演武堂/基于eBPF的Linux内核攻击监控方案/ebpf-monitor-v3/experiments/results/v3-wsl-2026-09-26/unit.log
[integration-result]: D:/work/研究生/演武堂/基于eBPF的Linux内核攻击监控方案/ebpf-monitor-v3/experiments/results/v3-wsl-2026-09-26/integration.json
[edges-result]: D:/work/研究生/演武堂/基于eBPF的Linux内核攻击监控方案/ebpf-monitor-v3/experiments/results/v3-wsl-2026-09-26/edges.json
[shutdown-result]: D:/work/研究生/演武堂/基于eBPF的Linux内核攻击监控方案/ebpf-monitor-v3/experiments/results/v3-wsl-2026-09-26/shutdown.json
[recovery-result]: D:/work/研究生/演武堂/基于eBPF的Linux内核攻击监控方案/ebpf-monitor-v3/experiments/results/v3-wsl-2026-09-26/recovery.json
[sweep-result]: D:/work/研究生/演武堂/基于eBPF的Linux内核攻击监控方案/ebpf-monitor-v3/experiments/results/v3-wsl-2026-09-26/load-sweep.json
[comparison]: D:/work/研究生/演武堂/基于eBPF的Linux内核攻击监控方案/ebpf-monitor-v3/experiments/results/v3-wsl-2026-09-26/analysis-comparison.json
[hashes]: D:/work/研究生/演武堂/基于eBPF的Linux内核攻击监控方案/ebpf-monitor-v3/experiments/results/v3-wsl-2026-09-26/source-sha256.json

## 7. VMware 普通用户启动修复（2026-09-26）

用户回传：目标机重新编译成功、原 57 项测试通过；普通用户实时启动的 collector.log 为 `sudo: a password is required`，分析器处理事件为 0。这次失败发生在 sudo 阶段，尚不能说明 BPF 加载失败。环境检查使用 `sudo bash scripts/target_check.sh` 可正常读取 tracefs；活动 LSM 不含 bpf，默认审计模式不要求启用 BPF LSM。

修复 scripts/run_live.py：采集器 Popen 从 start_new_session=True 改为 process_group=0。保留 sudo -v 所在会话以复用默认终端认证缓存，同时让采集器离开前台进程组，维持监督启动器处理 Ctrl+C 的顺序。需要 Python 3.11+，目标 Ubuntu 24.04 的 Python 3.12 满足要求。不修改 sudoers 或密码策略。

新增 test_supervisor.py 实际启动子进程，核对会话继承和进程组隔离。此前 source-sha256.json 和源码快照对应修复前版本，保留为历史证据；本次测试日志另存 experiments/results/v3-sudo-session-tests.log。目标机的密码认证与 Ctrl+C 仍需用户复验，不能以 root WSL 测试替代。

修复后本地 WSL 的 58 项测试全部通过；真实内核积压恢复、确认超时负例和前台进程组 Ctrl+C 三项退出测试通过，结果保存于 out/v3-sudo-session-shutdown-01。sudo 终端缓存机制参考 https://github.com/sudo-project/sudo/blob/main/docs/sudoers.man.in ，进程组参数参考 https://docs.python.org/3/library/subprocess.html 。
