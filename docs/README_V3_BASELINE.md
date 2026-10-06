# eBPF Linux 攻击行为监控原型 · v3

v3 从 v2 完整复制后独立开发。本轮优化分析器进程缓存过期处理，并实现“停止采集 → 排空 → 分析落盘确认”的退出流程。版本差异、验证结果和待办见 [v3 开发记录](docs/V3_DEVELOPMENT.md)。复制来的旧 `out/` 和历史实验仍是 v1/v2 证据；本轮结果单独存放在 `experiments/results/v3-wsl-2026-09-26/`。

本项目实现内核事件采集、四类基础规则、两条进程关联规则、证据存储与 HTML 报告，并提供限定范围的 BPF LSM 策略。它是研究原型，不是已通过生产验收的安全产品。

## 目标环境

| 项目 | 用户提供的验收环境 |
|---|---|
| 虚拟化 | VMware |
| 系统 | Ubuntu Server 24.04.3 |
| 内核 | 6.8.0-136-generic，x86_64 |
| 内存 | 3.8 GiB |
| 用户 | chenxiu，UID=1000 |
| 已有 BCC | 0.29.1+ds-1ubuntu7 |

本项目正式采集器使用 **libbpf/CO-RE**，无需替换已有 BCC。历史本地内核测试使用 WSL 6.6；现已复核目标 VMware 6.8 的 30 轮检测、12 项边界和过载恢复结果。初始 VM P95 245.39 ms、吞吐下降 32.49%；后续批处理优化的同二进制对照为 32.56% → 15.24%，回归 P95 240.01 ms，详见 `docs/PERFORMANCE_01.md`。活动 BPF LSM 尚未启用。任务状态见 `docs/PROGRESS.md`，目标机证据见 `docs/VERIFICATION_VM_01.md`。

## 1. 在 Ubuntu 安装依赖并构建

将整个 `ebpf-monitor` 目录复制到虚拟机。建议在虚拟机本地 ext4 文件系统运行；共享目录的同步写入延迟会影响性能实验。

```bash
sudo apt-get update
sudo apt-get install -y build-essential clang llvm libbpf-dev libelf-dev \
  zlib1g-dev pkg-config linux-tools-common linux-tools-generic python3-yaml
cd ebpf-monitor
sudo bash scripts/target_check.sh
bash scripts/build.sh
python3 -m unittest discover -s tests -v
```

脚本优先使用能工作的 bpftool，再查找发行版 linux-tools 目录。`vmlinux.h` 从运行机器的 BTF 生成；clang、libbpf、bpftool 的实际版本应随实验记录，不使用 Windows 生成的目标内核头文件。

## 2. 先运行自动化真实采集验收

完整顺序验收入口如下，会依次执行环境检查、构建、单元测试、30 轮集成、边界、过载恢复、五轮微基准和 LSM 测试，保存阶段日志、源码摘要和 `summary.json`：

```bash
sudo python3 scripts/acceptance.py --out out/vm-acceptance-01 --uid 1000
```

LSM 不可用、任一步失败或性能目标未达标，整体返回非零；不因此跳过其他可执行实验。此入口尚不包含竞品对照和一小时正常负载，不能代表全部研究计划验收。以下命令可单独复验某个阶段：

```bash
sudo python3 scripts/integration.py \
  --out out/target-integration-01 --repetitions 30 --uid 1000
sudo python3 scripts/live_edges.py --out out/target-edges-01
```

每次使用新的输出目录，避免旧结果混入。集成脚本生成无害临时文件、共享库和进程，启动真实 eBPF 采集，检查 R01—R04、C01—C02，以及正常例外。ptrace 边界脚本只修改自身创建的子进程中的测试整数，不操作其他进程。

`result.json` 表示实际执行结果；`collector.log`、`events.jsonl`、`alerts.db`、`report.html` 保存可检查证据。用例未通过会返回非零状态。

## 3. 启动持续观察

以普通用户 chenxiu 执行，脚本仅对采集器使用 sudo：

```bash
bash scripts/run.sh
```

按一次 Ctrl+C 后等待退出。监督启动器隔离两个子进程的终端信号，先通知采集器停止，分析器继续处理直到完成落盘确认。原始日志、告警、数据库及 `session.json` 默认写入新目录 `out/live-v3/<时间-PID>/`；终端显示实际路径，健康统计写入该目录的 `collector.log`。也可用 `bash scripts/run.sh --out out/my-v3-run` 指定一个不存在的新目录。脚本自动传入分析器 PID，防止采集自身写日志的行为形成反馈。

普通用户启动时仅采集器使用 sudo，分析器保持原用户身份。`--drain-timeout-ms` 默认 10000，可设 1–60000；这个预算用于拆卸探针后的传输排空与确认，不包含探针拆卸本身。超时、错误确认或对端退出均返回非零状态。`session.json` 的 `passed` 表示启动/退出与确认成功，`capture_loss_free` 另判断是否出现捕获/传输质量问题，二者不能混用。v3 socket 采集器须配套 v3 分析器。

规则位于 `rules/default.yaml`。R01 记录敏感对象异常打开，R02 记录 ptrace 写内存请求，R03 记录 preload 风险，R04 记录服务后代的临时目录执行。C01 关联执行链与敏感访问，C02 关联同一执行映像的 preload 风险与敏感访问。

默认没有“root 自动放行”。真实主机可能需要为认证、调试和运维程序配置精确例外。仅按 comm 放行不被支持。临时目录匹配是路径风险线索，首版不证明该目录对具体主体实际可写。

## 4. 查询、回放与报告

```bash
python3 -m monitor query --db out/my-v3-run/alerts.db --rule C01
python3 -m monitor report --db out/my-v3-run/alerts.db --output out/my-v3-run/report.html
python3 -m monitor replay out/my-v3-run/events.jsonl \
  --db out/replay.db --rules rules/default.yaml --alerts out/replay-alerts.jsonl
```

日志轮转后，应按旧到新顺序合并轮转文件再回放。实时与回放使用同一规则引擎；回放不把处理耗时当成实时检测延迟。规则改变后使用新的数据库，避免将不同实验混合。

Windows 可直接执行 `python -m monitor demo --out out/demo` 和单元测试；demo 明确标记为合成数据，不能用它证明 eBPF 在 Linux 加载成功。默认配置和 JSON 配置仅需标准库，YAML 文件另需 requirements.txt 中的 PyYAML。

## 5. 限定范围阻断验收

```bash
sudo cat /sys/kernel/security/lsm
sudo python3 scripts/verify_lsm.py --out out/target-lsm-01 --uid 1000
```

活动列表必须包含 `bpf`。只有 CONFIG_BPF_LSM=y 不足以证明已启用；采集器在无法确认活动 BPF LSM 时拒绝启动阻断模式。若文件不存在，还需检查 securityfs 是否可见。脚本不自动修改 GRUB、不重启系统。

测试创建独立 cgroup，只约束测试 UID 和两个指定对象。验证控制组成功、策略组拒绝、cgroup 外不受影响、对象替换后重载、失败重载保留旧策略、采集器崩溃后 link 解除。返回 77 表示环境不可验收，不能记作通过。

手动策略接口：

```bash
sudo ./build/collector --enforce-cgroup /sys/fs/cgroup/你的测试组 \
  --enforce-uid 1000 --deny-open /绝对路径/测试文件 --deny-exec /绝对路径/测试程序
```

对象匹配使用设备号和 inode；只覆盖明确固定的实验挂载。对象替换需 SIGHUP 重新解析，失败保留旧策略。退出后不持续保护，首版不 pin link。不要把本接口描述成通用路径防绕过或容器保护。

## 6. 实验与资源

```bash
sudo python3 scripts/benchmark.py --out out/target-benchmark-01 --rounds 5
python3 scripts/freeze_competitors.py --out out/competitors.json
python3 scripts/ablation.py --input out/target-integration-01 --out out/target-ablation-01
```

微基准只比较 B0/B1，不能代替完整应用性能、正常工作负载一小时验证以及 Falco/Tracee 对照。竞品冻结脚本只下载官方 release 元数据，不安装或运行竞品。实验分组定义在 `experiments/matrix.json`。

采集开销拆分入口（请使用不存在的新输出目录）：

```bash
sudo python3 scripts/benchmark.py --profile --rounds 5 \
  --opens 20000 --execs 1000 --environment-label vmware \
  --out out/vm-profile-01
```

| 组别 | 实际执行路径 |
|---|---|
| B0 | 不启动采集器 |
| P0 | 内核照常构造事件、入口出口配对和计数，跳过 ring buffer 输出 |
| P1 | 正常内核采集与 ring buffer 传输，用户态接收后丢弃，不编码 |
| P2 | 正常内核采集与 JSON 编码，编码后丢弃，不输出事件日志 |
| B1 | 正常采集并输出 JSONL，无分析器 |

P0/P1/P2 仅用于诊断，不能用于监控；采集器拒绝将诊断模式与 socket 分析或阻断混用。脚本验证诊断模式的接收计数及不输出普通事件的约束。零丢失计数不代表诊断模式保存了事件。各组轮换执行顺序，记录源码/采集器摘要、环境标签、输出目录、逐轮时间、RSS、子进程 CPU 与质量指标。子进程 CPU 包含负载子进程及采集器生命周期，不是采集器独占 CPU。

组间耗时差仅用于定位方向，不可视为各部件可相加的精确开销。P0 仍包含探针、字段读取、map 配对和统计，并非空探针成本；B2/B3 分析器开销需另做实验。脚本发现事件丢失/配对异常返回非零；性能是否低于 5% 仍由验收入口判断。历史 JSON 的环境说明保持原样，新输出已移除硬编码的“非 VMware”描述。

采集器默认按 **10 ms** 周期读取 ring buffer，减少频繁唤醒；事件字段及内核时间戳保持不变。`--batch-ms 0` 恢复原有自适应通知，允许范围为 0–50 ms。批处理可能增加事件等待时间，高负载下仍需检查 ring 丢失，不能只比较速度。

用同一个采集器交替比较批处理和原模式：

```bash
sudo python3 scripts/benchmark.py --compare-batching --batch-ms 10 \
  --rounds 5 --opens 20000 --execs 1000 --environment-label vmware \
  --out out/vm-batch-comparison-01
```

`seconds` 仍表示负载耗时，便于与历史结果对照；新增 `completion_seconds` 包含剩余事件排空与采集器退出，避免把延后处理误当作性能收益。采集器 CPU 在负载期间单独采样，子进程总 CPU 另列。不同口径分别报告，不混算。

消融入口重放同一份真实集成日志，比较单事件、进程来源、序列关联三组告警及证据；不用于计算性能或估计通用检出率。历史验证见 `docs/VERIFICATION_02.md`；当前 v3 进展见 `docs/V3_DEVELOPMENT.md`。

v3 新增的专项入口（均要求新的输出目录）：

```bash
# 真实内核：带积压排空、确认超时、一次终端 Ctrl+C
sudo python3 scripts/verify_shutdown.py --out out/v3-shutdown-01
# 完整链路的短时受控文件打开负载；不是业务性能开销实验
sudo python3 scripts/load_sweep.py --out out/v3-load-01 --rates 500,2000,5000 --seconds 3
# 无需 root，默认使用合成数据；也可用 --input 日志 --rules 配置做离线诊断
python3 scripts/analysis_benchmark.py --out out/v3-analysis-01 --rounds 3
```

本轮没有修改 eBPF 探针和六条规则的匹配条件。新增 `unpaired`/发送断线后清空关联状态属于证据质量处理，不是新增攻击类别。故意暂停分析器仍会触发有界队列丢失，排空确认不会恢复此前已丢弃的数据。

初始 ring buffer 16 MiB，pending map 上限 2048，用户态发送队列 1024 条，进程缓存 8192。JSONL 每 10 MiB 轮转，保留 5 份历史；SQLite 尚无自动归档，应使用独立实验目录并监控空间。root 采集权限与普通分析权限分开运行。

## 能力边界

- 监控“打开”而不是证明读取了内容；失败操作保持失败语义。
- preload 环境扫描最多 64 项，截断或读取失败显式标记，不把未知当作不存在。
- `argv_summary` 只记录 argv[0]；无完整命令行、capabilities、mount namespace 数据。
- 相对文件路径只有得到对象身份时可用于对象匹配；首版 rename/unlink 未完整重建 dirfd 路径。
- 启动快照仅在确认宿主机 PID namespace 时执行；WSL/容器 namespace 下明确降级，继续实时生命周期事件。
- kprobe 挂点具有内核兼容约束，首版缺失挂点会明确启动失败，不悄悄宣称完整覆盖。
- 无通用 Rootkit/提权/容器逃逸识别，不能在完全失陷的内核上保证可信。
- LSM 代码已编译；是否实际拒绝操作必须以启用 BPF LSM 的目标机验收为准。
