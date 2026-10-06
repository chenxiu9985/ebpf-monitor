# VMware 磁盘不足与稳定性复验

2026-09-29 用户粘贴的终端记录：VMware Ubuntu 内核 6.8.0-142-generic，活动 BPF LSM；真实响应测试 executed/passed=true，退出码0。三轮确认后的30次新打开全部 EPERM，TTL 后30次打开成功，三轮已有 fd 读取成功，非匹配打开正常。初始33次访问均成功，首次阻断率0/3，不能宣称首次攻击被阻断。记录来自用户终端，并非本机直接采集的原始数据库。

随后重建通过，但 --native-data、3600秒综合验收返回 ENOSPC：汇总 JSON 和归档目录创建均失败。一小时稳定性未验收通过；具体失败阶段和持续时长没有完整日志，不能据此断言监控器崩溃或出现事件丢失。原版 TemporaryDirectory 在归档失败时也会清理临时数据，原始记录可能已无法恢复。

## 修复

- scripts/acceptance_storage.py：按目标打开次数估算空间，8192字节/次加512MiB保留量，仅为保守预算，不是实际每事件成本结论。
- 综合测试与独立稳定性测试在运行前预检；稳定性每次资源采样检查至少512MiB余量，低于门槛则失败并停止产生负载。
- --stability-opens-per-second 显式传递负载，默认仍为1000，没有自动降低验收负载。
- 本地同文件系统归档使用重命名，避免第二份完整数据库；跨文件系统复制预检空间，归档/元数据失败时保留临时目录并打印位置。成功才清理临时目录。
- 结果写入失败时将 JSON 打印到终端并返回非零，不重复抛出掩盖原因的写入异常。

本机修复验证：Linux 83项测试通过（原77项加6项空间/归档回归检查）；2秒、100次/秒真实采集烟测生成200条、保存200条、passed=true。没有因此新增一小时通过结论，没有改变内核阻断逻辑。本次修改后的脚本不再属于之前 source-sha256.json 的代码快照。

## 复验

先检查块空间和 inode，不批量删除已有实验结果：

```bash
df -h / /tmp "$HOME"
df -i / /tmp "$HOME"
sudo du -xhd1 /tmp "$HOME/ebpf-monitor-v4/out" /var 2>/dev/null
```

更新补丁到 ~/ebpf-monitor-v4 后，1000次/秒的一小时空间预算约28GiB，建议先确保输出所在分区至少30GiB可用。Ubuntu项目已在本地Linux磁盘时直接写out，省去临时归档：

```bash
cd ~/ebpf-monitor-v4
RUN="out/vmware-acceptance-$(date +%Y%m%d-%H%M%S)"
sudo python3 scripts/acceptance_v4.py \
  --require-enforce --stability-seconds 3600 \
  --stability-opens-per-second 1000 --out "$RUN"
STATUS=$?
echo "退出码：$STATUS"
cat "$RUN/acceptance.json"
cat "$RUN/stability/result.json"
```

如果空间仅能达到约4GiB，可显式改为 --stability-opens-per-second 100；这属于每秒100次打开的持续测试，不等价于每秒1000次的验收条件。空间预算不足会在开始前拒绝，不需盲目重跑一小时。

## 后续每秒50次打开的一小时结果

用户在未扩大虚拟磁盘的环境完成独立 audit 稳定性测试，输出目录为 `out/vmware-stability-50-20260929-142914`。用户粘贴的是末尾约219秒的采样和结果汇总，保存于 `experiments/results/v4-vmware-2026-09-29/user-terminal-stability-50.txt`，不是完整原始JSON/数据库。

- workload_seconds=3600.00089139，rate_achieved=49.9999876195864，generated/saved=180000，passed=true。
- session.passed=true、capture_loss_free=true；collector_exit=analyzer_exit=0，shutdown_acknowledged=true；排空未发送/丢失/错误均0。
- 总 events_attempted=192085，包含目标文件打开之外的系统事件；ring_lost/map_fail/unpaired/queue_lost/transport_disconnects 均0，最终queue_depth=0。
- 尾部RSS：采集器36632KiB，分析器约446492至446540KiB。这不是全程峰值，完整内存趋势未提供，不能从尾部样本宣称不存在长期内存增长。
- 测试后根分区剩余2.3GiB。每秒1000次一小时仍未通过，本次audit测试也不证明长期策略TTL/异常响应的完整稳定性。

目标上已有功能验收、限定真实响应和每秒50次一小时audit持续输入证据；完整计划仍需完整响应失败矩阵、负载范围/趋势、业务性能和公平竞品对照。

## 2026-10-01 VMware五轮微基准及覆盖检查

VMware目录 `out/vmware-benchmark-20261001-112134/result.json` 已随用户的VMware版v4复制到本地。内核6.8.0-142-generic，BPF LSM活动。五轮 B0/B3 的参数均为2000次打开、20次exec；五轮B3各保存2000次目标打开，五轮组均passed，整体completed/passed=true，退出码0。

| 指标 | B0 | B3 |
|---|---:|---:|
| 工作量耗时中位数 | 0.128537496 s | 0.279956555 s |
| 工作量完成后的排空退出 | 基本为0 | 五轮约0.78–1.03 s |

B3相对B0耗时增加117.801%，固定工作量吞吐下降54.087%。计时的 `seconds` 不含排空退出时间；排空另列。该结果只证明这组文件打开/exec微基准在完整审计配置下显著增负，不能泛化为业务吞吐或解释为任一单独阶段的因果成本。五轮CPU为采集/分析用户态样本，不含内核总CPU，RSS是工作结束样本，不是峰值。低于5%的成本目标未达成。

覆盖检查：本地`bpf/collector/monitor/scripts/rules`及`build/collector`的哈希与上述result.json中43个源码/构建条目逐项一致，说明覆盖后的本地代码与VMware本轮基准对应。覆盖将先前两个空间保护脚本还原为旧版；已先在 `experiments/results/v4-vmware-2026-09-29/pre-storage-fix-20261001/` 保留其VMware测试时副本，再从原校验通过的`v4-storage-fix.zip`恢复保护。恢复后这两个脚本的哈希不再对应本轮微基准快照；原始结果和其他源码不变。

下一步应在同一VMware目标以已冻结的B0/P0/P1/P2/B1阶段微基准诊断主要成本，再做规则相关内核过滤及采集/持久化优化；每次变更后用完整捕获等价性和相同轮次复测，不直接根据本次B0/B3差值指定单点原因。代表性业务、竞品公平对照及强制响应异常矩阵仍未完成。

### 同机阶段诊断结果

用户随后在同一VMware、同一内核运行 `benchmark.py --profile --rounds 5 --opens 2000 --execs 20 --batch-ms 10`。用户终端全文保存于 `experiments/results/v4-vmware-2026-09-29/user-terminal-profile-20261001.txt`；提取的25条轮次及完整配置/源码哈希在同目录 `profile-20261001.json`。结果 `capture_loss_free=true`、`completed=true`；P0无事件输出是有意诊断状态，P1/P2消费计数已由脚本与尝试数核对。五轮中位数：

| 组 | 含义 | 工作量耗时 | 相对B0耗时增加 |
|---|---|---:|---:|
| B0 | 无监控 | 0.132842 s | — |
| P0 | 内核构造/配对/计数，禁用环形输出 | 0.179107 s | 34.83% |
| P1 | 增加环形传输和消费，不做JSON编码 | 0.193796 s | 45.89% |
| P2 | 增加JSON编码但丢弃 | 0.191794 s | 44.38% |
| B1 | 增加JSONL落盘，不含分析器 | 0.187455 s | 41.11% |

五轮每轮P0都慢于同轮B0，说明本负载中即便没有环形输出，内核侧观测路径仍有明显工作量开销。P1/P2/B1的中位数不单调，不能把中位数差值拆成各阶段独立因果成本，也不能声称JSON编码或日志落盘无成本。B1每轮约3.02MB原始日志；该实验没有分析器/SQLite。另一次完整B3约0.280秒，提示完整流水线还应诊断分析与持久化，但两次独立实验不足以量化其净贡献。采集器CPU采样以系统时钟粒度计，P0显示0不意味着零内核成本；各组约1秒的完成时间含启动后排空/退出，不等同工作量耗时。

后续优先核验内核侧高频打开路径和规则相关过滤，再用同机配对消融复测；同时以同轮真实B3事件输入运行 `analysis_benchmark.py`，分开观察规则分析与SQLite/日志路径。现阶段未修改这些检测路径，保留原始计时与源码快照。

### 同机离线分析与存储诊断

用户使用完整B3第1轮的 `events.jsonl` 在VMware运行 `analysis_benchmark.py --rounds 5 --rules rules/default.yaml`，2166条真实采集事件，`source=JSONL_REPLAY_NOT_LIVE_CAPTURE`，`passed=true`。五轮中位耗时：解码0.020355秒、规则引擎0.011582秒、单独SQLite存储0.326015秒、完整离线流水线0.497012秒。当前只有用户粘贴的汇总输出，本地尚未收到完整`result.json`；各轮CPU秒数、文件系统与抖动信息需用该文件继续核验。

存储测量包括每条JSON序列化、SQLite写入及最终提交；完整流水线另含验证、排序、规则、原始/告警JSONL及SQLite。各阶段是单独顺序运行，不可将0.326秒与0.020/0.012秒相加推算实时B3的成本。结果说明用户态持久化路径值得优先进一步测量，但不能单凭墙钟时间断定是CPU序列化还是磁盘同步等待。此诊断在原实现上运行，未声称优化达标。

五轮追加CPU数据：存储的墙钟/CPU秒数依次为(0.326/0.298)、(0.568/0.535)、(0.401/0.336)、(0.263/0.233)、(0.308/0.275)；完整流水线为(0.497/0.448)、(0.619/0.579)、(0.561/0.490)、(0.381/0.354)、(0.380/0.345)。CPU时间接近墙钟时间，说明用户态计算与SQLite调用开销占主要部分；不能根据此数据单独断言磁盘同步的精准占比。源码检查发现完整流水线对同一事件分别为SQLite和原始JSONL序列化一次。

### 首个保守优化：事件序列化复用

本地将`Store.event_with_body`的紧凑JSON同时用于SQLite与原始JSONL；`Store.event`的布尔返回兼容旧调用，告警写入及响应语义未改。原始JSONL改为紧凑空白格式，解析后的字段和值以及数据库body一致；新增测试覆盖中文路径、日志/数据库逐字一致和重复事件只写一次。WSL Linux共84项测试通过；带映射、影子响应的真实采集1轮通过，六条规则均命中、正常样例0告警、采集/分析退出码0。更改不涉及eBPF内核程序或VMware已验证的阻断实现。

使用复制来的同一VMware事件，在本机Linux文件系统上各做五轮离线回放：修改前完整流水线中位数约0.143秒，修改后约0.114秒；两次独立顺序运行受缓存与主机负载影响，只作本地探索，不能宣传为VMware/生产加速或5%目标已达成。VMware原始结果和源码哈希保持历史快照；下一步在目标机同样以五轮新目录复测，并核对结果的告警与行数。此处用户尚未把优化版部署到VMware。
