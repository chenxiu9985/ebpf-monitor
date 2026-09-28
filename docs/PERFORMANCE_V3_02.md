# v3 VMware 性能回传与突发缓冲修正

日期：2026-09-27。用户回传的是上一版 1024 消息队列在 VMware 上的结果。本文件区分目标机实测和随后在本地 WSL 做的修正验证。

## VMware 回传结论（修正前）

- 60 项单元测试、敏感访问专项全部通过。
- 同一二进制五轮 B0/B1-full/B1 中位运行时间 0.63130/0.89109/0.89063 秒；紧凑记录相对完整记录仅缩短约 0.052%，低于可靠实验结论所需的效果量。相对 B0，B1 吞吐下降 29.12%。之前 WSL 的约 6% 改善未在目标机复现。
- 完整 B3 五轮只保存 3632、5487、5532、5516、6436 次目标打开，期望每轮 10000 次；passed=false。这种丢失条件下 B0/B3 0.65254/1.20427 秒以及显示的 84.55% 时间增加，不可作为无损监控的正式性能数字。
- 三秒受控 500/2000/5000 次每秒分别保存 1500/6000/15000 次，均 passed=true。这支持有限速率能力，不支持任意突发容量。

## 修正与本地回归

正常运行期的传输队列由 1024 扩到 16384 条，有界缓冲可吸收短时突发；持续超出消费能力时仍会增加 queue_lost。通常约 1 KiB/条 JSON 数据，满队列约需 16 MiB 加队列元数据；确切占用取决于事件长度。这是内存换短时突发容量，不能降低每条事件的 CPU 成本，也不会恢复此前丢失的数据。退出的带超时排空与提交确认保持原样。

本地 WSL 6.6，Linux 本地文件系统，五轮 10000 次打开+100 次执行突发：原队列每轮仅保存 1967–2119 次目标打开；新队列五轮各保存 10000 次，queue_lost 均为 0，退出确认成功。B0/B3 中位工作负载时间为 0.09389/0.12872 秒，增幅 37.10%；采集器结束时 RSS 采样中位数从约 37652 KiB 增至 44308 KiB，差约 6.5 MiB。这些是 WSL 数据，不可写成 VMware 性能结论。

60 项单元测试、敏感访问专项、五轮既有集成、退出专项均通过。专门暂停分析器的 20000 次过载恢复测试仍报告 queue_lost=3366 并成功恢复、正常退出，证明缓冲仍有界且丢失可观察。受控速率的 WSL 本地 Linux 文件系统三档均完整保存；Windows 映射目录高负载会影响结果，目标机应在本地 ext4 跑实验。

## 在 VMware 复验

从当前工作区将整个更新后的 ebpf-monitor-v3 复制到虚拟机本地目录，先退出其他监控实例，然后执行：

```bash
cd ~/ebpf-monitor-v3
bash scripts/build.sh -B
python3 -m unittest discover -s tests -v
PERF_RUN=$(date +%Y%m%d-%H%M%S)
sudo python3 scripts/verify_denied_open.py --out "out/burst-denied-$PERF_RUN" --uid "$(id -u)"
sudo python3 scripts/benchmark_live.py --out "out/burst-live-$PERF_RUN" --rounds 5 --opens 10000 --execs 100 --environment-label vmware
sudo python3 scripts/load_sweep.py --out "out/burst-load-$PERF_RUN" --rates 500,2000,5000 --seconds 3
sudo python3 scripts/transport_recovery.py --out "out/burst-recovery-$PERF_RUN"
sudo tar -czf "v3-burst-results-$PERF_RUN.tar.gz" "out/burst-denied-$PERF_RUN" "out/burst-live-$PERF_RUN" "out/burst-load-$PERF_RUN" "out/burst-recovery-$PERF_RUN"
```

结果解释：benchmark_live.py 只有 passed=true、每轮 captured_fixture_opens=10000 且相关质量计数全零，才可引用其 B0/B3 耗时比例。即使通过，该比例只描述这组密集微基准，非一般应用开销。过载恢复测试故意暂停分析器，允许观察到队列丢失，应检查恢复和退出确认而非要求全程零丢失。


## VMware 突发缓冲复验结果（后续用户终端回传）

目标机重建成功；60 项单元测试全部通过。五轮完整链路测试每轮 10000 次目标文件打开均保存 10000 次，五轮 passed=true，最终 passed=true。按当前脚本判定，这同时要求正常退出、提交确认及相关采集/传输质量计数为零。本次依据用户粘贴的终端输出，尚未独立检查这轮全部原始数据库与 session.json。

本轮 B0 工作负载耗时中位数 0.608354900 秒，B3 为 1.088986143 秒，耗时增加 79.0051%，吞吐下降 44.1357%。因此有界缓冲解决了本组短时突发的完整性问题，但不能解释为低开销达标。此前丢数据时的 84.55% 与现在不能作为严格的性能改善对照。

B3 包含排空和退出的完成时间中位数约 2.372 秒。约 1.089 秒只是工作负载执行阶段，不能当作所有事件已处理完成的时间，也不能当作告警延迟。两进程结束时 RSS 采样合计中位数约 81.0 MiB，并非峰值、独占物理内存或全部内核内存。

当前结论：受控真实敏感访问及进程祖先告警已经通过；本组突发完整链路测试通过；动态加载和自定义策略已具备；密集微基准的开销仍明显。无需继续扩张队列以追求无限突发。若最低交付侧重功能，可以整理现有证据并明确性能边界；若低开销是硬性指标，仍需继续针对分析/存储优化或补充代表性业务实测，不能以本轮 passed=true 代替性能达标。
