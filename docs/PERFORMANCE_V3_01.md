# v3 性能收尾第一轮（2026-09-27）

## 改动

BPF ring 中按事件种类发送实际使用的结构前缀：file_open 保留公共字段和 path；fork/exit/ptrace 保留公共字段与 comm；exec、rename 等仍发送完整结构。采集器验证长度并补齐未使用的零字段，输出 JSON 格式保持一致。路径补采及质量标记继续保留；没有删除规则或采样丢弃事件。

新增 --full-event-records，可在同一采集器二进制内恢复旧的填充长度；scripts/benchmark.py --compare-records 轮换 B0、B1-full、B1，从而避免以不同内核、不同旧版本作不公平比较。

新增 scripts/benchmark_live.py：B0 与完整 B3（采集、规则、JSONL、SQLite）交替运行；统计两进程 CPU 时间、结束时 RSS、完整处理与退出时间、目标文件落库次数和丢失计数。passed 只表示采集完整与正常退出，不表示性能目标达标；出现丢失时耗时数字不能证明无损监控开销。RSS 不是峰值或全部内核内存，CPU 不包含全部系统内核成本。

## 本地证据与边界

- 60 项单元测试通过，其中新测试对九类事件比较完整和紧凑记录生成的全部 JSON 字段。
- 冷路径/拒绝访问、五轮既有集成、12 项边界通过。
- WSL 五轮采集微基准（10000 opens + 100 execs）：B0 中位数 0.09800 秒；B1-full 0.14164 秒；B1 0.13305 秒。紧凑模式相对完整记录耗时降低约 6.07%。相对 B0 的吞吐下降仍约 26.34%。两组丢失计数为零，不能宣布低开销完成。
- Windows 映射目录上完整链路突发测试发生大量队列丢失；本地 Linux 目录同类测试也发生丢失。后者 B0 约 0.09915 秒、B3 约 0.13629 秒，但每轮 10000 次打开仅保存约 1900–2100 次，不能用此耗时宣称完整监控性能。
- 本地 Linux 文件系统三档固定速率（500/2000/5000 次每秒，各三秒）分别保存 1500/6000/15000 次目标打开，均零丢失并正常确认退出。Windows 映射目录的 5000 档出现丢失；这说明部署存储位置会影响完整链路结果，但不是不限速突发丢失的唯一原因。

这些是 WSL 结果，不是 VMware 的性能改善结论。性能比值针对密集微基准，不能外推为正常业务开销。旧 VMware 47% 耗时增幅也不能与本次 WSL 数字直接比较。

证据在 out/compact-compare-wsl-01、compact-denied-01、compact-integration-01、compact-edges-01、compact-live-wsl-01、compact-live-wsl-local-02、compact-load-wsl-01、compact-load-wsl-local-02 和 compact-unit.log。

## VMware 命令

更新整个 v3 或解压本次补丁后，在虚拟机本地 ~/ebpf-monitor-v3 执行；不要直接在 /mnt/hgfs/share 运行实验。先退出其他监控实例。

```bash
cd ~/ebpf-monitor-v3
bash scripts/build.sh -B
python3 -m unittest discover -s tests -v
PERF_RUN=$(date +%Y%m%d-%H%M%S)
sudo python3 scripts/verify_denied_open.py --out "out/perf-denied-$PERF_RUN" --uid "$(id -u)"
sudo python3 scripts/benchmark.py --out "out/perf-records-$PERF_RUN" --compare-records --rounds 5 --opens 10000 --execs 100 --environment-label vmware
sudo python3 scripts/benchmark_live.py --out "out/perf-live-$PERF_RUN" --rounds 5 --opens 10000 --execs 100 --environment-label vmware
sudo python3 scripts/load_sweep.py --out "out/perf-load-$PERF_RUN" --rates 500,2000,5000 --seconds 3
sudo tar -czf "v3-perf-results-$PERF_RUN.tar.gz" "out/perf-denied-$PERF_RUN" "out/perf-records-$PERF_RUN" "out/perf-live-$PERF_RUN" "out/perf-load-$PERF_RUN"
```

逐条执行。完整链路若因负载超过容量而 passed:false，请保留结果，后续受控速率测试仍有意义；若探针加载失败则先排查日志。

补丁包包含路径修复所需文件及性能更新，不含 build/out。必须重新编译并配套更新分析器。尚未承诺任意突发流量零丢失；这轮交付是有限的传输优化与完整性能测量工具。
