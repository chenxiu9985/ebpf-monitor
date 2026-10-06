# eBPF Monitor v4 开发版

2026-10-01 VMware记录：限定三轮真实动态阻断和每秒50次目标打开的一小时audit持续测试通过。五轮2000次打开/20次exec微基准全部保存目标事件，B0/B3耗时中位数0.12854/0.27996秒，耗时增加117.80%，吞吐下降54.09%，低开销目标未达成。VMware覆盖后的源码与本轮基准哈希逐项一致；两处被覆盖的磁盘空间保护脚本已保存测试时副本并恢复。详见[VMware验证记录](docs/VMWARE_STORAGE_RECOVERY.md)。以下未完成清单是此前开发快照，完整计划仍未验收。

同机阶段诊断五轮中位数：B0 0.13284秒，内核路径P0 0.17911秒，P1 0.19380秒，P2 0.19179秒，采集日志B1 0.18745秒。P0相对B0增加34.83%；后续阶段差值不单调，需要进一步分离内核高频路径与分析/SQLite成本。原始记录和解释见[VMware验证记录](docs/VMWARE_STORAGE_RECOVERY.md)。

后续VMware离线回放2166条真实事件时，存储/完整流水线中位耗时0.326/0.497秒，CPU时间接近耗时。本地现已让SQLite与原始JSONL复用一次事件序列化，84项Linux测试及1轮真实影子集成通过；VMware尚未对优化版复测。用于目标机更新的最小补丁包及基础/更新哈希见 `experiments/results/v4-vmware-2026-09-29/v4-json-reuse-patch-20261001.zip` 和同目录manifest。

开发依据：[v4 开发计划与验收标准](../13_v4开发计划与验收标准.md)。初次从 v3 独立复制，v3 源码和实验数据保留；当时未复制原仓库 .git、旧构建和 out。现有 out 包含后续 VMware 测试数据。基线摘要见 `docs/V3_BASELINE_SHA256.json`。

当前已实现新身份和协议、规则证据质量、两条场景阶段报告、受限动态控制/TTL map、audit/shadow/enforce 接线及规则相关存储过滤。VMware限定真实阻断和每秒50次目标打开的一小时审计测试已通过；**完整 v4 验收尚未完成**：强制响应异常矩阵、代表性业务、目标负载范围和竞品等价对照仍是待验收项；详见 `docs/V4_DEVELOPMENT.md` 及 `docs/VMWARE_STORAGE_RECOVERY.md`。

## 构建与审计

Linux x86-64、BTF、libbpf、clang、bpftool、C 编译器和 Python 3.11+；Python 依赖仍固定在 requirements.txt。实际依赖版本与目标内核必须随结果保存。

```bash
python3 -m pip install -r requirements.txt
bash scripts/build.sh -j2
python3 -m unittest discover -s tests -v
python3 -m monitor doctor
python3 scripts/run_live.py --duration 30
# 增加限定文件映射证据
python3 scripts/run_live.py --capture-mappings --duration 30
```

按一次 Ctrl+C，等待采集退出、排空和提交确认。结果默认写入新的 out/live-v4/<时间-PID>；检查 session.json 的 passed、capture_loss_free 及最终丢失计数。

## 回放、查询与报告

```bash
python3 -m monitor replay events.jsonl --db v4-replay.db --rules rules/default.yaml
python3 -m monitor query --db v4-replay.db --rule C01
python3 -m monitor report --db v4-replay.db --output v4-report.html
python3 scripts/equivalence.py events.jsonl --rules rules.json --out equivalence.json
```

v3 schema 1 可以回放，未知身份明确降级。回放永远不真实下发策略；使用新 v4 数据库，保留 v3 数据库原样。合成 demo 和历史 experiments/results 下的 v3 数据均不算 v4 内核实测。

## 影子与强制响应

把独立规则配置的 response_mode 改为 shadow，运行普通实时入口，即只记录拟申请、不拒绝。audit 是默认值；response_ttl_ms 默认 5000，上限 30000。

enforce 必须显式配置 response_mode=enforce，并提供本轮授权的无害文件、专用 cgroup 子目录和 UID；BPF LSM 必须实际活动。当前 WSL 不能确认该条件，入口会拒绝加载强制程序。不得绕过前置质量和身份门槛。

```bash
python3 scripts/run_live.py rules/enforce-lab.json \
  --control-object /tmp/owned-lab/protected \
  --control-cgroup /sys/fs/cgroup/owned-lab \
  --control-target-uid 1000
```

规则文件和 cgroup/文件应在实验作用域内预先配置；示例不是已完成部署。只保护原执行实例的后续新打开，不保护已打开 fd，不继承到后代，不保证第一次访问来得及阻断。

## 验证入口

WSL 工作区位于 Windows 挂载盘时，可使用以下入口在 Linux 临时本地存储完成测试后归档；它不修改内核启动配置。没有活动BPF LSM时，完整计划验收仍为false。

```bash
python3 scripts/acceptance_v4.py --native-data --stability-seconds 10 --out out/v4-acceptance
```

```bash
python3 scripts/integration.py --capture-mappings --uid 1000 --out out/integration-v4
python3 scripts/integration.py --capture-mappings --response-ready-fixture \
  --response-mode shadow --uid 1000 --repetitions 3 --out out/shadow-v4
python3 scripts/live_edges.py --out out/edges-v4
python3 scripts/verify_mapping.py --out out/mapping-v4
python3 scripts/verify_shutdown.py --out out/shutdown-v4
python3 scripts/transport_recovery.py --out out/recovery-v4
python3 scripts/verify_response.py --out out/response-v4
python3 scripts/benchmark_live.py --rounds 5 --opens 2000 --execs 20 \
  --environment-label TARGET-LINUX --out out/benchmark-v4
```

verify_response 返回 77 表示不能运行，绝不是通过。它包含零 sleep 初始打开、确认后拒绝、TTL、非匹配进程和既有 fd 边界；完整强制异常矩阵仍未全部覆盖。

接口详见 `docs/PROTOCOL_V4.md`；冻结实验合同见 `docs/EXPERIMENT_CONTRACT.json`；本次原始结果为 `experiments/results/v4-wsl-2026-09-29/`。旧 README 在 `docs/README_V3_BASELINE.md`，仅作历史参考。

## R04 automatic response

See [automatic response](docs/automatic-response.md) for runtime UID/cgroup discovery, multi-object protection, existing service enrollment, file replacement and asynchronous response limits.

```bash
bash scripts/build.sh
python3 scripts/run_live.py rules/default.yaml --response-mode enforce
sudo python3 scripts/verify_response_auto.py --out "out/auto-response-$(date +%Y%m%d-%H%M%S)"
```

Default monitoring remains audit. Explicit legacy control arguments retain the original single-object protocol. Real LSM acceptance exits 77 when unavailable; compilation and mocked control tests do not prove real kernel denial.
