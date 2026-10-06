# R04 自动响应

## 启动

在 Ubuntu 中更新此副本后，先重新编译；不能继续使用修改前的采集器二进制。

```bash
cd ~/ebpf-monitor-v4
bash scripts/build.sh
python3 scripts/run_live.py rules/default.yaml --response-mode enforce
```

这个命令不要求 `--control-object`、`--control-cgroup` 或 `--control-target-uid`。默认规则仍为 audit；只有显式选择 enforce 才加载动态阻断 LSM。正常 audit 和 shadow 模式也登记服务身份，但不加载阻断 hook。

仍须配置**保护哪些资产、哪些程序算服务**。默认对象是 `/etc/shadow`、`/etc/gshadow`，默认服务包含 `/usr/sbin/cron` 等程序。无需事先知道攻击进程的 PID、UID、执行令牌或 cgroup，也无需手动创建演示 cgroup。可以把现有业务文件加入 `sensitive_paths`，把实际服务程序加入 `service_executables`。

配置中的服务可执行文件身份是一项来源授权，不代表 systemd 单元身份：通过其他方式运行同一个已登记服务程序也属于这项来源。合法的 cron 任务如果满足“服务 → shell → 临时程序”也可能匹配；应以准确的程序路径、UID、规则配置 `exceptions`。

## 实际流程

### 两个终端的简洁演示

左侧在项目目录运行：

```bash
python3 scripts/run_live.py --response-mode enforce
```

右侧进入同一个项目目录，运行：

```bash
sudo python3 scripts/demo_response.py
```

新增脚本需要先同步到 Ubuntu。它自动寻找本项目唯一正在运行的采集器/分析器，使用本次有效配置，编译已有 `auto_response_worker.c`，通过已运行的 `cron.service` 启动“cron → /bin/sh → /tmp/临时程序”。无需提前指定目标 UID、cgroup 或执行实例；不新建服务，不新建 cgroup，不改监控规则。需要默认配置已经登记 `/usr/sbin/cron`、保护 `/etc/shadow` 和 `/etc/gshadow`，并启用 R04。

脚本添加一个唯一的 `/etc/cron.d/ebpf-r04-demo-*` 任务，等待下一次分钟调度，开始后立即反复打开保护对象，只显示成功、EPERM 拒绝、恢复等状态变化。默认连续运行 9 秒：5 秒 TTL 加 4 秒观察时间。不等待策略 applied，不输出敏感内容。完成后用正在运行的监控数据库核对同一进程、执行令牌和策略的 R04/applied/policy_denied；仅普通权限失败或仅有告警不算通过。

完成、报错和普通中断会移除脚本创建的定时任务；一次性目录锁阻止重复执行。中断时已经启动的工作程序会在有限时长内退出。强制 kill -9/断电无法执行清理，需删除脚本显示路径对应的 `/etc/cron.d/ebpf-r04-demo-*` 单个文件。真实 JSONL 和结果保留在输出显示的 `/tmp/ebpf-r04-demo.*/`，监控证据仍在左侧原输出目录；演示不会停止监控。

这是实际 cron 来源的响应演示，连续访问让异步策略的生效及到期可见；它不保证短进程或第一次访问被阻止。监控尚未观察到真实执行链、例外规则阻止响应、丢失或配置不匹配时，脚本报告未完成，不伪造阶段。

1. 监督器保存本次有效规则到输出目录的 `rules.json`，将配置路径写入 `response-assets.tsv`。采集器以 root 权限打开这些文件，登记设备号与 inode。清单最多 64 个对象和 64 个服务程序；不接受控制请求中的任意文件路径。
2. 内核记录 fork、成功 exec、UID、cgroup 和执行令牌。对已运行服务，首次捕获派生时用父进程实际 `mm->exe_file` 核验登记文件身份，并提供独立的 `service_registration` 证据。这不是补造历史 exec。进程快照依然只能提供上下文。
3. 分析器关联服务来源、观察到的 shell exec 和临时目录程序 exec。cron 多次 fork 的辅助进程保留真实 fork 证据，不再把继承的 cron 程序路径误当成缺失的 exec。字段不完整、丢失、过期、缺失来源或例外规则会禁止响应。
4. R04 满足响应条件时发送 V4/2 请求：执行实例键、执行令牌、事件 UID、事件 cgroup、规则版本和 TTL。`object_id=0` 表示本次启动已授权的整个保护集合。采集器再次核对内核身份表中的令牌、UID、cgroup 和已登记服务来源；不匹配则拒绝。
5. 写入 BPF 动态策略后返回 `applied`，后续 `file_open` 必须同时匹配进程实例、令牌、UID、cgroup、有效期和保护对象身份，才返回 `-EPERM`。真实拒绝另发 `policy_denied`，包含实际设备号、inode、对象编号和策略编号。
6. TTL 到期恢复打开权限。退出和新 exec 清除实例策略；UID/cgroup 改变后旧策略不再匹配。策略不会自动继承给新子进程。

## 文件替换与配置更新

采集器每 250 ms 重查授权路径。替换后的新 inode 加入保护集合，旧 inode 移除；活动策略自动使用更新后的集合。文件暂时不存在时显示为未登记，重新出现时恢复登记。硬链接/符号链接通过实际设备号与 inode 匹配。保留文件描述符直到旧项移除，避免删除后的 inode 重用被误识别；更新失败时停止新的自动策略应用并记录错误，后续刷新重试。

**刷新不是原子文件替换通知**：替换到重新登记之间可能有访问空窗。`monitor_registry` 记录当前对象和刷新状态，可与打开结果核对。修改授权对象、服务清单、响应模式或范围需重启监督器；SIGHUP 不允许在当前会话扩大这些授权。

## 可验证的边界

用户态关联和控制下发是异步过程，默认重排窗口为 200 ms。第一次打开和短生命周期程序可能早于策略生效，不能宣称“R04 一出现就保证首次敏感访问被阻止”。`applied` 仅表示策略写入已确认；真正阻断要看 `policy_denied` 和目标程序的 `errno=1`。

本实现阻断有效期内的**新打开**，不撤销已打开的 fd，不阻断所有任意路径，也不终止进程。已运行服务只有在监控期间观察到派生并完成核验后才能建立响应来源；监控之前发生且没有证据的整个历史攻击链不能补造。

## 不等待策略确认的真实验收

```bash
sudo python3 scripts/verify_response_auto.py \
  --out "out/auto-response-$(date +%Y%m%d-%H%M%S)"
```

验收使用两个无害文件和测试服务，不读取 shadow、不修改现有系统服务。三个服务在监控启动前运行，工作开始只等监控就绪，**不等策略 applied**。测试 root、普通用户、cron 式多次派生，以及立即退出的程序；持续打开两个文件，固定时间替换一个文件，再持续到 TTL 到期。

`result.json` 分开记录首次访问、策略前成功打开数量、有效期内拒绝、替换刷新空窗、替换后拒绝、到期恢复、旧 fd 和短进程漏过。`first_open_guaranteed=false`；短进程是边界测量项，其漏过不伪装为阻断成功。完整阻断验收以持续进程拒绝、两个对象匹配、替换后拒绝、到期恢复及采集无丢失为通过条件。

没有 root 或 BPF LSM 未启用时退出码 **77**，状态 `unavailable`，不算通过。不提供真实 Ubuntu 运行结果时，编译和模拟控制测试不能替代实际阻断验收。

## 兼容旧演示

原来的三个限定参数一起提供时，监督器选择 legacy 模式，保留 V4/1 单对象、固定 UID/cgroup 控制协议：

```bash
python3 scripts/run_live.py "$LAB/rules.json" --out "$RUN" \
  --control-object "$OBJECT" --control-cgroup "$CGROUP" \
  --control-target-uid "$DEMO_UID"
```

只提供部分限定参数会报错。`verify_response.py` 明确使用 legacy，保留原来的“等待 applied 后验证打开失败”测试；新的 `verify_response_auto.py` 用于验证没有这种等待的实际异步过程。
