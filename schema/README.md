# 事件、规则与传输接口

`event.schema.json` 是对外事件格式；`monitor/model.py` 是运行时验证器。内核和 C 采集器之间另用 `bpf/events.h` 定长结构，两个层面的版本不可混用。

- socket 消息：4 字节大端无符号长度 + UTF-8 JSON。上限 1 MiB；半包累计，非法长度与断线残包报错。
- v3 socket 退出协议：采集器停探针后使用一个总超时排空队列与剩余 ring 数据，发送带 `shutdown_ack_required=true` 的 monitor_stop，再半关闭发送方向。分析器收到完整 EOF 后完成 SQLite 提交、JSONL flush/close，再返回 ASCII `COMMITTED <monitor_stop event_id>\n`。确认身份不匹配、超时、断线或残包均不算成功；这不补回运行期间已丢失事件，也不承诺断电下多个文件的原子一致性。
- v3 `--socket` 采集器需要搭配 v3 分析器。`--exit-on-stop` 供监督启动器使用；独立 listen 默认仍可等待后续连接。stdout JSONL 模式不使用确认协议。
- `transport_disconnects` 记录发送断线；与 ring/map/queue 丢失和 unpaired 一起使后续关联状态失效。`shutdown_unsent=0` 仅表示发送队列为空，须同时检查 `shutdown_acknowledged` 和退出状态。
- JSONL：每行一个完整事件。event_id 在一次采集会话内唯一；数据库幂等插入，关联器有界去重。
- monotonic_ns 使用 CLOCK_MONOTONIC；start_ns 使用任务 start_boottime，只用于身份，不用于延迟相减。
- process_key：machine-id、boot-id、宿主机 TGID、组长启动时间。exec_generation 在分析端递增；不能用 comm 作为身份。
- 来源链在子进程首次观测时冻结祖先映像、代次和证据；父进程后续 exec 不改写该来源。缺少启动前信息时保留未知，祖先深度有界。
- 完整挂点及读取器就绪后才开启采集，拆卸前关闭；跨越起止边界的未完成调用不保证被记录。活动观察窗口内的未配对出口仍计入 unpaired。
- process_dead 来自退出时 signal->live；线程退出不自动等同于进程退出。
- argv_summary 首版仅记录 argv[0]；不采集完整命令参数与环境。env 只保留 LD_PRELOAD、LD_LIBRARY_PATH。
- quality_flags：1=截断，2=读取错误，4=上下文缺失，8=环境扫描未完整结束。只扫描前 64 个环境条目，每值最多 255 字节。
- device 是 Linux 内核 dev_t 编码（major << 20 | minor），不是用户态 st_dev 原始整数。
- target_pid 是 ptrace 请求中的 namespace PID；target_process_key 只有内核探针实际解析到目标 task 时才提供。不存在的目标不能臆造身份。
- 文件路径为调用参数，可能是相对路径；inode/device 为检查阶段获得的实际对象。成功打开根据系统调用返回值，不根据到达安全检查推断。
- result_state 表示操作结果；action_state 表示告警/拒绝。告警不表示攻击成功，LSM 告警也不自动证明所有副作用测试通过。

配置采用固定规则 ID 与参数，支持 JSON 或 YAML。使用命令行不传 --rules 时采用相同内置默认值。例外必须同时匹配 rule、exe、uid；不支持仅按进程名称或 root 身份放行。

SIGHUP 请求重新加载：分析器先验证完整配置再切换并清空旧关联状态；采集器重新 stat 显式给定的保护对象，写入非活动策略槽后切换版本。加载失败保留旧配置。新进程重连不会承诺补齐断线期间缺失事件。
