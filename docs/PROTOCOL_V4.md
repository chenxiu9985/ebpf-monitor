# v4 协议、身份与质量合同

对应计划：V4-101—105、201—204、301—306、401—406。接口已实现；目标机强制模式验收仍单列。

## 事件和旧数据

事件继续采用 AF_UNIX/SOCK_STREAM：4 字节大端长度 + UTF-8 JSON，最大 1 MiB。JSON `schema_version=2`；这与控制版本 1、规则配置 `version` 是三个独立版本。不支持的事件版本立即报错。

`session_id` 是采集器启动唯一值；`event_id` 在该会话内递增。事件、接收、判定和 map 更新使用 CLOCK_MONOTONIC。`process_start_ns` 来自 task group leader 的 start_boottime，是启动身份字段，禁止拿它与事件时间计算延迟。`exec_token` 是内核为 fork/成功 exec 生成的实例令牌，不是 Python generation。Python generation 只用于旧规则内部兼容。

启动之前的实例没有令牌时保持 0；不得由快照/PID 补造可处置身份。身份 map 是有容量上限的 HASH，失败计入 map_fail。线程 exec 从 old_pid 找入口参数，重新读取当前线程组身份并更换令牌；启动身份变化时清理旧 map 项。fork 子代具有自己的令牌，旧策略不继承；exec 清理旧策略；最后线程退出清理身份与策略。

旧 schema 1 经 `validate_event` 适配成 2，标记 `source_schema_version=1`、`source_hook=v3_replay_adapter`、`exec_token=0`。旧日志仍可分析，但无法满足动态处置身份条件。每次回放使用新的 v4 数据库；不得向 v3 数据库写入。

## 证据

`monitor/evidence.py` 声明规则必需阶段，不生成概率分数。`complete_for_rule` 只表示当前规则必要证据和质量条件满足。原始 evidence_ids、各阶段 IDs、字段读取/截断错误、缺失项、禁止处置原因和观测区间同时保存。

R04 是前置序列触发点；C01 是后续敏感打开的关联结论。二者共用 shell 开始的时间窗口，窗口外 R04 可以保留为风险线索，但不能触发策略。来源保存为 fork 时的历史关系，父进程后续 exec 不会改写子代来源。文件打开成功不称为读取内容。

C02 要求配置、对应文件对象打开、同对象成功 mmap 和后续敏感行为；保留原来的配置＋敏感行为风险提示，但缺失打开/映射时明确降级。失败 mmap 单列 attempted；没有 file 对象的失败请求不伪造对象。成功映射不表示恶意函数或代码已执行。

任何读取/截断/缺失、迟到、身份未知、原始证据不在缓存或相关丢失区间都会阻止动态响应。字段错误目前按保守的整体降级处理，尚未按“无关字段”放宽处置。丢失区间采用会话观察起点至健康报告时间的保守范围，不能指出具体丢失事件。健康记录的区间不是精准丢失时刻。

分析器保留 200 ms 整理窗口。8192 条队列上限触发的提前处理在原始记录质量中标为缺失。session 变化先排空旧队列，再清除关联、快照别名与窗口，避免跨会话拼接。

## 映射覆盖

`--capture-mappings` 默认关闭，开启后只为成功 exec 时观测到 LD_PRELOAD/LD_LIBRARY_PATH 的实例配对 x86-64 mmap 入口、security_mmap_file 文件对象和 syscall 出口。按 TID 保存 pending，按线程组实例关联。flags、prot（operation）、fd（dirfd）、device/inode 和 retval 一并保存。

没有环境配置的 dlopen、mmap2、其他架构、所有映射变化和路径规范化不在当前承诺内。库路径按捕获配置与打开请求精确对应，再按对象关联映射；符号/硬链接的内核对象采集已验证，但不承诺所有不同配置路径别名都能被 C02 自动识别。

## 独立控制协议

AF_UNIX/SOCK_SEQPACKET，单包最大 1024 字节；请求 ASCII 格式如下，字段不能含空格、任意路径或其他动作：

```text
V4 1 VERB REQUEST_ID SESSION_ID RULE_VERSION EVIDENCE_ID TGID START_NS EXEC_TOKEN UID OBJECT_ID TTL_MS
```

VERB 仅 APPLY/QUERY/REVOKE；OBJECT_ID 只允许启动时授权对象 1；TTL 为 1—30000 ms；数字必须无符号十进制且不溢出。request ID/evidence ID 上限 64 字符、session 上限 255 字符。回复是有 control_version、request_id、state、reason、policy_id、更新前后时间、expires_ns 的 JSON。

socket 创建权限 0600，拒绝覆盖既有路径；使用 SO_PEERCRED 同时核验分析器 PID 与 peer UID。速率上限 20 请求/秒，终身请求缓存上限 1024，动态 map 上限 128；满时拒绝，不覆盖有效策略。相同 request ID 和完全相同参数返回既有状态；不同参数冲突拒绝。到期后重放不会重新激活；超时后 QUERY 核对，未核对成功为 unknown。

C 端核验会话、动作、对象、启动授权 UID、TTL、内核执行令牌、对象是否被替换；内核命中再次核验启动身份、令牌、cgroup、UID、device/inode、TTL。原子 map 更新前后的单调时间形成应用区间，applied 不表示实际命中。已有 LSM 和静态策略拒绝优先返回，不覆盖它们的安全决定。

启动时持有 O_PATH 文件描述符，使授权对象删除后仍被引用，降低 inode 复用风险；新 APPLY 对配置路径替换拒绝。策略限制短期文件对象，对后来替换出的路径对象不承诺自动保护。不会撤销已打开 fd、既有映射或读取能力。

正常退出先撤销控制请求入口和动态策略，再停止采集、分离 BPF links，保留 v3 排空及 COMMITTED 确认。异常退出使用不 pin 的 map/link 生命周期；已有 TTL 不自动续期。目标机异常恢复、跨 namespace、容量和身份竞态的全矩阵仍需真实强制验收，模拟 map 测试不替代它。

## 存储和报告

新增 responses 表保存追加式策略状态，保留 requested/timed_out/unknown 的歧义。请求先提交 SQLite 意图，再发送；denied 通过会话＋policy_id 回溯请求及告警。事件的 storage_submit_ns 是提交写操作时刻，不是精确事务持久化时刻；排空 ACK 才确认最终事务和日志已提交。

报告按事实、证据质量、动作、成本展示，所有外部文字安全转义。缺测成本标未知。`capture_profile=rule_related` 仅减少无关 file_open 的 SQLite/JSONL 落盘；全部事件继续更新分析上下文。它不降低 BPF/ring/编码/传输成本，也不是计划中的内核规则过滤。意外丢失与有意存储过滤分别计数。
