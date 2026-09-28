# v3 失败打开路径采集修复（2026-09-27）

针对 VMware 的 probe 失败打开事件 path 为空、Q_READ_ERROR=2 导致 R01 漏报的问题，新增 do_filp_open kprobe，读取 struct filename.name 中内核已复制的请求路径。该位置位于路径权限检查之前，因此可覆盖 EACCES。保留入口历史读取错误，未改写调用结果；不会在返回时猜测或重新读取可能已变化的用户字符串。

依据 Linux 6.6 fs/open.c 的 getname → do_filp_open 调用关系：https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux.git/+/refs/tags/v6.6/fs/open.c 。这是内核内部探针，当前面向 6.6/6.8；目标内核无法挂载时启动失败，不静默宣称补采可用。

## 数据兼容

事件 schema_version 保持 1。新增可选 path_source：kernel_filename、syscall_entry、unavailable。quality_flags 位 16 表示内核路径来源，本身不是错误；位 2 仍表示发生过读取错误。因此恢复成功可同时出现值 18。请求路径不等于解析后的绝对路径；相对路径、截断和对象身份能力边界仍然存在。不支持的路径不得推断为 /etc/shadow。请将采集器和分析器一起更新并重建。

## 验证

本地 WSL 6.6：编译和真实加载成功；59 项单元回归通过；五轮既有集成、12 项边界通过。专项 verify_denied_open.py 创建无害 root 所有的 000 权限文件，以 UID1000 从 bash 启动测试程序，分别验证 file-backed mmap 冷页面中的路径、普通拒绝访问以及无效指针。两个拒绝访问均正确生成 R01，路径为内核副本且保留 bash 祖先；无效指针不产生敏感访问告警；退出确认和质量计数正常。

首次专项脚本错误使用命名空间 PID 与 BPF 宿主 PID 比较，导致判定失败；原始记录中补采与告警已成功。脚本已改为按唯一执行路径映射 process_key，最终结果位于 out/path-fix-wsl-02/result.json。其他证据为 out/path-fix-unit.log、out/path-fix-integration-01/result.json、out/path-fix-edges-01/result.json。

这验证了入口路径读取失败的可复现场景，不足以反推旧 VMware 事件读取失败的唯一底层原因。原始 VMware 结果保持不变，旧空路径事件无法可靠回填。新增探针尚未做性能对照，不宣称修复了性能问题。

## VMware 更新

补丁包只含修复源码、回归脚本和本文档，不含 build 或旧 out。把包放到 /mnt/hgfs/share 后：

```bash
cd ~/ebpf-monitor-v3
tar -czf "out/before-path-fix-$(date +%Y%m%d-%H%M%S).tar.gz" bpf collector monitor schema scripts tests
tar -xzf /mnt/hgfs/share/v3-path-fix-20260927.tar.gz
bash scripts/build.sh -B
python3 -m unittest discover -s tests -v
sudo python3 scripts/verify_denied_open.py --out "out/path-fix-vm-$(date +%Y%m%d-%H%M%S)" --uid "$(id -u)"
```

最后应显示 passed:true 且所有 checks 为 true；随后重新进行原先 /etc/shadow 双终端演示。必须在 VMware 重建，不能使用本机 WSL 二进制。未取得目标机新结果前，状态为本地修复通过、VMware 待复验。
