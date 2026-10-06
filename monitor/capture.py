"""Conservative static storage filter; does not claim to reduce probe/ring cost."""
from collections import OrderedDict


class CapturePlan:
    def __init__(self, config):
        self.config = config
        self.loading = OrderedDict()
        self.filtered = 0
        self.considered = 0

    def keep(self, event, sensitive_objects):
        self.considered += 1
        kind, key = event["event_type"], event.get("process_key")
        if kind == "process_exec":
            self.loading.pop(key, None)
            if any(event.get("env", {}).values()):
                self.loading[key] = event.get("exec_token", 0)
                if len(self.loading) > self.config["max_processes"]:
                    self.loading.popitem(last=False)
        if kind == "thread_exit" and event.get("process_dead"):
            self.loading.pop(key, None)
        if self.config["capture_profile"] == "full" or kind != "file_open":
            return True
        # Unknown capture fields and all loading-related opens are retained.
        keep = bool(event.get("quality_flags", 0) & ~16 or
                    (key in self.loading and self.loading[key] == event.get("exec_token", 0)) or
                    event.get("path") in {*self.config["sensitive_paths"], self.config["preload_config"]} or
                    (event.get("device", 0), event.get("inode", 0)) in sensitive_objects)
        if not keep:
            self.filtered += 1
        return keep
