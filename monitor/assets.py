"""Startup authorization manifest; targets are discovered by the kernel later."""
from pathlib import Path


def write_manifest(config, path):
    lines = []
    for kind, field in (("object", "sensitive_paths"), ("service", "service_executables")):
        paths = list(dict.fromkeys(config[field]))
        if not 1 <= len(paths) <= 64:
            raise ValueError(f"automatic response requires 1..64 {field}")
        for index, value in enumerate(paths, 1):
            if not value.startswith("/") or len(value.encode()) >= 256 or any(c in value for c in "\t\r\n\0"):
                raise ValueError(f"invalid registry path: {value!r}")
            lines.append(f"{kind}\t{index}\t{value}\n")
    Path(path).write_text("".join(lines), encoding="utf-8")
