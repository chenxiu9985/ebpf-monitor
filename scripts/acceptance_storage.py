"""Disk budgets and failure-preserving archival for live acceptance."""
import json
import shutil
from pathlib import Path


RESERVE_BYTES = 512 * 1024 * 1024
BYTES_PER_OPEN_BUDGET = 8192


def required_storage(seconds, rate):
    # Estimate, not a promise: database, indexes, WAL and retained logs all count.
    return seconds * rate * BYTES_PER_OPEN_BUDGET + RESERVE_BYTES


def check_storage(path, required=RESERVE_BYTES):
    free = shutil.disk_usage(path).free
    if free < required:
        raise OSError(f"Insufficient free space at {path}: {free / 2**30:.2f} GiB free, "
                      f"{required / 2**30:.2f} GiB budget required; test stopped before disk exhaustion")
    return free


def save_result(path, result):
    try:
        Path(path).write_text(json.dumps(result, indent=2), encoding="utf-8")
        return True
    except OSError as exc:
        print(f"Cannot save {path}: {exc}", flush=True)
        print(json.dumps(result, indent=2), flush=True)
        return False


def archive_results(source, destination):
    source, destination = Path(source), Path(destination)
    if destination.exists():
        raise FileExistsError(destination)
    if source.stat().st_dev == destination.parent.stat().st_dev:
        # Same filesystem: no second full copy of an hours-long database.
        source.rename(destination)
        return "rename"
    size = sum(p.stat().st_size for p in source.rglob("*") if p.is_file())
    check_storage(destination.parent, size + RESERVE_BYTES)
    shutil.copytree(source, destination)
    # Caller cleans source only after archival and metadata both succeed.
    return "copy"
