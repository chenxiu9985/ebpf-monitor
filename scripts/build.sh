#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
tool="${BPFTOOL:-}"
if [[ -z "$tool" ]]; then
    if bpftool version >/dev/null 2>&1; then
        tool="$(command -v bpftool)"
    else
        tool="$(find /usr/lib/linux-tools* -name bpftool \( -type f -o -type l \) 2>/dev/null | sort -V | tail -n 1)"
    fi
fi
if [[ -z "$tool" ]]; then
    echo "bpftool unavailable; install linux-tools-common and linux-tools-generic" >&2
    exit 1
fi
make BPFTOOL="$tool" "$@"
