#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p out
python3 -m monitor doctor > out/target-environment.json
uname -a
id
free -h
dpkg-query -W clang libbpf-dev python3-yaml bpfcc-tools 2>/dev/null || true
cat out/target-environment.json
echo "Static checks are not a load test. Next: bash scripts/build.sh; python3 scripts/integration.py --out out/target-integration-01"
