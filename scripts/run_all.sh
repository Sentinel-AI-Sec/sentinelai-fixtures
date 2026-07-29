#!/usr/bin/env bash
# Convenience only - runs each tool's OWN script, one at a time, in the
# order that satisfies their dependencies (Roslyn before OSV needs the
# lockfile; terraform init before terraform graph).
# You can just as easily run any single script below on its own.
set -uo pipefail
cd "$(dirname "$0")/.."

echo "############ 1/5 terraform ############"
bash scripts/run_terraform_graph.sh

echo "############ 2/5 roslyn ############"
bash scripts/run_roslyn.sh

echo "############ 3/5 osv-scanner ############"
bash scripts/run_osv.sh

echo "############ 4/5 trivy ############"
bash scripts/run_trivy.sh

echo "############ 5/5 checkov ############"
bash scripts/run_checkov.sh

echo
echo "=== all scan_out/ files ==="
ls -la scan_out/
