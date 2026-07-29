#!/usr/bin/env bash
# Run ONLY Checkov - once against Terraform, once against the Dockerfile.
# Produces: scan_out/checkov_infra.sarif, scan_out/checkov_docker.sarif
set -uo pipefail
cd "$(dirname "$0")/.."

mkdir -p scan_out
PY="/c/Users/PC_STORE/AppData/Local/Python/bin/python.exe"

echo "=== ensuring checkov is installed ==="
"$PY" -m pip install -q checkov

echo "=== checkov version ==="
"$PY" -m checkov --version

echo "=== scanning infra/ (Terraform) ==="
rm -rf scan_out/checkov_infra
"$PY" -m checkov -d infra --output sarif --output-file-path scan_out/checkov_infra

echo "=== scanning Dockerfile ==="
rm -rf scan_out/checkov_docker
"$PY" -m checkov -f Dockerfile --output sarif --output-file-path scan_out/checkov_docker

for pair in "checkov_infra:checkov_infra.sarif" "checkov_docker:checkov_docker.sarif"; do
  d="${pair%%:*}"; name="${pair##*:}"
  src="scan_out/$d/results_sarif.sarif"
  if [ -f "$src" ]; then
    cp "$src" "scan_out/$name"
  fi
done

for f in scan_out/checkov_infra.sarif scan_out/checkov_docker.sarif; do
  if [ -f "$f" ]; then
    echo "=== OK: $f written ==="
    "$PY" scripts/view_sarif.py "$f"
  else
    echo "=== missing: $f ==="
  fi
done