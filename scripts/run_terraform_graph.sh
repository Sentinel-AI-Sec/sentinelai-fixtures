#!/usr/bin/env bash
# Run ONLY terraform init + terraform graph.
# Produces: scan_out/terraform-graph.dot
# (Not a "vulnerability" scanner, but treated the same way - one
# independent, inspectable output, run on its own.)
set -uo pipefail
cd "$(dirname "$0")/.."   # repo root

mkdir -p scan_out

if ! command -v terraform >/dev/null 2>&1; then
  echo "=== terraform not installed - install it first (see README) ==="
  exit 1
fi

echo "=== terraform version ==="
terraform -version

cd infra
echo "=== terraform init ==="
terraform init -input=false

echo "=== terraform graph ==="
terraform graph > ../scan_out/terraform-graph.dot
cd ..

echo "=== OK: scan_out/terraform-graph.dot written ==="
echo "--- first 20 lines ---"
head -20 scan_out/terraform-graph.dot
