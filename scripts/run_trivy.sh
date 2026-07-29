#!/usr/bin/env bash
# Run ONLY Trivy against the whole fixture repo (misconfig + vuln scanners).
# Produces: scan_out/trivy.sarif
set -uo pipefail
cd "$(dirname "$0")/.."   # repo root

mkdir -p scan_out

if ! command -v trivy >/dev/null 2>&1; then
  echo "=== trivy not installed - installing ==="
  curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin
fi

echo "=== trivy version ==="
trivy --version

echo "=== scanning repo (misconfig + vuln) ==="
rm -f scan_out/trivy.sarif
trivy fs --scanners misconfig,vuln --format sarif -o scan_out/trivy.sarif .

if [ -f scan_out/trivy.sarif ]; then
  echo "=== OK: scan_out/trivy.sarif written ==="
  python3 scripts/view_sarif.py scan_out/trivy.sarif
else
  echo "=== FAILED: no trivy.sarif produced ==="
  exit 1
fi
