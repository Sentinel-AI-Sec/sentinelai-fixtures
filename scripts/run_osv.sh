#!/usr/bin/env bash
# Run ONLY OSV-Scanner against the fixture's lockfile.
# Produces: scan_out/osv.sarif
set -uo pipefail
cd "$(dirname "$0")/.."

mkdir -p scan_out
LOCK="src/OrderApp/packages.lock.json"
BIN="scripts/.tools/osv-scanner.exe"

if [ ! -f "$LOCK" ]; then
  echo "=== $LOCK not found - run scripts/run_roslyn.sh first (it generates it) ==="
  exit 1
fi

if [ ! -f "$BIN" ]; then
  echo "=== $BIN not found ==="
  echo "Download it manually from:"
  echo "  https://github.com/google/osv-scanner/releases/download/v2.3.8/osv-scanner_windows_amd64.exe"
  echo "Save it as: $BIN"
  exit 1
fi

echo "=== osv-scanner version ==="
"$BIN" --version

echo "=== scanning lockfile ==="
rm -f scan_out/osv.sarif
"$BIN" --format sarif --output-file scan_out/osv.sarif --lockfile "$LOCK"
RC=$?
echo "osv-scanner exit code: $RC (1 = vulns found, expected here)"

if [ -f scan_out/osv.sarif ]; then
  echo "=== OK: scan_out/osv.sarif written ==="
  "/c/Users/PC_STORE/AppData/Local/Python/bin/python.exe" scripts/view_sarif.py scan_out/osv.sarif
else
  echo "=== FAILED: no osv.sarif produced ==="
  exit 1
fi