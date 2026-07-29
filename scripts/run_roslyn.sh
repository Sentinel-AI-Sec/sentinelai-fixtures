#!/usr/bin/env bash
# Run ONLY Roslyn / Security Code Scan against the fixture app.
# Produces: scan_out/roslyn.sarif
set -uo pipefail
cd "$(dirname "$0")/.."   # repo root

mkdir -p scan_out
export PATH="/usr/share/dotnet:$PATH"
export DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1

echo "=== dotnet --version ==="
dotnet --version || { echo "dotnet SDK not found - install it first"; exit 1; }

cd src/OrderApp

echo "=== adding SecurityCodeScan.VS2019 analyzer ==="
dotnet add OrderApp.csproj package SecurityCodeScan.VS2019 --version 5.6.7

echo "=== restore (with lock file, so OSV can use it later) ==="
dotnet restore OrderApp.csproj --use-lock-file

echo "=== build with SARIF error log ==="
rm -f ../../scan_out/roslyn.sarif
# NOTE: use -p: (not /p:) - Git Bash/MSYS on Windows mangles arguments that
# start with "/" (it tries to convert them as Unix paths), which silently
# strips the leading slash and breaks MSBuild switch parsing
# (-> "MSB1008: Only one project can be specified"). -p: is accepted by
# dotnet build identically on Windows, Linux, and WSL.
dotnet build OrderApp.csproj --no-restore --nologo -v quiet \
  "-p:ErrorLog=../../scan_out/roslyn.sarif%3Bversion%3D2.1" \
  -p:RunAnalyzersDuringBuild=true \
  -p:TreatWarningsAsErrors=false

cd ../..

if [ -f scan_out/roslyn.sarif ]; then
  echo "=== OK: scan_out/roslyn.sarif written ==="
  python3 scripts/view_sarif.py scan_out/roslyn.sarif
else
  echo "=== FAILED: no roslyn.sarif produced ==="
  exit 1
fi