# SentinelAI Demo Fixture (SEC-04)

Deliberately vulnerable three-layer app used to demo and regression-test
SentinelAI's cross-layer exploit-path reasoning. **Not for production use.**
All secrets/keys/passwords in this repo are dummy fixture values.

## Golden chain (must reconstruct end-to-end)

```
DEP-01 (Newtonsoft.Json 12.0.1, CVE)
  -> CODE-01 (OrdersController: CWE-502 unsafe deserialization)
  -> [image join: tinyapp/order, Dockerfile <-> main.tf, confidence=inferred]
  -> INFRA-01 (order_task_role: IAM s3:* wildcard, CWE-284, confidence=certain)
  -> S3 customer-data bucket (INFRA-02 no encryption, INFRA-03 public access, INFRA-04 no versioning)
```

## Deliberate unresolved edge

`legacy_worker_task` in `infra/main.tf` references `var.legacy_worker_image`,
which does not normalize to any Dockerfile image in this repo. This seam
should resolve to `graph_edges.confidence = "unresolved"`, surfaced by the
Reporter as "potential chain, unverified join" rather than dropped.

## Vulnerability inventory

### Code layer (14) — `src/OrderApp/`

Scanned by **Roslyn / Security Code Scan (SCS)** only — Semgrep has been
dropped from the toolchain (its C# coverage was thin anyway; SCS is the
analyzer that actually runs inside the real `dotnet build`).

| ID | CWE | Location | Detected by SCS? |
|----|-----|----------|-------------------|
| CODE-01 (flagship) | CWE-502 | Controllers/OrdersController.cs | ✅ `SCS0028` |
| CODE-02 | CWE-89 | Controllers/UsersController.cs | ✅ `SCS0026`/`SCS0002` |
| CODE-03 | CWE-79 | Controllers/ReportsController.cs | ✅ `SCS0029` |
| CODE-04 | CWE-798 | Services/AuthService.cs | ⚠️ partial — SCS has no dedicated hardcoded-secret rule; may not fire |
| CODE-05 | CWE-259 | Services/AuthService.cs | ⚠️ partial — same gap as CODE-04 |
| CODE-06 | CWE-327 | Services/AuthService.cs | ✅ `SCS0005`-family (weak crypto/RNG) |
| CODE-07 | CWE-347 | Services/AuthService.cs | ❌ not covered — JWT validation-bypass logic is outside SCS's rule set |
| CODE-08 | CWE-611 | Controllers/ReportsController.cs | ⚠️ partial — SCS has an XXE rule but coverage of `XmlReaderSettings` variants is inconsistent |
| CODE-09 | CWE-22 | Services/ExportService.cs | ✅ `SCS0018` |
| CODE-10 | CWE-918 | Controllers/ReportsController.cs | ❌ not covered — SSRF (outbound `HttpClient` to user input) isn't an SCS rule |
| CODE-11 | CWE-732 | Program.cs | ❌ not covered — file-permission calls aren't in scope for SCS |
| CODE-12 | CWE-209 | Controllers/OrdersController.cs | ❌ not covered — info-leakage-via-exception isn't an SCS rule |
| CODE-13 | CWE-284 | Controllers/UsersController.cs | ❌ not covered — missing `[Authorize]` is a config/architecture pattern, not a code-analyzer rule |
| CODE-13b | CWE-284 | Controllers/AdminController.cs | ❌ not covered — same as CODE-13 |

`Services/PricingService.cs` is deliberately clean — a distractor node.

> **Known gap, stated not papered over.** 6 of 14 code-layer vulns (CODE-04,
> 05, 07, 10, 11, 12, 13, 13b) sit outside Security Code Scan's rule
> coverage. This is expected — SCS is a Roslyn analyzer built for
> injection/crypto/deserialization-class bugs, not for authz/config/SSRF
> patterns. Options if full code-layer coverage matters for the demo:
> add a small custom Roslyn analyzer, add back Semgrep for just these
> categories, or explicitly scope the fixture's flagship narrative around
> the CWEs SCS *does* catch and document the rest as "detected by
> [future tool]" placeholders. No change needed for the golden chain —
> CODE-01 (the flagship) is solidly covered by `SCS0028`.

### Dependency layer (7) — `packages.lock.json`

| ID | Package (pinned) | Class |
|----|---|---|
| DEP-01 (flagship) | Newtonsoft.Json 12.0.1 | Deserialization |
| DEP-02 | System.Text.RegularExpressions 4.3.0 | ReDoS-class |
| DEP-03 | Microsoft.Data.SqlClient 2.1.1 | Known advisories |
| DEP-04 | Serilog.Sinks.File 4.1.0 | Info disclosure |
| DEP-05 | SixLabors.ImageSharp 1.0.4 | DoS/memory |
| DEP-06 | System.IdentityModel.Tokens.Jwt 6.10.0 | Pairs with CODE-07 |
| DEP-07 (noise) | Microsoft.CodeAnalysis.NetAnalyzers 6.0.0 | Build-time only, unreachable |

> Versions are pinned deliberately old; let Dependency-Check resolve the
> live NVD entries at scan time rather than hardcoding CVE IDs here.
> `packages.lock.json` contentHash fields are placeholders — run
> `dotnet restore` locally to regenerate real hashes before scanning.

### Infra layer (8) — `infra/`, `Dockerfile`

| ID | Resource | Issue |
|----|---|---|
| INFRA-01 (flagship) | aws_iam_role_policy.order_task_policy | Wildcard action + resource (CWE-284) |
| INFRA-02 | aws_s3_bucket.customer_data | No encryption at rest |
| INFRA-03 | aws_s3_bucket_public_access_block | Public access block disabled |
| INFRA-04 | aws_s3_bucket_versioning | Versioning disabled |
| INFRA-05 | aws_security_group.order_svc_sg | Ingress 0.0.0.0/0 |
| INFRA-06 | aws_ecs_task_definition.order_task | No log configuration |
| INFRA-07 | Dockerfile | Secret baked in via ENV (dummy value) |
| INFRA-08 | Dockerfile | No USER directive — runs as root |

`aws_s3_bucket.build_artifacts_orphan` and `legacy_worker_role` /
`legacy_worker_policy` are noise: real findings, but not reachable from
any hot seed, so Blue/Reporter should demote them rather than chain them.

## Running each tool independently

`scripts/` has one script per tool — each is fully standalone, writes its
own SARIF file into `scan_out/`, and prints a readable summary via
`scripts/view_sarif.py` (tolerant of SARIF v1/v2 shape differences). Run
any one on its own to debug that tool in isolation:

```bash
chmod +x scripts/*.sh
bash scripts/run_terraform_graph.sh   # -> scan_out/terraform-graph.dot
bash scripts/run_roslyn.sh            # -> scan_out/roslyn.sarif (also generates packages.lock.json)
bash scripts/run_osv.sh               # -> scan_out/osv.sarif (needs the lock file, so run roslyn first)
bash scripts/run_trivy.sh             # -> scan_out/trivy.sarif
bash scripts/run_checkov.sh           # -> scan_out/checkov_infra.sarif + scan_out/checkov_docker.sarif
```

Or inspect any SARIF file directly at any time, from any tool:

```bash
python3 scripts/view_sarif.py scan_out/roslyn.sarif
python3 scripts/view_sarif.py scan_out/trivy.sarif --max 20
```

`scripts/run_all.sh` just calls all five in the order their dependencies
require (Roslyn before OSV, terraform init before terraform graph) — it's
a convenience wrapper, not a separate mechanism; nothing about running
one tool depends on the others having run except that ordering.

## Next steps to make this scan-ready

1. `cd src/OrderApp && dotnet restore --use-lock-file` to generate real
   lock-file hashes (needed before OSV-Scanner runs).
2. `terraform init && terraform graph > terraform-graph.dot` in `infra/`.
3. Run the current toolchain and confirm each produces ≥1 finding:
   - **Roslyn / Security Code Scan** (code) — via `dotnet build` with
     `SecurityCodeScan.VS2019` installed and `/p:ErrorLog=...sarif`
   - **OSV-Scanner** (dep) — against `packages.lock.json`
   - **Trivy** (infra) — `trivy fs --scanners misconfig,vuln`
   - **Checkov** (infra) — run separately against `infra/` and `Dockerfile`
   - *(Semgrep removed from the toolchain — see the code-layer coverage
     note above for what that leaves uncovered.)*
4. Record the resulting golden chain JSON for the SEC-49 regression harness.
