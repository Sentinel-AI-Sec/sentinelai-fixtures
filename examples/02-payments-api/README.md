# Fixture 02 — `payments-api`

A card-payments service: ECS Fargate behind an ALB, a Postgres ledger, and the payment
processor's live key in Secrets Manager. **Not for production use.** Every secret, key and
password in this fixture is a dummy value.

**What it exercises that the flagship does not:** the pivot is *credential theft*, not remote
code execution. The flagship chain ends with an attacker running code; this one ends with an
attacker holding the account's secrets without ever executing anything.

## The chain

```
DEP-01  RestSharp 106.11.7 (follows redirects by default)
  ->  CODE-01  WebhooksController.VerifyCallback: CWE-918 SSRF, caller supplies the URL
  ->            fetches http://169.254.169.254/  (IMDS)  ->  task role credentials
  ->  [image join: fintech/payments, Dockerfile <-> infra/main.tf, confidence=inferred]
  ->  INFRA-01  payments_task_role: secretsmanager:GetSecretValue on Resource = "*"  (CWE-284)
  ->  prod/psp/live-key  (INFRA-10 no CMK, INFRA-11 no recovery window)
```

Four things have to be true at once for this to work, and each is a separate finding that looks
survivable on its own:

1. the callback URL is attacker-controlled and unvalidated (CODE-01),
2. the HTTP client follows redirects, so a first-hop allow-list would not have saved it (DEP-01),
3. the task has a public IP, so the SSRF is reachable from the internet (INFRA-06),
4. the role it steals can read every secret, not just the one this service uses (INFRA-01).

That is the fixture's whole argument: a scanner reports four medium findings, and the composition
is critical.

## The second cluster — deliberately *not* the answer

`RefundsController` carries a SQL injection (CODE-07), an IDOR (CODE-08) and a business-logic
flaw (CODE-09). A severity-ranked list puts the SQL injection at the top. It reaches the ledger,
which is bad — but the ledger password is already in the task definition in plaintext (INFRA-05)
and the database is publicly addressable (INFRA-13), so the injection is not the shortest path to
that data. **A reasoner that ranks CODE-07 above the SSRF chain has ranked on severity rather
than on reachability**, which is the failure mode this cluster exists to catch.

## Deliberate noise

- `orphaned_batch_role` in `infra/iam.tf` — `s3:*` on `*`, reachable from nothing in this stack.
- `DEP-05` `Microsoft.CodeAnalysis.NetAnalyzers` — build-time only, never shipped.
- `DEP-03` YamlDotNet — a real advisory, on a code path no request reaches.

All three are genuine findings that should be **demoted, not chained**.

## Where the issues are

### Code — `src/PaymentsApi/`

| ID | CWE | File | Issue |
|----|-----|------|-------|
| **CODE-01** | CWE-918 | `Controllers/WebhooksController.cs` | **Flagship.** SSRF — caller-supplied callback URL fetched with no allow-list or scheme check |
| CODE-02 | CWE-200 | `Controllers/WebhooksController.cs` | Fetched response body returned to the caller, making the service an open proxy |
| CODE-03 | CWE-117 | `Controllers/WebhooksController.cs` | Log injection — unencoded URL written to the log |
| CODE-04 | CWE-330 | `Controllers/WebhooksController.cs` | Replay token from `Random` seeded on `TickCount` |
| CODE-05 | CWE-327 | `Services/SecretsClient.cs` | MD5 used to "sign" webhook payloads |
| CODE-06 | CWE-208 | `Services/SecretsClient.cs` | Non-constant-time signature comparison |
| CODE-07 | CWE-89 | `Controllers/RefundsController.cs` | SQL injection on `merchantRef` |
| CODE-08 | CWE-639 | `Controllers/RefundsController.cs` | IDOR — any merchant can refund any payment |
| CODE-09 | CWE-841 | `Controllers/RefundsController.cs` | Refund amount never checked against the original charge |
| CODE-10 | CWE-16 | `Program.cs` | Developer exception page enabled unconditionally |
| CODE-11 | CWE-942 | `Program.cs` | CORS allows any origin *with* credentials |
| CODE-12 | CWE-798 | `appsettings.json` | Database credentials in a checked-in config file |

### Dependencies — `src/PaymentsApi/PaymentsApi.csproj`

| ID | Package | Why |
|----|---------|-----|
| **DEP-01** | RestSharp 106.11.7 | **Flagship.** Redirect-following is what defeats a first-hop URL check |
| DEP-02 | Microsoft.Data.SqlClient 2.1.1 | Known advisories; pairs with CODE-07 |
| DEP-03 | YamlDotNet 5.3.0 | Deserialization advisories — unreachable in this app |
| DEP-04 | BouncyCastle 1.8.5 | Known advisories; second crypto signal beside CODE-05 |
| DEP-05 | Microsoft.CodeAnalysis.NetAnalyzers 6.0.0 | **Noise** — build-time only |

### Infrastructure — `infra/` and `Dockerfile`

| ID | CWE | File | Issue |
|----|-----|------|-------|
| **INFRA-01** | CWE-284 | `infra/iam.tf` | **Flagship.** `secretsmanager:GetSecretValue` on `Resource = "*"` |
| INFRA-02 | CWE-269 | `infra/iam.tf` | `sts:AssumeRole` on `*` — one credential becomes lateral movement |
| INFRA-03 | CWE-732 | `infra/iam.tf` | CI user with `AdministratorAccess` attached directly |
| INFRA-04 | CWE-778 | `infra/main.tf` | Container Insights disabled |
| INFRA-05 | CWE-798 | `infra/main.tf` | DB password as a plaintext task-definition env var |
| INFRA-06 | CWE-668 | `infra/main.tf` | `assign_public_ip = true` — makes the SSRF internet-reachable |
| INFRA-07 | CWE-284 | `infra/main.tf` | Security group open to `0.0.0.0/0` on 8080 **and** 5432 |
| INFRA-08 | CWE-319 | `infra/main.tf` | ALB listener on plain HTTP |
| INFRA-09 | CWE-778 | `infra/main.tf` | ALB access logs disabled |
| INFRA-10 | CWE-311 | `infra/data.tf` | Secret has no customer-managed key |
| INFRA-11 | CWE-404 | `infra/data.tf` | Secret recovery window set to 0 |
| INFRA-12 | CWE-311 | `infra/data.tf` | RDS storage not encrypted |
| INFRA-13 | CWE-668 | `infra/data.tf` | RDS `publicly_accessible = true` |
| INFRA-14 | CWE-778 | `infra/data.tf` | No RDS log exports |
| INFRA-15 | — | `infra/data.tf` | Backups disabled (`backup_retention_period = 0`) |
| INFRA-16 | CWE-778 | `infra/data.tf` | CloudTrail present but `enable_logging = false` |
| INFRA-17 | CWE-798 | `Dockerfile` | PSP key baked into the image via `ENV` |
| INFRA-18 | CWE-250 | `Dockerfile` | No `USER` directive — runs as root |

**Total: 12 code + 5 dependency + 18 infrastructure = 35 planted issues.**

## What the toolchain actually detects

Measured by building each project with Security Code Scan and reading NuGet's own advisory
warnings — not predicted.

| Planted | Detected? | By what |
|---|---|---|
| **CODE-01 SSRF (flagship)** | ❌ **No** | SCS has no SSRF rule. The flagship code vulnerability of this fixture is a **false-negative probe** — it is exactly the finding a cross-layer reasoner has to infer from the chain rather than read off a scanner |
| CODE-04 weak RNG | ✅ | `SCS0005` |
| CODE-07 SQL injection | ✅ | `SCS0002` |
| DEP-01 RestSharp 106.11.7 | ✅ | `GHSA-9pq7-rcxv-47vq` (high) |
| DEP-02 Microsoft.Data.SqlClient 2.1.1 | ✅ | `GHSA-98g6-xh36-x2p7` (high) |
| DEP-04 BouncyCastle 1.8.5 | ✅ | four moderate advisories |

Everything else in the code table is outside SCS's rule set (authorization logic, business rules,
CORS and framework configuration). That is the honest position, and it is the reason this fixture
is interesting: **the highest-severity finding in it is one no scanner reports.**

## The load-bearing detail

`Dockerfile`'s `LABEL org.sentinelai.image="fintech/payments"` must normalize to the same
coordinate as `infra/main.tf`'s container image field
(`registry.hub.docker.com/fintech/payments:2.1.0`). Strip the registry prefix and the tag and
both read `fintech/payments`. Remove the label and the code→infra seam has nothing to compare,
the chain breaks silently, and every individual finding still reports — which is exactly the
failure the flagship fixture's own README warns about.
