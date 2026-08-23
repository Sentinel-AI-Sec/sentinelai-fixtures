# Fixture 03 — `patient-portal`

A clinician-and-patient portal on **Azure**: a container group, a SQL server holding records, and
a Storage account holding scanned documents and imaging. **Not for production use.** Every
secret, key and password in this fixture is a dummy value.

**What it exercises that the others do not:** the target is *data at rest*, not code execution or
credential theft — and the fixture's whole argument is that the chain is not the only way in.

## The chain

```
DEP-01  System.IdentityModel.Tokens.Jwt 6.10.0
  ->  CODE-01  TokenValidator.Validate: CWE-347, signature verification disabled
  ->            forged token with role=clinician  ->  authorization passes
  ->  CODE-05  RecordsController.GetDocument: CWE-22 path traversal out of the patient prefix
  ->  [image join: health/patient-portal, Dockerfile <-> infra/main.tf, confidence=inferred]
  ->  INFRA-01  patient_documents container: container_access_type = "container"  (CWE-284)
  ->  every patient document, readable anonymously
```

## The point of this fixture

**The chain is the long way round.** `INFRA-01` sets the documents container to
`container_access_type = "container"`, which means anonymous read of the blobs *and* the listing.
An attacker who learns the storage account name downloads every document without a token, forged
or otherwise — no JWT, no traversal, no application involved at all.

So there are two paths to the same data, and they differ in what they need:

| Path | Requires | Findings involved |
|---|---|---|
| Through the app | Knowing the portal URL, forging a token | DEP-01 + CODE-01 + CODE-05 |
| Direct to storage | Knowing the account name | INFRA-01 alone |

A reasoner that reports only the chain has found the *harder* attack and missed the easier one.
One that reports only INFRA-01 has missed that the application is independently broken. **Both are
real and neither subsumes the other** — that is what this fixture is for, and it is why `CODE-01`
and `INFRA-01` are both marked flagship.

## Where the issues are

### Code — `src/PatientPortal/`

| ID | CWE | File | Issue |
|----|-----|------|-------|
| **CODE-01** | CWE-347 | `Services/TokenValidator.cs` | **Flagship.** JWT signature not verified — `RequireSignedTokens = false` |
| CODE-02 | CWE-613 | `Services/TokenValidator.cs` | Token lifetime not validated — a leaked token never expires |
| CODE-03 | CWE-798 | `Services/TokenValidator.cs` | Hardcoded signing-key fallback when config is empty |
| CODE-04 | CWE-611 | `Controllers/RecordsController.cs` | XXE — `DtdProcessing.Parse` with an `XmlUrlResolver` |
| CODE-05 | CWE-22 | `Controllers/RecordsController.cs` | Path traversal out of the patient's blob prefix |
| CODE-06 | CWE-532 | `Controllers/RecordsController.cs` | NHS number and date of birth written to the application log |
| CODE-07 | CWE-798 | `Services/BlobArchive.cs` | Storage account key hardcoded as a fallback |
| CODE-08 | CWE-319 | `Program.cs` | No HTTPS redirection |
| CODE-09 | CWE-798 | `appsettings.json` | Storage connection string in a checked-in config file |

### Dependencies — `src/PatientPortal/PatientPortal.csproj`

| ID | Package | Why |
|----|---------|-----|
| **DEP-01** | System.IdentityModel.Tokens.Jwt 6.10.0 | **Flagship.** The library CODE-01 misconfigures |
| DEP-02 | Azure.Storage.Blobs 12.8.0 | Old SDK on the archive path |
| DEP-03 | HtmlSanitizer 5.0.372 | Bypass advisories — genuinely reachable, clinician notes render as HTML |
| DEP-04 | iTextSharp 5.5.13.1 | XXE history; second signal beside CODE-04 |
| DEP-05 | FluentAssertions 5.10.3 | **Noise** — test-only, never shipped |

### Infrastructure — `infra/` and `Dockerfile`

| ID | CWE | File | Issue |
|----|-----|------|-------|
| **INFRA-01** | CWE-284 | `infra/storage.tf` | **Flagship.** Documents container is `container` — anonymous read *and* listing |
| INFRA-02 | CWE-319 | `infra/storage.tf` | `enable_https_traffic_only = false` |
| INFRA-03 | CWE-326 | `infra/storage.tf` | `min_tls_version = "TLS1_0"` |
| INFRA-04 | CWE-284 | `infra/storage.tf` | Storage reachable from the public internet, no network rules |
| INFRA-05 | CWE-319 | `infra/main.tf` | Container group public on port 80 |
| INFRA-06 | CWE-798 | `infra/main.tf` | Storage key as a plaintext environment variable |
| INFRA-07 | CWE-284 | `infra/main.tf` | SQL server public network access enabled |
| INFRA-08 | CWE-532 | `infra/storage.tf` | Log container anonymously readable at blob level |
| INFRA-09 | CWE-404 | `infra/storage.tf` | Blob soft-delete disabled (`days = 0`) |
| INFRA-10 | CWE-778 | `infra/main.tf` | No diagnostic settings — container stdout retained nowhere |
| INFRA-11 | CWE-311 | `infra/main.tf` | SQL minimum TLS version 1.0 |
| INFRA-12 | CWE-284 | `infra/main.tf` | SQL firewall rule spanning `0.0.0.0`–`255.255.255.255` |
| INFRA-13 | CWE-1188 | `infra/main.tf` | Key Vault provisioned, purge protection off, and **wired to nothing** |
| INFRA-14 | CWE-250 | `Dockerfile` | No `USER` directive — runs as root |
| INFRA-15 | CWE-1104 | `Dockerfile` | Base image pinned only to a major tag |

**Total: 9 code + 5 dependency + 15 infrastructure = 29 planted issues.**

## Deliberate noise

- `staging_unused` container in `infra/storage.tf` — correctly private, holds nothing, used by
  nothing. Present so "configured correctly" is distinguishable from "not configured".
- `DEP-05` FluentAssertions — test-only, never shipped.
- `INFRA-13` is the interesting one: a Key Vault that is *provisioned properly enough to look
  like a control* while the secret it should hold sits in an environment variable two resources
  away. A finding about a resource's own settings misses the point; the finding is the gap
  between it and `INFRA-06`.

## What the toolchain actually detects

Measured, not predicted.

| Planted | Detected? | By what |
|---|---|---|
| **CODE-01 JWT signature not verified (flagship)** | ❌ **No** | SCS has no rule for disabled token validation. A **false-negative probe** — and the single most consequential line in the fixture |
| CODE-04 XXE | ✅ | `SCS0007` |
| DEP-01 System.IdentityModel.Tokens.Jwt 6.10.0 | ✅ | NuGet advisory |
| **INFRA-01 public storage container** | ✅ | Checkov, on the Terraform |

The split here is the whole point. The infrastructure half of the chain is loudly reported by any
IaC scanner; the code half is silent. A tool that reports only what it can pattern-match tells you
the container is public and never tells you the application authenticating against it is broken.

## The load-bearing detail

`Dockerfile`'s `LABEL org.sentinelai.image="health/patient-portal"` must normalize to the same
coordinate as `infra/main.tf`'s container image
(`registry.hub.docker.com/health/patient-portal:1.9.0`). Remove the label and the code→infra seam
has nothing to compare, and the chain silently degrades to two unrelated clusters of findings.
