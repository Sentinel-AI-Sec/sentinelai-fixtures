# Additional fixtures

Four more deliberately vulnerable applications, alongside the flagship fixture at the repository
root. **None of these is for production use.** Every secret, key, token and password in every one
of them is a dummy fixture value.

Each is self-contained — its own `src/`, its own infrastructure, its own `Dockerfile`, its own
`README.md` naming every planted issue and where it lives.

## Why these are here

The flagship fixture proves one chain: a vulnerable dependency reaching an unsafe deserialization
reaching an over-permissive IAM role reaching an S3 bucket. It proves it well, and it proves it
once. A single chain shape cannot show whether the reasoning generalises or whether it has been
fitted to one example.

These four vary the things that should not matter and hold constant the thing that should:

| | Chain shape | Infrastructure | Crown jewel |
|---|---|---|---|
| **Flagship** (root) | Deserialization → RCE | AWS / Terraform | Customer-data S3 bucket |
| **02** `payments-api` | SSRF → IMDS → credential theft | AWS / Terraform | Payment processor's live key |
| **03** `patient-portal` | Auth bypass → data at rest | **Azure** / Terraform | Patient documents |
| **04** `ci-runner` | Container escape → cluster takeover | **Kubernetes** manifests | Every secret in the cluster |
| **05** `iot-gateway` | Supply chain → fleet compromise | AWS / Terraform | Every device in the field |

What stays constant is that **the chain is always cross-layer** and **no single finding on it is
critical on its own**. That is the property under test.

## Why the code layer is C# in all five

Not a preference. The toolchain in `scripts/` runs Roslyn / Security Code Scan for the code
layer, and it only analyses C#. A Python or Node fixture would produce dependency findings (OSV)
and infrastructure findings (Checkov, Trivy) but **no code-layer findings at all** — so it could
not carry a cross-layer chain, which is the only thing these fixtures exist to exercise.

The infrastructure layer is where the real variation is, because Checkov and Trivy cover
Terraform, Kubernetes, CloudFormation and Dockerfiles equally well.

## What each one is designed to catch

Each fixture plants a specific failure of reasoning, not just a pile of vulnerabilities:

- **02 `payments-api`** — a **severity trap**. `RefundsController` carries a SQL injection that
  any scanner ranks at the top. It is not the shortest path to the ledger, because the database
  password is in the task definition in plaintext and the database is publicly addressable. A
  reasoner that ranks it above the SSRF chain has ranked on severity rather than reachability.

- **03 `patient-portal`** — **two paths, neither subsuming the other**. The forged-token chain
  reaches patient documents through the application; the storage container is anonymously
  readable and reaches them without it. Reporting only one is missing half the answer.

- **04 `ci-runner`** — **composition**. Every application behaviour is correct for a CI runner.
  Four separate manifest fields remove the boundary that made them safe. Remove any one and the
  incident is contained; all four together turn an untrusted zip into cluster-admin. It also
  plants a finding of **absence**: there is no NetworkPolicy anywhere, and nothing in any file is
  wrong.

- **05 `iot-gateway`** — **pairs that are only findings together**. A permissive bucket policy
  and a disabled public-access block are two mediums separately and one critical together,
  because neither works without the other. And a correctly locked-down bucket is still reachable
  because a role elsewhere holds a wildcard over it.

## Deliberate noise

Every fixture plants findings that are **genuine and unreachable** — an orphaned IAM role, a
build-time-only package, a correctly-configured resource nothing uses. They are there so that
"demoted correctly" can be told apart from "not detected", which a fixture with only true
positives cannot measure.

## Ground truth

These carry their planted-issue inventory in each `README.md` rather than in
`benchmark/ground_truth/`. That directory is the scored measurement corpus for SEC-38/SEC-39 and
carries a `.no-ingest` marker; adding these to it is a separate decision about what the
precision/recall headline is measured against, and not one to make by dropping files in.

## Totals

| Fixture | Code | Deps | Infra | Total |
|---|---:|---:|---:|---:|
| 02 `payments-api` | 12 | 5 | 18 | **35** |
| 03 `patient-portal` | 9 | 5 | 15 | **29** |
| 04 `ci-runner` | 7 | 5 | 18 | **30** |
| 05 `iot-gateway` | 8 | 5 | 13 | **26** |
| | | | | **120** |

Plus the flagship's 29 at the repository root: **149 planted issues across five fixtures.**
