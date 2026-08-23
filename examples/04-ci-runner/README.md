# Fixture 04 — `ci-runner`

A build runner on **Kubernetes**: three replicas in a `ci` namespace, unpacking artifacts and
executing pipeline steps. **Not for production use.** Every token and credential in this fixture
is a dummy value.

**What it exercises that the others do not:** the infrastructure layer is Kubernetes manifests
rather than Terraform, and the chain is a **container escape** — the application never touches the
crown jewels itself, it escapes the boundary that was supposed to contain it.

## The chain

```
DEP-01  SharpZipLib 1.2.0 (zip-slip advisory: entry paths are not constrained)
  ->  CODE-01  ArtifactExtractor.ExtractAsync: CWE-22, entry name joined with no containment check
  ->  [image join: ci/build-runner, Dockerfile <-> k8s/runner-deployment.yaml, confidence=inferred]
  ->  INFRA-01  privileged: true  +  INFRA-10  hostPath / mounted read-write at /host
  ->            traversal writes to the NODE's filesystem, not the container's
  ->  INFRA-02  ServiceAccount bound to cluster-admin  (CWE-269)
  ->  every secret in every namespace
```

## The point of this fixture

**Every application behaviour here is correct for a CI runner.** Unpacking archives is the job.
Executing commands is the job. Neither is a finding in isolation — a runner that refused to do
them would be a runner that does nothing.

What makes them catastrophic is the boundary, and the manifest removes it four separate times:

| Removal | Field | Effect |
|---|---|---|
| Isolation | `privileged: true` | All capabilities, node devices, no seccomp |
| Filesystem | `hostPath: /` mounted at `/host` | The traversal's destination is the node |
| Namespaces | `hostNetwork` + `hostPID` | Kubelet and every process on the node are reachable |
| Identity | `cluster-admin` binding | The projected token is the cluster's root credential |

**Remove any one of them and the chain is a serious but contained incident. All four together
turn an untrusted zip file into cluster-admin.** That composition is what the fixture is for.

There is also a **second, independent escape** that does not use the traversal at all: `INFRA-11`
mounts the container runtime socket, so anything running in the pod can start a new container
with any mount and any privilege. A reasoner that reports only the zip-slip path has found one of
two routes to the same outcome.

## Where the issues are

### Code — `src/BuildRunner/`

| ID | CWE | File | Issue |
|----|-----|------|-------|
| **CODE-01** | CWE-22 | `Services/ArtifactExtractor.cs` | **Flagship.** Zip slip — entry name joined onto the workspace with no containment check |
| CODE-02 | CWE-377 | `Services/ArtifactExtractor.cs` | Predictable, world-writable staging path |
| CODE-03 | CWE-400 | `Services/ArtifactExtractor.cs` | No bound on entry count, size or expansion — zip bomb |
| CODE-04 | CWE-78 | `Controllers/JobsController.cs` | Command injection — build step from the request body into `/bin/sh -c` |
| CODE-05 | CWE-306 | `Controllers/JobsController.cs` | No authentication on any endpoint |
| CODE-06 | CWE-552 | `Controllers/JobsController.cs` | Workspace browse endpoint, path not constrained |
| CODE-07 | CWE-295 | `Services/ClusterClient.cs` | TLS certificate validation disabled for API-server calls |

### Dependencies — `src/BuildRunner/BuildRunner.csproj`

| ID | Package | Why |
|----|---------|-----|
| **DEP-01** | SharpZipLib 1.2.0 | **Flagship.** Zip-slip advisory — the same defect as CODE-01, seen from the library's side |
| DEP-02 | KubernetesClient 6.0.16 | Old in-cluster client on the token path |
| DEP-03 | Newtonsoft.Json 12.0.1 | Deserialization advisories — reachable, job payloads are JSON |
| DEP-04 | SharpCompress 0.22.0 | Path-traversal history; second signal beside DEP-01 |
| DEP-05 | BenchmarkDotNet 0.12.1 | **Noise** — build-time only |

### Infrastructure — `k8s/` and `Dockerfile`

| ID | CWE | File | Issue |
|----|-----|------|-------|
| **INFRA-01** | CWE-250 | `k8s/runner-deployment.yaml` | **Flagship.** `privileged: true` |
| **INFRA-02** | CWE-269 | `k8s/runner-rbac.yaml` | **Flagship.** ServiceAccount bound to `cluster-admin` |
| INFRA-03 | CWE-1108 | `k8s/runner-deployment.yaml` | `automountServiceAccountToken: true` |
| INFRA-04 | CWE-653 | `k8s/runner-deployment.yaml` | `hostNetwork: true` |
| INFRA-05 | CWE-653 | `k8s/runner-deployment.yaml` | `hostPID: true` |
| INFRA-06 | CWE-250 | `k8s/runner-deployment.yaml` | `runAsUser: 0`, `allowPrivilegeEscalation: true` |
| INFRA-07 | CWE-732 | `k8s/runner-deployment.yaml` | Writable root filesystem |
| INFRA-08 | CWE-250 | `k8s/runner-deployment.yaml` | `SYS_ADMIN`, `NET_ADMIN`, `SYS_PTRACE` added |
| INFRA-09 | CWE-798 | `k8s/runner-deployment.yaml` | Registry push token as a literal env var |
| INFRA-10 | CWE-552 | `k8s/runner-deployment.yaml` | `hostPath: /` mounted read-write at `/host` |
| INFRA-11 | CWE-552 | `k8s/runner-deployment.yaml` | Container runtime socket mounted — a second, independent escape |
| INFRA-12 | CWE-770 | `k8s/runner-deployment.yaml` | No resource limits — CODE-03 takes down the node |
| INFRA-13 | CWE-732 | `k8s/runner-rbac.yaml` | Cluster-wide `get/list/watch` on all secrets — reads scoped, is not |
| INFRA-14 | CWE-668 | `k8s/runner-service.yaml` | `LoadBalancer` — exposes CODE-05's unauthenticated API publicly |
| INFRA-15 | CWE-1188 | `k8s/runner-service.yaml` | **No NetworkPolicy anywhere** — a finding of absence, not of value |
| INFRA-16 | CWE-798 | `k8s/runner-service.yaml` | Registry credential base64-encoded in a checked-in Secret |
| INFRA-17 | CWE-250 | `Dockerfile` | No `USER` directive |
| INFRA-18 | CWE-829 | `Dockerfile` | Docker CLI installed into the runtime image — the tooling that makes INFRA-11 usable |

**Total: 7 code + 5 dependency + 18 infrastructure = 30 planted issues.**

## The hardest one to find

`INFRA-15` is an **absence**. There is no NetworkPolicy in `k8s/`, so every pod in the cluster can
reach every other pod. Nothing in any file is wrong; the finding is that a file which should
exist does not. Rule-based scanners generally check the values of resources that are present, and
this is deliberately outside that shape.

## What the toolchain actually detects

Measured, not predicted. This fixture is the one the scanner does best on.

| Planted | Detected? | By what |
|---|---|---|
| **CODE-01 zip slip (flagship)** | ✅ | `SCS0018` path traversal |
| CODE-04 command injection | ✅ | `SCS0001` |
| CODE-06 workspace browse traversal | ✅ | `SCS0018` |
| CODE-07 TLS validation disabled | ✅ | `SCS0004` |
| **DEP-01 SharpZipLib 1.2.0** | ✅ | `GHSA-m22m-h4rf-pwq3` (high) — the zip-slip advisory itself |
| DEP-03 Newtonsoft.Json 12.0.1 | ✅ | `GHSA-5crp-9r3c-p9vr` (high) |
| INFRA-01…12 pod security | ✅ | Checkov, on the manifests |
| **INFRA-15 missing NetworkPolicy** | ❌ **No** | A finding of *absence*. Nothing in any file is wrong |

So almost every individual finding is reported — and that is exactly why this fixture matters. A
scanner produces a long list of true positives here and still does not say *"an untrusted zip file
becomes cluster-admin"*, because that sentence is about how four of them compose.

## The load-bearing detail

`Dockerfile`'s `LABEL org.sentinelai.image="ci/build-runner"` must normalize to the same
coordinate as the deployment's container image
(`registry.hub.docker.com/ci/build-runner:4.2.0`). Without it the code→infra seam has nothing to
compare, and the fixture degrades into "an app with a path traversal" and "a badly configured
pod" as two unrelated clusters — which is precisely the reading the product exists to beat.
