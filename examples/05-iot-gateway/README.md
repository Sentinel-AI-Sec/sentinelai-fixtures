# Fixture 05 — `iot-gateway`

A device gateway for a fleet of field hardware: registration, telemetry, and the firmware update
channel the whole fleet installs from. **Not for production use.** Every key and credential in
this fixture is a dummy value.

**What it exercises that the others do not:** the target is not this system. It is every device
downstream of it. This is a **supply-chain** chain — the attacker compromises the update channel
and the fleet installs the payload itself.

## The chain

```
DEP-01  System.Private.Xml 4.3.0 (external-entity advisories)
  ->  CODE-01  DevicesController.Register: CWE-611 XXE, XmlUrlResolver + DtdProcessing.Parse
  ->            file:///proc/self/environ  ->  reads the container's environment
  ->  INFRA-05  Firmware__WriteKey stored there as a plaintext env var  (CWE-798)
  ->  [image join: iot/device-gateway, Dockerfile <-> infra/main.tf, confidence=inferred]
  ->  INFRA-01  firmware bucket policy: s3:PutObject from Principal "*"  (CWE-284)
  ->  CODE-05  FirmwareController.Publish: CWE-345, manifest signature read and never verified
  ->  every device installs the attacker's image
```

## The point of this fixture

**The credential theft is redundant.** `INFRA-01` allows `s3:PutObject` from `Principal = "*"` —
anyone on the internet can write into the firmware bucket without stealing anything at all. The
XXE path exists so the fixture contains a *long* chain and a *one-step* chain to the same
outcome, and a reasoner should find both.

The other half is `CODE-05`. The manifest carries a `VendorSignature` field, the gateway reads
it, and nothing verifies it. Devices check the SHA-256 and the SHA-256 comes from the same
manifest as the image — so **integrity is verified against a value the attacker also wrote**.
That is the difference between integrity and authenticity, and it is why the bucket write turns
into fleet-wide code execution instead of a corrupted download.

`INFRA-12` closes the loop grimly: the firmware signing key is baked into the image. Even a fix
to `CODE-05` that started verifying signatures would not help, because anyone who can pull the
image can produce valid ones.

## Two findings that are only findings together

`INFRA-01` (the permissive bucket policy) and `INFRA-02` (public access block fully disabled) are
each reported separately by any IaC scanner. **Neither is exploitable without the other** — with
the public access block on, the bucket policy is inert. A tool that reports two mediums has
described the situation accurately and ranked it wrongly; the pair is critical.

The same shape appears at `INFRA-10`: the build-logs bucket is correctly locked down at every
public-access setting, and the gateway's task role holds `s3:*` on `Resource = "*"`, which
reaches it anyway. **A correctly configured resource is still reachable if something else holds a
wildcard over it** — which is only visible when the graph is read as a whole.

## Where the issues are

### Code — `src/DeviceGateway/`

| ID | CWE | File | Issue |
|----|-----|------|-------|
| **CODE-01** | CWE-611 | `Controllers/DevicesController.cs` | **Flagship.** XXE — `XmlUrlResolver` with `DtdProcessing.Parse` |
| CODE-02 | CWE-287 | `Controllers/DevicesController.cs` | Device auth is a sequential serial number printed on the hardware |
| CODE-03 | CWE-639 | `Controllers/DevicesController.cs` | Any device can read any other device's config, including provisioning keys |
| CODE-04 | CWE-319 | `Controllers/DevicesController.cs` | Devices bootstrapped onto a plaintext MQTT endpoint |
| **CODE-05** | CWE-345 | `Controllers/FirmwareController.cs` | **Flagship.** Manifest signature read and never verified |
| CODE-06 | CWE-306 | `Controllers/FirmwareController.cs` | Firmware publish endpoint requires no authentication |
| CODE-07 | CWE-798 | `Services/FirmwareCatalog.cs` | Bucket write credential hardcoded as a fallback |
| CODE-08 | CWE-798 | `appsettings.json` | Bucket write key in a checked-in config file |

### Dependencies — `src/DeviceGateway/DeviceGateway.csproj`

| ID | Package | Why |
|----|---------|-----|
| **DEP-01** | System.Security.Cryptography.Xml 4.7.0 | **Flagship.** Signature-bypass advisory — in a fixture about an unverified signature |
| DEP-02 | MQTTnet 3.0.13 | Old broker client; pairs with CODE-04 |
| DEP-03 | AWSSDK.S3 3.3.104.29 | Old SDK on the firmware path |
| DEP-04 | SharpZipLib 1.2.0 | Zip-slip advisory — firmware bundles are archives |
| DEP-05 | Microsoft.CodeAnalysis.CSharp 4.0.1 | **Noise** — build-time only |

### Infrastructure — `infra/` and `Dockerfile`

| ID | CWE | File | Issue |
|----|-----|------|-------|
| **INFRA-01** | CWE-284 | `infra/storage.tf` | **Flagship.** `s3:PutObject` allowed from `Principal = "*"` |
| INFRA-02 | CWE-284 | `infra/storage.tf` | Public access block fully disabled — what makes INFRA-01 live |
| INFRA-03 | CWE-353 | `infra/storage.tf` | Versioning suspended — no way to see or roll back what was replaced |
| INFRA-04 | CWE-778 | `infra/storage.tf` | No access logging on the firmware bucket |
| INFRA-05 | CWE-798 | `infra/main.tf` | Bucket write key as a plaintext task-definition env var |
| INFRA-06 | CWE-668 | `infra/main.tf` | `assign_public_ip = true` — XXE and publish endpoint internet-reachable |
| INFRA-07 | CWE-284 | `infra/main.tf` | Security group open to `0.0.0.0/0` on 8080 and 1883 |
| INFRA-08 | CWE-284 | `infra/main.tf` | Fleet IoT policy grants `iot:*` on `*` |
| INFRA-09 | CWE-311 | `infra/main.tf` | Telemetry queue unencrypted |
| INFRA-10 | CWE-732 | `infra/main.tf` | Task role holds `s3:*` on `*` — reaches the locked-down logs bucket |
| INFRA-11 | CWE-311 | `infra/storage.tf` | No customer-managed key, bucket keys disabled |
| INFRA-12 | CWE-798 | `Dockerfile` | Firmware signing key baked into the image |
| INFRA-13 | CWE-250 | `Dockerfile` | No `USER` directive — runs as root |

**Total: 8 code + 5 dependency + 13 infrastructure = 26 planted issues.**

## What the toolchain actually detects

Measured, not predicted.

| Planted | Detected? | By what |
|---|---|---|
| **CODE-01 XXE (flagship)** | ✅ | `SCS0007` |
| **CODE-05 signature read and never verified (flagship)** | ❌ **No** | There is no rule for "this field is parsed and ignored". A **false-negative probe**, and the reason the bucket write becomes fleet-wide code execution |
| DEP-01 System.Security.Cryptography.Xml 4.7.0 | ✅ | `GHSA-vh55-786g-wjwj` — a signature-bypass advisory, in a fixture about an unverified signature |
| DEP-04 SharpZipLib 1.2.0 | ✅ | `GHSA-m22m-h4rf-pwq3` (high) |
| **INFRA-01 `Principal = "*"` with `s3:PutObject`** | ✅ | Checkov |
| INFRA-02 public access block disabled | ✅ | Checkov |

Both halves of the critical pair (INFRA-01 + INFRA-02) are reported, **separately, as two
mediums**. Neither is exploitable without the other and together they are critical. Ranking that
correctly is a reasoning problem, not a detection one.

## The load-bearing detail

`Dockerfile`'s `LABEL org.sentinelai.image="iot/device-gateway"` must normalize to the same
coordinate as `infra/main.tf`'s container image
(`registry.hub.docker.com/iot/device-gateway:4.1.2`). Without it the code→infra seam has nothing
to compare and the XXE, the credential and the bucket read as three unrelated findings.
