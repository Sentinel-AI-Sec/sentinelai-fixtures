# Benchmark corpus (SEC-38)

A labeled, ground-truth benchmark corpus for measuring SentinelAI's detection accuracy.

> **Scaffolding only.** This session created the folder structure and placeholder files.
> External projects are **not** vendored yet and no ground-truth items are written yet —
> those are later sessions.

## Purpose

This is a labeled benchmark corpus for measuring SentinelAI's detection **precision** and
**recall** (SEC-39). Each sample has a known-correct answer (a "real finding" or "not a
finding"), so the tool's output can be scored against the truth instead of guessed at.

It is kept **completely separate** from two things it must never be confused with:

- The **RAG knowledge corpus** (the offensive/defensive knowledge SentinelAI retrieves from).
  This benchmark is a *measuring stick*, not knowledge — see the rule below.
- The **`flagship/` demo fixture** (the three-layer demo repository). The flagship exists to
  *show* the product working end to end; this benchmark exists to *measure* how accurate it is.
  They are structurally separate on purpose and must stay that way.

## The "never embedded" rule

**Nothing under `benchmark/` may ever be ingested into Qdrant / the RAG knowledge base.**

Embedding this corpus would poison both sides at once: it would contaminate the knowledge
base with test data, and it would invalidate the measurement (the tool would be "studying the
answer key"). Either alone is disqualifying.

This is not a documentation-only promise. A hard guard enforces it:

- The marker file [`.no-ingest`](./.no-ingest) sits at the root of this corpus.
- The ingestion pipeline (`sentinelai-knowledge`) **must fail loudly** if it ever encounters a
  `.no-ingest` path — refusing to ingest rather than silently skipping.

That guard is **added in a later session**; this session only lays down the marker and the
structure it guards.

## Ground-truth schema

Each `ground_truth/*.json` file is an object of the form:

```json
{
  "project": "<name>",
  "source_commit": "",
  "items": []
}
```

`project` matches the sample set (`csharp`, `terragoat`, `kubernetes-goat`, `cfngoat`,
`clean-samples`), and `source_commit` will pin the exact commit of the vendored source once it
is vendored. Every entry in `items` uses this schema:

```json
{
  "id": "GT-001",
  "layer": "code|dep|infra",
  "file": "path/to/file",
  "resource_or_line": "resource name or line ref",
  "expected_label": "real_finding|not_a_finding",
  "expected_category": "short category label",
  "cwe_or_rule": "CWE-xxx or scanner rule id",
  "notes": "why this is/isn't a finding"
}
```

Field notes:

- **`id`** — stable identifier, unique within the file (e.g. `GT-001`).
- **`layer`** — which layer the item lives in: `code`, `dep`, or `infra`.
- **`file`** — path to the file the item refers to, relative to the sample project.
- **`resource_or_line`** — the specific resource name or line reference within that file.
- **`expected_label`** — the ground truth: `real_finding` or `not_a_finding`. Clean samples
  are labeled `not_a_finding` and exist to measure false positives.
- **`expected_category`** — a short human-readable category label for the issue.
- **`cwe_or_rule`** — the CWE id or the scanner rule id this item corresponds to.
- **`notes`** — the reasoning: why this is, or is not, a real finding.

## Vendored sources

External benchmark projects are vendored as frozen snapshots (working tree only, no nested git
history) by [`scripts/vendor-benchmark-repos.sh`](../scripts/vendor-benchmark-repos.sh), pinned to
the commit below. `clean-samples/` and `csharp-handlabeled/` are authored in this repo, so they
have no upstream source.

| Project | Source repo | Pinned commit |
|---------|-------------|---------------|
| terragoat | https://github.com/bridgecrewio/terragoat | `729f8da62c6a85ce4af5ad3d123de97776d954c4` |
| kubernetes-goat | https://github.com/madhuakula/kubernetes-goat | `723a0db478f050d173d23b4ce5044b65bce0bdd0` |
| cfngoat | https://github.com/bridgecrewio/cfngoat | `0c09b69cfc3dbc6cb3ef01883415c35c588ced48` |

## C# ground-truth gap (honest limitation)

There is **no standard C# vulnerability benchmark** comparable to the OWASP Benchmark for Java.
Nothing off-the-shelf provides a large, community-validated, labeled C# corpus.

As a result, the C# ground truth is **limited**: it consists of the hand-labeled flagship
fixture plus a small number of additional hand-written snippets. It is not a statistically
large sample.

**Read C# category results as indicative, not statistically rigorous.** They illustrate
behavior on known cases; they do not support strong quantitative claims about C# detection
accuracy the way the larger infra corpora (TerraGoat, Kubernetes-Goat, CfnGoat) can. This
limitation is stated openly rather than hidden.

## Ground-truth provenance & known bias

Some benchmark projects document their intended findings via **a specific scanner's output**.
CfnGoat's ground truth is derived from its auto-generated **Checkov** results (the README
"Existing vulnerabilities" tables), and TerraGoat likely does the same. That makes those sets
**Checkov-rule-grained** rather than scanner-neutral.

Where the documenting scanner is one **SentinelAI also runs** (SentinelAI's toolchain includes
Checkov), cross-tool **recall** comparisons on that project are **biased toward SentinelAI**: the
ground truth is effectively "what Checkov flags," so a Checkov-based scanner starts with an unfair
advantage and a non-Checkov tool (SonarQube, Snyk) can look worse than it is.

Consequences we hold to:

- The **headline precision/recall-vs-SonarQube/Snyk claim (SEC-39)** leans on the
  projects/sets where ground truth is **scanner-neutral** (e.g. hand-labeled sets and
  clean-samples), **not** on the Checkov-documented projects.
- Checkov-documented projects (cfngoat, likely terragoat) are used for **within-SentinelAI
  validation**, not as the cross-tool fairness headline.
- This bias is **disclosed per-project** in each ground-truth file's top-level `provenance`
  field, so anyone reading a result set sees the caveat next to the data.
