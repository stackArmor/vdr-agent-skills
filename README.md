# vdr-agent-skills

> Repository rename: this project was previously named `trivy-plugin-vdr-skills`.
> GitHub preserves redirects for the old repository URL and Git clients, but new
> links and checkouts should use `stackArmor/vdr-agent-skills`.

Agent skills that capture reviewable security metadata for
[trivy-plugin-vdr](https://github.com/stackArmor/trivy-plugin-vdr) FedRAMP
VDR/VER scoring. One skill assesses system and agency security objectives
without infrastructure access; the Kubernetes skills read clusters with
read-only `kubectl` and write ConfigMaps locally. The Terraform skill
selectively adds reviewable metadata to CIS Foundations-mapped cloud assets.
**Nothing is ever applied to a cluster or cloud account by an agent.**

## The skills

### `capture-dataflow` → the `vdr-dataflow` ConfigMap (beta)

> **Status:** This skill is in beta and may be deprecated. Treat its schema and
> generated artifacts as experimental analysis aids rather than a stable
> long-term interface.

The skill is useful for discovering and reviewing data flows and
interrelationships among workloads, services, ingress paths, policy controls,
and external dependencies in Kubernetes environments. It builds the cluster's
dataflow evidence for internet-reachability analysis by working through
evidence sources in stages — declared **NetworkPolicies**, then **service-mesh
authorization** resources, then optional **Hubble / mesh flow exports**, then
declared **env / Secret / ConfigMap** connection analysis. It produces the
`vdr-dataflow` ConfigMap plus per-namespace Mermaid diagrams for operator
review. The agent-assisted review also records **broker candidates** — possible
payload paths through cloud brokers (SQS, S3, Pub/Sub, GCS, ...) that Kubernetes
alone cannot confirm — each with the workload-identity principal to verify
against IAM later.

### `generate-security-objectives` → `security-objectives.json`

Assesses the **system's** security objectives (what the product holds and does
by design) together with the deploying **agency's** expected use (the data that
agency will actually place in the system). It applies the FedRAMP Class as a
transparent prior, not as authority over the data profile, and derives an
optional ceiling with `min(SSO, ASO)`. The single JSON artifact contains the
evidence, confidence, divergence record, wire value such as
`cr-m_ir-m_ar-l`, and display value such as `CR:M/IR:M/AR:L`. It does not
access Kubernetes, classify components, or generate a ConfigMap.

The skill includes a
[source-pinned machine-readable catalog](skills/generate-security-objectives/references/nist-sp-800-60-v2r1-information-types.json)
of all 170 information-type records in NIST SP 800-60 Volume II Revision 1. It
queries the catalog to identify candidate FIPS 199 information types, preserves
each record's provisional C/I/A profile and special factors, and records how
confirmed types informed the system and agency objectives. NIST recommendations
remain advisory starting points and never replace actual-use evidence or a
governing categorization.

The ceiling may be copied into `vdr-fedramp` as
`securityRequirementsCeiling` or passed to trivy-plugin-vdr with
`--security-requirements-ceiling`. Using it is optional.

### `generate-vdr-configmap` → the SIP-based `vdr-fedramp` ConfigMap

Interviews the operator to capture the canonical scoring attestations: the
FedRAMP **Certification Class**, **agency scope** (single/multi-agency), and
per-workload security-impact profiles expressed as direct vectors,
compositional decision traces, or named archetypes. Emits a central
`vdr-fedramp` ConfigMap rule for every
workload plus an assignment-coverage ledger with confidence and manual-review
reporting.

### `generate-cloud-vdr-config` → the central vdr-cloud.yaml (proposed contract)

Extends the central-assignment model to **non-Kubernetes cloud resources**. It
discovers CIS Foundations-addressed GCP and AWS resource families (object
storage, VMs, managed SQL, BigQuery datasets, and the rest) with read-only
`gcloud`/`aws` CLIs, interviews the operator, and emits a single multi-scope
`vdr-cloud.yaml` (`CloudResourceScoringConfig`) plus an inventory baseline and a
coverage ledger. Resources are matched by **name, tag, network, or type rules**
with family-tier precedence, or by whole account/project defaults; each resolves
FedRAMP Class, agency scope, and a CR/IR/AR security-impact profile
independently down the chain. This document becomes the **primary** assignment
surface, so per-resource `vdr.fedramp.io/*` tags are demoted to
exceptions/overrides. Provider-managed resources (staging buckets, template
stores, CDK assets, ...) are matched against a governed catalog and
**materialized as reviewable medium-confidence rules**, never assumed silently.
Like the `tag-terraform-vdr-assets` sidecar, `vdr-cloud.yaml` is a **proposed
integration contract — `trivy-plugin-vdr` does not consume it today** — and
every artifact and handoff says so.

### `tag-terraform-vdr-assets` → selective Terraform metadata

Inventories AWS, Azure, and GCP Terraform and allows only asset families
addressed by the supplied CIS Foundations Benchmarks (for example projects or
accounts, identities, VMs, databases, buckets, keys, logging, and network
boundaries). It separately interviews the operator for compositional CR/IR/AR
decision traces, then adds provider-valid tags or labels only where the pinned
provider or module supports them. Untaggable IAM and control resources are
reported as coverage gaps instead of receiving invalid Terraform arguments.
GCP projects and AWS accounts can optionally carry confirmed Certification
Class and multi-agency defaults.

## Installation

### Claude Code

```
/plugin marketplace add stackArmor/vdr-agent-skills
/plugin install trivy-plugin-vdr-skills
```

Then invoke a skill by name, or describe what you need ("assess the system and
agency security objectives" or "set up the FedRAMP scoring ConfigMap").

### Antigravity, Codex, and other agents

The `.agents/skills/` directory contains the same skills for agents that
discover skills there (Antigravity auto-discovers them when run inside the
repo; confirm with `/skills`). The skill content is identical — only the
discovery path differs.

## Requirements

| Tool | Notes |
|------|-------|
| `kubectl` (authenticated) | For `generate-vdr-configmap` and `capture-dataflow`; not needed by `generate-security-objectives`. **Read-only RBAC is sufficient** — `get`/`list` on workloads, namespaces, and (for dataflow) NetworkPolicies, mesh resources, and Secrets. |
| `gcloud` / `aws` CLIs (authenticated, read-only) | For `generate-cloud-vdr-config` only. Read-only access is sufficient — `list`/`describe`/`get` and `sts get-caller-identity`; the skill never runs a mutating verb or applies anything to a cloud account. |
| `terraform` | Optional for formatting and offline validation of Terraform edits; never used to apply infrastructure. |
| `python3` (>= 3.8) | For the inventory/capture scripts. Standard library only — no `pip install`. |

## Security posture

- **Read-only verbs only.** The skills and their scripts run `kubectl get` /
  `list` exclusively — never `exec`, `apply`, `label`, `patch`, or `delete`.
- **No Terraform deployment.** The Terraform skill never reads state or plan
  files and never runs `terraform apply`; it edits only operator-approved HCL
  and validates the resulting diff.
- **Secret values never leave the cluster.** Where Secret-declared
  connections are analyzed, values are reduced to `host:port` endpoints in
  all outputs; credentials are never written to any artifact.
- **Artifacts stay local** until the operator applies them. Every generated
  manifest and label command is written to a local output directory for
  review; applying is an explicit operator action (`kubectl apply -f` or a
  GitOps commit).
- Operator attestations remain distinct from agent inferences. Missing impact
  detail does not suppress an objectives artifact or ConfigMap: each skill
  makes a conservative, evidence-backed assessment and exposes its confidence
  and review needs. HA is mitigation evidence and never lowers the
  Availability Requirement.

## How the ConfigMaps are consumed

Both ConfigMaps are read in-cluster by
[trivy-plugin-vdr](https://github.com/stackArmor/trivy-plugin-vdr):
`vdr-fedramp` drives PAIN scoring and `VDR-TFR-PVR` remediation deadlines
(Certification Class, agency scope, and security-impact-profile rules). An optional
`securityRequirementsCeiling` in that ConfigMap—or the corresponding runtime
flag—caps profile CR/IR/AR values only when recalculating reported PAIN
scores. Its absence is valid and silent. The beta
`vdr-dataflow` workflow can supply experimental dataflow evidence for
internet-reachability determination, but may be changed or deprecated. See
that repository's README for the scoring model and the ConfigMap schemas.

## License

MIT — see [LICENSE](LICENSE).
