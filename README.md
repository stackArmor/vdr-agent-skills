# trivy-plugin-vdr-skills

Agent skills that capture reviewable security metadata for
[trivy-plugin-vdr](https://github.com/stackArmor/trivy-plugin-vdr) FedRAMP
VDR/VER scoring. The Kubernetes skills read clusters with read-only `kubectl`
and write ConfigMaps locally. The Terraform skill selectively adds reviewable
metadata to CIS Foundations-mapped cloud assets. **Nothing is ever applied to a
cluster or cloud account by an agent.**

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

### `generate-security-requirements-configmap` → the `vdr-fedramp` ConfigMap

Derives a per-component **Security Requirements** vector (CR/IR/AR) from three
per-objective inputs: the **system's** security objectives (what the product
holds by design, confirmed by the operator from consented web research), the
deploying **agency's** security objectives (the data that agency would
actually place in the system — objective-level, never the FIPS 199 high-water
mark, with the Certification Class used as a prior rather than authority), and
each **component's** security objectives from read-only structural evidence.
The envelope `min(system, agency)` caps component vectors; enumerated breakout
categories (agency-endpoint delivery paths, cross-system trust anchors, shared
CSP infrastructure) may exceed it with written justification and manual-review
flags. Emits the `vdr-fedramp` ConfigMap (label key
`vdr.fedramp.io/security-requirements`, dot-free `cr-*_ir-*_ar-*` values, a
human-only `humanReviewCompleted` marker) plus `security-objectives.json` and
`assignment-coverage.json` justification records. Every decision carries
confidence; medium/low decisions, capped components, and breakouts are printed
for review.

### `generate-vdr-configmap` → the `vdr-fedramp` ConfigMap (deprecated)

> **Status:** Superseded by `generate-security-requirements-configmap`. Use it
> only to maintain clusters that still resolve the legacy
> `vdr.fedramp.io/asset-archetype` vocabulary.

Interviews the operator to capture the scoring attestations: the FedRAMP
**Certification Class**, the **agency scope** (single/multi-agency), and
per-workload compositional decision traces producing deterministic CR/IR/AR
vectors. Emits a central `vdr-fedramp` ConfigMap rule for every workload plus
an assignment-coverage ledger with confidence and manual-review reporting.

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
/plugin marketplace add stackArmor/trivy-plugin-vdr-skills
/plugin install trivy-plugin-vdr-skills
```

Then invoke either skill by name, or just describe what you need ("set up the
FedRAMP scoring ConfigMap for this cluster").

### Antigravity, Codex, and other agents

The `.agents/skills/` directory contains the same skills for agents that
discover skills there (Antigravity auto-discovers them when run inside the
repo; confirm with `/skills`). The skill content is identical — only the
discovery path differs.

## Requirements

| Tool | Notes |
|------|-------|
| `kubectl` (authenticated) | For the Kubernetes skills. **Read-only RBAC is sufficient** — `get`/`list` on workloads, namespaces, and (for dataflow) NetworkPolicies, mesh resources, and Secrets. |
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
  detail does not suppress the ConfigMap: the generation skill makes a
  conservative, evidence-backed assignment and exposes its confidence and
  review needs. HA is recorded as mitigation evidence and never used to lower
  the Availability Requirement.

## How the ConfigMaps are consumed

Both ConfigMaps are read in-cluster by
[trivy-plugin-vdr](https://github.com/stackArmor/trivy-plugin-vdr):
`vdr-fedramp` drives PAIN scoring and `VDR-TFR-PVR` remediation deadlines
(Certification Class, agency scope, and security-requirements rules; legacy
archetype rules remain supported for clusters generated by the deprecated
skill). The beta
`vdr-dataflow` workflow can supply experimental dataflow evidence for
internet-reachability determination, but may be changed or deprecated. See
that repository's README for the scoring model and the ConfigMap schemas.

## License

MIT — see [LICENSE](LICENSE).
