# trivy-plugin-vdr-skills

Agent skills that capture operator-attested metadata for
[trivy-plugin-vdr](https://github.com/stackArmor/trivy-plugin-vdr) FedRAMP
VDR/VER scoring. The Kubernetes skills read clusters with read-only `kubectl`
and write ConfigMaps locally. The Terraform skill selectively adds reviewable
metadata to CIS Foundations-mapped cloud assets. **Nothing is ever applied to a
cluster or cloud account by an agent.**

## The skills

### `capture-dataflow` → the `vdr-dataflow` ConfigMap

Builds the cluster's dataflow evidence for internet-reachability analysis. It
works through evidence sources in stages — declared **NetworkPolicies**, then
**service-mesh authorization** resources, then optional **Hubble / mesh flow
exports**, then declared **env / Secret / ConfigMap** connection analysis —
evaluating after each stage whether the evidence collected is sufficient
before descending to the next. It produces the `vdr-dataflow` ConfigMap plus
per-namespace Mermaid dataflow diagrams for operator review. The agent-assisted
review also records **broker candidates** — possible payload paths through cloud
brokers (SQS, S3, Pub/Sub, GCS, ...) that Kubernetes alone cannot confirm — each
with the workload-identity principal to verify against IAM later.

### `generate-vdr-configmap` → the `vdr-fedramp` ConfigMap

Interviews the operator to capture the scoring attestations: the FedRAMP
**Certification Class** (mapped from the existing authorization level: Ready →
A, Low → B, Moderate → C, High → D), the **agency scope**
(single/multi-agency), and per-workload compositional decision traces. Each
trace has one independently mapped reason for disclosure, trusted change, and
dependency/outage, producing a deterministic CR/IR/AR vector while preserving
the rationale in the archetype value. The skill proposes traces from a
read-only workload and privilege inventory, then emits a central
`vdr-fedramp` ConfigMap rule for every confirmed workload plus a complete
assignment-coverage ledger. Direct labels are optional operator-requested
overrides, never the default output.

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
- Attestations (Class, scope, environment intent, and decision traces) are
  explicit operator decisions captured by the interview — the skills propose,
  the operator confirms. HA is recorded as mitigation evidence and never used
  to lower the Availability Requirement.

## How the ConfigMaps are consumed

Both ConfigMaps are read in-cluster by
[trivy-plugin-vdr](https://github.com/stackArmor/trivy-plugin-vdr):
`vdr-fedramp` drives PAIN scoring and `VDR-TFR-PVR` remediation deadlines
(Certification Class, agency scope, archetype rules), and `vdr-dataflow`
supplies the dataflow evidence for internet-reachability determination. See
that repository's README for the scoring model and the ConfigMap schemas.

## License

MIT — see [LICENSE](LICENSE).
