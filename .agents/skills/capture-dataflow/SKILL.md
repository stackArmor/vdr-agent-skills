---
name: Capture Dataflow
description: Use when a FedRAMP Kubernetes operator needs the vdr-dataflow ConfigMap for trivy-plugin-vdr — captures the cluster's dataflow/taint graph (internet-exposed workloads, workload-to-service edges, hairpin/internet-transit paths) via staged read-only kubectl analysis, plus per-namespace Mermaid diagrams for human review. Read-only; the operator applies the resulting ConfigMap themselves.
version: 0.1.0
---

# Capture Dataflow

Produce the `vdr-dataflow` ConfigMap (namespace `fedramp-vdr-trivy`) that gives
[trivy-plugin-vdr](https://github.com/stackArmor/trivy-plugin-vdr) the cluster's
declared/attested dataflow topology, plus one Mermaid diagram per namespace with
internet-exposed workloads.

**Hard rules — state them to the user and obey them throughout:**
- `kubectl` read-only verbs only (`get`/`list`). NEVER `kubectl exec`. NEVER
  `apply`/`create`/`patch`/`delete` (not even `--dry-run=server`).
- Secret values may be parsed by the script, but only scheme+host+port may ever
  appear in outputs, evidence, or conversation — never credential material.
- Artifacts are saved locally. The operator applies the ConfigMap manually or via
  GitOps; you never apply it.

## Workflow

### 1. Confirm scope
Confirm the target `kubectl` context (`kubectl config current-context`) and the
namespace scope with the user (`--namespaces app1,app2` or `--all-namespaces`,
which excludes system namespaces). State the read-only guarantee above. Requires
authenticated `kubectl` + `python3`.

### 2. Capture
```bash
python3 ${CLAUDE_PLUGIN_ROOT}/skills/capture-dataflow/scripts/capture_dataflow.py \
  --namespaces <ns1,ns2> --emit bundle
```
Optional enrichment inputs (never required): `--flows-file <hubble.jsonl>`,
`--mesh-metrics-file <metrics.txt>`. `--all-stages` forces every stage; `--help`
for the rest. Read `vdr-dataflow-output/bundle.json`.

### 3. Agentic analysis (required)
Follow `${CLAUDE_PLUGIN_ROOT}/skills/capture-dataflow/references/analysis-guide.md`
**section by section**: stage-verdict interpretation, exposure review, zero-edge
workloads (ask the user targeted questions), unresolved-host triage, hairpin
review, then the attestation question. Capture the answers in
`operator-edges.yaml` (format in
`${CLAUDE_PLUGIN_ROOT}/skills/capture-dataflow/references/configmap-schema.md`;
example in `${CLAUDE_PLUGIN_ROOT}/skills/capture-dataflow/assets/operator-edges.example.yaml`).

### 4. Finalize
```bash
python3 ${CLAUDE_PLUGIN_ROOT}/skills/capture-dataflow/scripts/capture_dataflow.py \
  --namespaces <ns1,ns2> --merge operator-edges.yaml --emit all
```
This writes the final `configmap.yaml` and `diagrams/<namespace>.mmd`.

### 5. Review the diagrams
Present each diagram to the user (rendered, or as a fenced `mermaid` block). If
they correct an edge, update `operator-edges.yaml` and re-run step 4 — never
hand-edit `configmap.yaml`.

### 6. Hand off
Tell the user to review and apply it themselves:
```bash
kubectl apply -f vdr-dataflow-output/configmap.yaml   # or commit to their GitOps repo
```

## Scope
Dataflow/taint-graph capture only. Schema (`v1alpha1`, draft pending trivy-plugin-vdr
Phase B) is specified in `references/configmap-schema.md`; a filled example is in
`assets/vdr-dataflow.example.yaml`.
