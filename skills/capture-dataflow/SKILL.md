---
name: capture-dataflow
description: Beta and potentially deprecated analysis aid for understanding data flows and interrelationships in Kubernetes environments. Use when an operator needs a read-only workload/service dataflow graph, internet-exposure and transit evidence, per-namespace Mermaid diagrams, or the experimental trivy-plugin-vdr vdr-dataflow ConfigMap; the operator reviews and applies any artifact.
---

# Capture Dataflow

> **Beta:** This skill may be deprecated. Use it as an experimental aid for
> understanding Kubernetes data flows and interrelationships; do not treat its
> schema or generated artifacts as a stable long-term interface.

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
workloads (ask the user targeted questions), unresolved-host triage,
broker-candidate identification (SQS/S3/Pub/Sub/GCS links pending IAM
verification, with the workload-identity principal to check), hairpin review,
then the attestation question. Capture the answers in
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
