---
name: Generate VDR ConfigMap
description: Use when the user wants to create or update the vdr-fedramp scoring ConfigMap for trivy-plugin-vdr — interviews the operator (FedRAMP Certification Class, agency scope, asset-archetype attestations), inventories cluster workloads read-only, and writes the ConfigMap YAML plus suggested label commands locally. Never applies anything to the cluster.
version: 0.1.0
---

# Generate VDR ConfigMap

Interview the operator and produce the `vdr-fedramp` ConfigMap (namespace
`fedramp-vdr-trivy`) that [trivy-plugin-vdr](https://github.com/stackArmor/trivy-plugin-vdr)
reads for PAIN scoring: the Certification Class, the agency scope, and the
name/namespace archetype rules for components that cannot carry labels. Also
produce suggested `kubectl label` commands for the archetype attestations the
operator confirms.

## Ground rules

- **Read-only.** Only `kubectl get`/`kubectl config` are ever run (via the
  inventory script or directly). Never `exec`, `apply`, `label`, `patch`,
  `edit`, or `delete` — not even if the user asks; instead point them at the
  generated artifacts to review and apply themselves.
- **Artifacts stay local.** Everything is written to `./vdr-configmap-output/`.
  The operator applies it manually (`kubectl apply -f`) or through GitOps.
- **Attestations are decisions, not guesses.** Every Class, scope, and
  archetype value in the output must have been explicitly confirmed by the
  user. Propose; never silently assume.

## Workflow

### 1. Confirm the kubectl context

Show `kubectl config current-context` and confirm with the user that this is
the cluster to inventory. State the read-only guarantee up front: this skill
only lists resources and never modifies the cluster.

### 2. Confirm the Certification Class and agency scope (required — never skip)

The Certification Class selects the entire remediation-deadline column block,
so it must be confirmed explicitly. Present this mapping so the operator can
find themselves by their existing FedRAMP authorization level:

| Your FedRAMP authorization | Certification Class |
|----------------------------|---------------------|
| FedRAMP Ready              | **A**               |
| FedRAMP Low                | **B**               |
| FedRAMP Moderate           | **C**               |
| FedRAMP High               | **D**               |

Ask the user to confirm the Class explicitly. **Do not silently default** —
if they are unsure, help them locate their authorization level on the
[FedRAMP Marketplace](https://marketplace.fedramp.gov/) first.

Then confirm the agency scope — `multiAgency: "true"` or `"false"`:

- **true** — a multi-tenant platform serving several agencies from this
  cluster (a compromise can affect more than one agency at once).
- **false** — a single-agency deployment.

Explain that this is the cluster-wide default: hierarchical override labels
(`vdr.fedramp.io/multi-agency` on a namespace or workload, most-specific wins)
exist for exceptions, so a mostly-single-agency cluster with one shared
namespace can stay `"false"` and label the exception.

### 3. Inventory the workloads

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/skills/generate-vdr-configmap/scripts/list_workloads.py > workloads.json
```

(Use `-n <namespace>` to restrict scope; default is all namespaces. Requires
authenticated `kubectl` + `python3`, stdlib only.)

The JSON lists every workload (namespace, kind, name, existing
`vdr.fedramp.io/*` labels, container images), namespace-level
`vdr.fedramp.io/class` / `vdr.fedramp.io/multi-agency` labels, and flags
cloud-managed namespaces (`kube-system`, `gke-managed-*`, `gmp-*`,
`amazon-cloudwatch`, `azure-*`, …) whose components cannot carry customer
labels.

### 4. Archetype attestation (interactive)

Read `${CLAUDE_PLUGIN_ROOT}/skills/generate-vdr-configmap/references/archetype-guide.md`
— it contains the archetype catalog (CR/IR/AR values, typical members) and the
classification rule. For each workload **without** an existing
`vdr.fedramp.io/asset-archetype` label, propose one:

- **Control-plane lens first**: if the workload can deploy, orchestrate, hold
  cross-estate credentials, or actuate configuration, classify it by that
  control function regardless of the data it stores. Otherwise classify by the
  data it holds.
- The same software lands in different archetypes **by role**: an in-memory
  store is `app-tier` as a cache, `identity-secrets` as a session/token store,
  `data-backbone` as a job broker. When the role is ambiguous from images and
  names alone, ask rather than assume.

Walk the user through the proposals in batches (grouped by namespace works
well): show workload, proposed archetype, one-line rationale; capture
confirmations and corrections.

- **Customer-controlled workloads** the user confirms → become
  `kubectl label` suggestions in `label-commands.sh` (step 5).
- **Cloud-managed components** (flagged namespaces) cannot carry labels →
  become `nameRules` / `namespaceRules` entries inside the ConfigMap instead
  (first match wins; nameRules win over namespaceRules).
- **Unconfirmed workloads stay unlabeled.** Tell the user this is intentional
  and loud: the plugin's fail-safe classifies untagged assets as
  `unclassified` (CR/IR/AR all High), so they score noisily (typically N4)
  until someone classifies them. Do not invent a quieter default.

### 5. Emit the artifacts

Write two files to `./vdr-configmap-output/`:

**(a) `vdr-fedramp.yaml`** — the Namespace + ConfigMap manifest (model it on
`${CLAUDE_PLUGIN_ROOT}/skills/generate-vdr-configmap/assets/vdr-fedramp.example.yaml`):

- `class` and `multiAgency` scalars from step 2.
- `scoring.yaml` with the `nameRules`/`namespaceRules` for cloud-managed and
  otherwise unlabelable components from step 4, each rule commented with its
  rationale.
- `internetAccessibleIngressClasses` / `internetAccessibleGatewayClasses`
  **only if** the user identifies Ingress/Gateway classes whose edge load
  balancer is provisioned outside Kubernetes (ask once: "any ingress classes
  fronted by a load balancer built outside the cluster, e.g. Terraform?").
- Rubric overrides (catalog entries, EPSS threshold, `unclassified` default)
  inside `scoring.yaml` **only if the user asks** for rubric changes — the
  built-in rubric is complete without them. If asked about the PAIN **word
  thresholds**: they are deliberately **not** ConfigMap-configurable; they
  live in the governed `--scoring-config` file so calibration cannot be
  changed by ad-hoc cluster edits. Say so and move on.

**(b) `label-commands.sh`** — the suggested labels for confirmed attestations,
headed by a comment block stating it is **FOR OPERATOR REVIEW AND EXECUTION —
this skill never runs it**. One line per workload:

```bash
kubectl label deployment/payments-api -n payments \
  vdr.fedramp.io/asset-archetype=app-tier --overwrite
```

Do not execute either artifact. Do not run `kubectl apply` or
`kubectl label` under any circumstances.

### 6. Hand off

Tell the user:

- Review both files in `./vdr-configmap-output/`.
- Apply the ConfigMap with `kubectl apply -f vdr-configmap-output/vdr-fedramp.yaml`,
  or commit it to the GitOps repo (ArgoCD/Flux) that owns cluster config —
  preferred, since the ConfigMap is governed security configuration.
- Run `label-commands.sh` after review (or translate the labels into their
  Helm charts / manifests so they survive redeploys).
- Re-run this skill when the estate changes — new namespaces, new
  cloud-managed components after a cluster upgrade, or a Class/scope change.
  Anything left unclassified will keep scoring loudly until then.

## Scope

This skill produces the **scoring** ConfigMap only (Class, scope, archetype
rules). Internet-reachability evidence is the companion `capture-dataflow`
skill, which produces the separate `vdr-dataflow` ConfigMap. Neither skill
ever modifies the cluster.
