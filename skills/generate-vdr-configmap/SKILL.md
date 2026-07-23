---
name: generate-vdr-configmap
description: Generate or update the trivy-plugin-vdr vdr-fedramp scoring ConfigMap from explicit FedRAMP Class, agency-scope, and compositional CR/IR/AR decision-trace attestations; inventory Kubernetes workloads read-only, centrally assign every confirmed workload with ConfigMap rules, validate complete assignment coverage, and never apply anything.
---

# Generate VDR ConfigMap

Interview the operator, inspect the selected Kubernetes cluster read-only, and
write the governed scoring artifacts consumed by `trivy-plugin-vdr`.
In commands below, resolve `<skill-dir>` to the directory containing this file.

## Ground rules

- Run only `kubectl config` and `kubectl get`. Never run `exec`, `apply`,
  `label`, `patch`, `edit`, or `delete`.
- Write only under `./vdr-configmap-output/`. The operator reviews and applies
  the output manually or through GitOps.
- Treat Class, agency scope, environment intent, and every assigned decision
  trace as operator attestations. Propose values; never silently assume them.
- Treat the generated ConfigMap as the default assignment surface for every
  confirmed workload. Ownership and labelability never decide whether a
  workload receives a ConfigMap rule.
- Account for every inventoried workload. Generation is incomplete unless each
  workload either resolves to a confirmed archetype or appears as an explicit
  operator-accepted unresolved exception. Never omit a workload silently.
- For a fresh evaluation, do not read or use the existing `vdr-fedramp`
  ConfigMap. Existing labels may be reported but must be reconfirmed.
- Never retrieve Secret resources or values. Reference names visible in
  workload specs are sufficient evidence; never reproduce credential material.

## Decision-trace schema

Use one Kubernetes label value with exactly three segments:

```text
<disclosure>.<trusted-change>.<dependency>
```

The segments independently determine CR, IR, and AR. Example:

```text
privileged-access.foundation-control.recovery-critical -> H/H/H
```

Read `references/archetype-guide.md` completely before classifying workloads.
It defines the allowed reasons, the five-question interview, availability
calibration, all 27 vector combinations, and classification examples.

The current plugin treats the dotted string as an opaque archetype name; it
does not parse the segments. Therefore every exact trace used by a label or
rule must also appear under `scoring.yaml.archetypes` with its derived vector.
Keep every value Kubernetes-label-safe and at most 63 characters.

## Workflow

### 1. Confirm the target context

Run `kubectl config current-context`, show the value, and obtain explicit
confirmation before inventory. State that cluster access remains read-only.
Pass that exact reviewed name to every inventory query; never rely on a mutable
current-context after confirmation.

### 2. Confirm Class and agency scope

Map the existing FedRAMP authorization to Certification Class:

| Authorization | Class |
|---|---|
| FedRAMP Ready | A |
| FedRAMP Low | B |
| FedRAMP Moderate | C |
| FedRAMP High | D |

Require the operator to confirm the Class. Then confirm the cluster-wide
`multiAgency` default:

- `true`: compromise can affect several agencies from this cluster.
- `false`: single-agency deployment.

Do not infer this flag from workload population. Namespace and workload
`vdr.fedramp.io/multi-agency` labels remain available for exceptions.

### 3. Inventory workloads and structural evidence

Run:

```bash
python3 <skill-dir>/scripts/list_workloads.py \
  --context '<reviewed-context>'
```

Preserve the exact successful JSON as
`./vdr-configmap-output/workload-inventory.json`; do not reconstruct or filter
the inventory when calculating coverage.

Use `-n <namespace>` only when the user restricts scope. The script records
images, service accounts, host privilege indicators, and referenced resource
names without resolving their contents. It exits nonzero if any required query
fails; never reinterpret a partial inventory as an empty resource class. It
pins the reviewed context on every `kubectl get`, preventing a concurrent
context switch from mixing clusters in one inventory.

Inventory standalone and custom-owned Kubernetes Jobs as independently
scorable workloads. Suppress a Job whenever its controller owner is a CronJob;
the plugin represents that repeated execution through the CronJob template.
Keep Pods owned by custom controllers, but suppress Pods whose owner kind the
plugin already inventories (`ReplicaSet`, `StatefulSet`, `DaemonSet`, or `Job`).

When needed, collect more evidence with read-only `kubectl get` calls for:

- workload specifications and owner references;
- Service, Ingress, and Gateway routing;
- Roles, ClusterRoles, and their bindings;
- validating or mutating webhooks;
- PVC references and node selectors.

Privilege evidence outweighs product naming. Strong signals include broad
Secret access, service-account token creation, IAM/RBAC mutation, `pods/exec`,
workload mutation, privileged mode, host PID/network, writable host mounts,
runtime sockets, and powerful Linux capabilities.

A managed-namespace match is an ownership hint, not a decision and not a
metadata-transport choice. Include provider-controlled, customer-controlled,
third-party, and application workloads in the same central assignment plan.

### 4. Ask the impact questions

Ask no more than five questions for an asset or a coherent workload group:

1. Should this environment use production-equivalent values, or is it an
   intentionally isolated low-impact environment?
2. What could disclosure expose?
3. What trusted action, record, identity, or control could compromise alter?
4. Who is affected by complete logical loss: CSP operators, a bounded user
   subset, or all users?
5. Ignoring replicas, failover, and other mitigations, is that outage limited,
   serious, severe, or specifically recovery/protection critical?

Environment names never establish impact. If the operator requires parity,
classify nonproduction workloads by their intended production data and
consequences even when current data is synthetic.

HA never lowers AR. Evaluate the consequence of the workload class being
logically unavailable across all replicas; record redundancy only as a
mitigating control outside the requirement vector. Population informs outage
consequence but is not an independent multiplier.

### 5. Propose and confirm traces

For each inventoried workload, show:

- workload or precise workload group;
- exact three-part trace;
- derived CR/IR/AR vector;
- one-line evidence and any operator-dependent assumption;
- confidence level.

Build the assignment plan from the complete inventory, not from ownership or
whether a workload can retain labels. Use exact `nameRules` by default. A
narrow, stable name pattern may cover a coherent group only when every current
match has the same confirmed trace. Use a `namespaceRule` only when every
relevant workload in that namespace has the same confirmed trace. Treat
`kindRules` as exceptional; never use a blanket Job fallback unless every Job
it can match is proven coherent and the operator explicitly accepts it.

Give standalone and Helm-hook Jobs explicit rules based on their role and
authority. Prefer exact `nameRules` when names are stable; when generated names
defeat exact rules, use a narrow `kindRule` scoped by namespace and name glob.
Continue suppressing CronJob-owned Jobs because the CronJob is the durable
scorable workload.

Existing explicit archetype labels have higher runtime precedence. Reconfirm
them and record whether they agree with the central rule; flag unknown or
conflicting labels because they can prevent the intended rule from resolving.
Offer direct labels only when the operator explicitly requests an override.

Ask when payload type, cross-environment authority, or business consequence
cannot be learned from cluster state. An unconfirmed workload may remain at the
`unclassified` H/H/H fail-safe only after the operator explicitly accepts it as
an unresolved exception; record the workload and reason in the coverage file.

### 6. Compile the scoring catalog

Validate confirmed traces and generate exact catalog entries with:

```bash
python3 <skill-dir>/scripts/reason_codes.py \
  --cover-27 <confirmed-trace>...
```

`--cover-27` adds a canonical trace only for vector combinations not already
represented. Use it when the operator confirms that the policy should retain
all 27 CR/IR/AR permutations. Coverage-only entries are policy capability, not
asset assignments; do not assign them without a workload attestation.

### 7. Emit the artifacts

Write three required files under `./vdr-configmap-output/`:

1. `workload-inventory.json`
   - The exact successful output from step 3.
   - Keep the reviewed context, namespace records, workload records, and
     summary together as the coverage baseline.
2. `vdr-fedramp.yaml`
   - Namespace `fedramp-vdr-trivy` and ConfigMap `vdr-fedramp`.
   - Quoted `class` and `multiAgency` strings.
   - Exact custom `archetypes` entries and central assignment rules for every
     confirmed inventoried workload, regardless of ownership.
   - Prefer exact `nameRules`; allow narrow stable patterns only for confirmed
     coherent groups. Use `namespaceRules` and `kindRules` only under the
     explicit uniformity gates in step 5.
   - Include explicit rules for standalone and Helm-hook Jobs. Use narrowly
     scoped Job `kindRules` when generated names require them; do not add a
     blanket Job fallback merely to improve apparent coverage.
   - Avoid broad namespace fallbacks where privilege varies; unknown future
     components should fail loud.
3. `assignment-coverage.json`
   - Record the reviewed context, inventory total, and one entry for every
     inventoried workload: namespace, kind, name, confirmed trace and vector,
     expected resolution source, and status.
   - Record every operator-accepted unresolved exception with its reason.
   - Summarize counts by namespace, resolution source, confirmed assignment,
     and accepted unresolved exception.

If the operator explicitly requests direct-label overrides, also emit
`label-overrides.sh`. Begin it with `FOR OPERATOR REVIEW AND EXECUTION`, state
that the skill never runs it, and pin every suggestion to the reviewed
`--context`. Recommend moving accepted overrides into Helm or deployment
manifests. For CronJobs, put the trace in CronJob `metadata.labels` or
`spec.jobTemplate.spec.template.metadata.labels`; the plugin inventories the
CronJob and suppresses its generated Jobs. Do not rely on
`spec.jobTemplate.metadata.labels`, which the plugin does not score. Put an
override directly in one-shot and Helm-hook Job manifests.

Ask once whether any Ingress/Gateway class is fronted by a load balancer built
outside Kubernetes. Include `internetAccessibleIngressClasses` or
`internetAccessibleGatewayClasses` only for classes the operator confirms.
Omit the keys when there are none.

Do not put PAIN word thresholds in the ConfigMap. Those remain governed
`--scoring-config` policy and are intentionally not cluster-overridable.

If the user supplies a proprietary-term deny-list, scan reusable content and
generated files case-insensitively. Parameterize a required namespace or
workload identifier rather than leaking it or targeting a guessed resource.

### 8. Validate without touching the cluster

Before handoff:

- parse the outer YAML and embedded `scoring.yaml`;
- verify every trace has three registered reasons and matching H/M/L values;
- verify all rule and label references are declared exactly;
- verify all 27 vectors are represented when requested;
- check rule globs, ordering, and duplicate/shadowed entries;
- resolve every inventory entry using actual precedence: workload label,
  namespace label, `nameRule`, `kindRule`, `namespaceRule`, then fail-safe;
- fail validation if a confirmed workload resolves to `unclassified`, if an
  unknown or unconfirmed conflicting explicit label blocks its intended rule,
  or if any inventory entry is absent from `assignment-coverage.json` without
  an operator-accepted unresolved exception;
- verify the inventory equation: confirmed assignments plus accepted
  unresolved exceptions equals the inventory total, with no duplicate workload
  entries; report the same accounting by namespace and resolution source;
- verify every emitted assignment rule matches at least one inventoried
  workload unless the operator explicitly attests a forward-looking rule;
- when `label-overrides.sh` exists, run `bash -n` on it;
- run the proprietary-term deny-list scan when applicable;
- keep the `skills/` and `.agents/skills/` copies byte-identical.

When a sibling `trivy-plugin-vdr` checkout is available, prefer an offline
parser/smoke test against that implementation. Treat warnings about an invalid
cluster scoring config as failures even when the command exits zero.

Never execute any generated artifact.

## Handoff

Report the inventory total, confirmed assignment count, accepted unresolved
count, and any precedence conflicts. Do not call the generation complete when
the accounting rule fails. Tell the operator to review all required files and
apply the ConfigMap manually or through the owning GitOps repository. Mention
label overrides only when they were explicitly requested. Re-run the skill
after estate, Class, scope, or policy changes; anything unresolved continues to
score loudly.
