---
name: generate-vdr-configmap
description: Generate or update the trivy-plugin-vdr vdr-fedramp scoring ConfigMap from explicit FedRAMP Class, agency-scope, and compositional CR/IR/AR decision-trace attestations; inventory Kubernetes workloads read-only, compile exact dotted reason codes into the scoring catalog, and emit local review-only label commands without applying anything.
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

A managed-namespace match is an ownership hint, not a decision. A
customer-installed component in a system namespace should still receive a
direct label. A provider-controlled component should use a ConfigMap rule.

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

For each unlabeled workload, show:

- workload or precise workload group;
- exact three-part trace;
- derived CR/IR/AR vector;
- one-line evidence and any operator-dependent assumption;
- confidence level.

Group repetitive managed components by narrow, reviewable name pattern. Ask
when payload type, cross-environment authority, or business consequence cannot
be learned from cluster state. Unconfirmed workloads stay unlabeled and resolve
to the `unclassified` H/H/H fail-safe.

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

Write both files under `./vdr-configmap-output/`:

1. `vdr-fedramp.yaml`
   - Namespace `fedramp-vdr-trivy` and ConfigMap `vdr-fedramp`.
   - Quoted `class` and `multiAgency` strings.
   - Exact custom `archetypes` entries and narrow `nameRules` for confirmed
     provider-controlled components.
   - Avoid blanket system-namespace fallbacks when privilege varies; unknown
     future components should fail loud.
2. `label-commands.sh`
   - Begin with `FOR OPERATOR REVIEW AND EXECUTION` and state that the skill
     never runs it.
   - Emit one `kubectl label ... --overwrite` suggestion per confirmed
     customer-controlled workload.
   - Require a reviewed context value and pin every suggested mutation with
     `--context`; a one-time context check alone has a race.
   - Recommend moving labels into Helm or deployment manifests after review.
     For CronJobs, put the trace in CronJob `metadata.labels` or
     `spec.jobTemplate.spec.template.metadata.labels`; the plugin inventories
     the CronJob and suppresses its generated Jobs. Do not rely on
     `spec.jobTemplate.metadata.labels`, which the plugin does not score. Put
     the label directly in one-shot and Helm-hook Job manifests as well.

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
- run `bash -n vdr-configmap-output/label-commands.sh`;
- run the proprietary-term deny-list scan when applicable;
- keep the `skills/` and `.agents/skills/` copies byte-identical.

When a sibling `trivy-plugin-vdr` checkout is available, prefer an offline
parser/smoke test against that implementation. Treat warnings about an invalid
cluster scoring config as failures even when the command exits zero.

Never execute either generated artifact.

## Handoff

Tell the operator to review both files, apply the ConfigMap manually or through
the owning GitOps repository, and execute or translate the label suggestions
only after review. Re-run the skill after estate, Class, scope, or policy
changes; anything unclassified continues to score loudly.
