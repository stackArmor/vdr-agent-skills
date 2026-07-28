---
name: generate-vdr-configmap
description: Generate or update the canonical trivy-plugin-vdr vdr-fedramp scoring ConfigMap from FedRAMP Class, agency scope, and independently dimensional CR/IR/AR asset security-impact profiles; support direct vectors, compositional decision traces, or named archetypes; inventory Kubernetes workloads read-only, make evidence-backed best-effort assignments when operator detail is incomplete, annotate confidence and manual-review needs in the YAML and coverage ledger, validate complete coverage, and never apply anything.
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
- Ask for Class, agency scope, environment intent, and workload consequences,
  but do not let incomplete answers stop artifact generation after a successful
  inventory. Make the strongest evidence-backed best guess, state every
  assumption, and mark its confidence. Never present an inference as an
  operator attestation.
- Treat the generated ConfigMap as the default assignment surface for every
  inventoried workload. Ownership and labelability never decide whether a
  workload receives a ConfigMap rule.
- Account for every inventoried workload. Ordinary uncertainty is not an
  unresolved exception: assign the most defensible trace, lower its confidence,
  and flag it for review. Never omit a workload silently.
- For a fresh evaluation, do not read or use the existing `vdr-fedramp`
  ConfigMap. Existing labels may be reported, but do not treat them as operator
  attestations unless reconfirmed.
- Never retrieve Secret resources or values. Reference names visible in
  workload specs are sufficient evidence; never reproduce credential material.

## Security-impact-profile schema

The required runtime input is an independently dimensional CR/IR/AR asset
security-impact profile. `securityImpactProfile` rules and the
`vdr.fedramp.io/security-impact-profile` label accept any of these forms:

1. a direct vector such as `cr-h_ir-m_ar-l`;
2. a compositional decision trace with exactly three segments:

```text
<disclosure>.<trusted-change>.<dependency>
```

3. a named entry from the plugin's optional archetype catalog.

Prefer a compositional trace unless the operator chooses another governed
assignment method. Its segments independently determine CR, IR, and AR while
preserving the reason chain. Example:

```text
privileged-access.foundation-control.recovery-critical -> H/H/H
```

Read `references/archetype-guide.md` completely before assigning profiles. It
defines direct vectors, the optional archetype system, allowed trace reasons,
the five-question interview, availability calibration, all 27 vector
combinations, and examples.

The plugin parses direct vectors and governed decision traces natively. Do not
duplicate traces under `scoring.yaml.archetypes`; that catalog is only for
named archetypes. Keep every label value Kubernetes-label-safe and at most 63
characters. Emit only `securityImpactProfile` and
`vdr.fedramp.io/security-impact-profile`; retired `archetype` and `assetValue`
transports are invalid.

If the CSP uses a scalar asset-value method upstream, translate High, Medium,
or Low to the equal-dimension direct SIP vector before emission. Record that
lossy derivation and caution that it removes independent CR/IR/AR reasoning.

## Workflow

### 1. Confirm the target context

Run `kubectl config current-context`, show the value, and obtain explicit
confirmation before inventory. State that cluster access remains read-only.
Pass that exact reviewed name to every inventory query; never rely on a mutable
current-context after confirmation.

### 2. Determine Class and agency scope

Map the existing FedRAMP authorization to Certification Class:

| Authorization | Class |
|---|---|
| FedRAMP Ready | A |
| FedRAMP Low | B |
| FedRAMP Moderate | C |
| FedRAMP High | D |

Ask the operator to confirm the Class. Then ask for the cluster-wide
`multiAgency` default:

- `true`: compromise can affect several agencies from this cluster.
- `false`: single-agency deployment.

Do not infer this flag from workload population. Namespace and workload
`vdr.fedramp.io/multi-agency` labels remain available for exceptions.

If either value remains unanswered, infer it from explicit authorization or
tenant evidence when available. Otherwise emit fail-closed provisional values
(`D` and `true`), annotate each assumed value immediately above its YAML key
with `# confidence: low` and `# manual-review: ...`, record the assumption in
the coverage ledger, and include it in the terminal review report. Missing
Class or agency-scope answers never justify withholding `vdr-fedramp.yaml`.

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

### 4. Ask focused impact questions, then infer the rest

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

Do not repeat broad questions after the operator authorizes best judgment.
Answers such as "potentially all, depending on workload" establish the range;
use inventory evidence and workload role to choose within that range. Ask a
follow-up only when one answer would materially change several assignments and
the operator has not already delegated the choice. Otherwise proceed.

Use these confidence levels consistently:

- `high`: direct operator attestation for the assignment, or strong and
  unambiguous structural evidence for the workload's role and all three impact
  dimensions;
- `medium`: the role is well supported, but data sensitivity, authority,
  population, or outage consequence relies partly on a conventional workload
  inference;
- `low`: evidence is sparse, conflicting, name-based, or depends on
  infrastructure outside Kubernetes.

Confidence describes evidence quality, not impact severity. Never lower a
CR/IR/AR value because confidence is low. When several outcomes remain
credible, choose the strongest credible consequence and state what would
change the result.

### 5. Assign profiles and expose uncertainty

For each inventoried workload, show:

- workload or precise workload group;
- exact profile value and derivation method (`direct-vector`,
  `decision-trace`, or `named-archetype`);
- derived CR/IR/AR vector;
- one-line evidence and every assumption;
- confidence level.

Build the assignment plan from the complete inventory, not from ownership or
whether a workload can retain labels. Use exact `nameRules` by default. A
narrow, stable name pattern may cover a coherent group only when every current
match has the same assigned profile. Use a `namespaceRule` only when every
relevant workload in that namespace has the same assigned profile. Treat
`kindRules` as exceptional; never use a blanket Job fallback unless every Job
it can match is proven coherent and the operator explicitly accepts it.

Give standalone and Helm-hook Jobs explicit rules based on their role and
authority. Prefer exact `nameRules` when names are stable; when generated names
defeat exact rules, use a narrow `kindRule` scoped by namespace and name glob.
Continue suppressing CronJob-owned Jobs because the CronJob is the durable
scorable workload.

Existing explicit security-impact-profile labels have higher runtime
precedence. Reconfirm them when possible and record whether they agree with the
central rule; flag unknown or conflicting values because they can prevent the
intended rule from resolving. Offer direct labels only when the operator
explicitly requests an override.

Do not use `unclassified` merely because payload type, cross-environment
authority, or business consequence is uncertain. Infer from role and
structural evidence, choose the strongest credible profile, and mark it medium or
low confidence. Reserve `unclassified` for a technical validation failure that
must be fixed before handoff, not as a substitute for best-effort generation.

### 6. Validate profile derivation

Validate assigned decision traces and mechanically derive their vectors with:

```bash
python3 <skill-dir>/scripts/reason_codes.py \
  --cover-27 <assigned-trace>...
```

`--cover-27` reports a canonical trace for vector combinations not already
represented. Use it only for a coverage review. The output is a validation
report, not a ConfigMap catalog: the plugin resolves traces natively.

Validate direct vectors with the same independent H/M/L constraints. For a
named archetype, resolve the exact catalog entry and retain the archetype name
as the profile value. Record the derivation method in the coverage ledger.

### 7. Emit the artifacts

Write three required files under `./vdr-configmap-output/`:

1. `workload-inventory.json`
   - The exact successful output from step 3.
   - Keep the reviewed context, namespace records, workload records, and
     summary together as the coverage baseline.
2. `vdr-fedramp.yaml`
   - Namespace `fedramp-vdr-trivy` and ConfigMap `vdr-fedramp`.
   - Quoted `class` and `multiAgency` strings. Put a confidence comment
     immediately above each value, even when it is operator-confirmed; add a
     manual-review comment whenever its confidence is not high.
   - Central `securityImpactProfile` assignment rules for every inventoried
     workload, regardless of ownership or confidence. Add an `archetypes`
     catalog entry only when the CSP intentionally uses a named-archetype
     system; never add one merely to compile a decision trace.
   - Put a `# confidence: high|medium|low` comment immediately above every
     assignment rule or coherent rule group. Add a nearby
     `# manual-review: ...` comment for every medium- or low-confidence rule,
     naming the uncertainty that could change its profile. Use plain, sanitized
     evidence; never include credentials or Secret values.
   - Prefer exact `nameRules`; allow narrow stable patterns only for assigned
     coherent groups. Use `namespaceRules` and `kindRules` only under the
     explicit uniformity gates in step 5.
   - Include explicit rules for standalone and Helm-hook Jobs. Use narrowly
     scoped Job `kindRules` when generated names require them; do not add a
     blanket Job fallback merely to improve apparent coverage.
   - Avoid broad namespace fallbacks where privilege varies; unknown future
     components should fail loud.
3. `assignment-coverage.json`
   - Use top-level `context`, `inventoryTotal`, `assignments`,
     `configurationAssumptions`, and `summary` fields.
   - Add one `assignments` entry for every inventoried workload: `namespace`,
     `kind`, `name`, `securityImpactProfile`, `derivationMethod`, `vector`,
     `resolutionSource`, status
     (`operator-confirmed` or `agent-inferred`), confidence (`high`, `medium`,
     or `low`), `evidence`, `assumptions`, and `manualReview`.
   - Use an empty `manualReview` list only for high-confidence entries. Give
     every medium- or low-confidence entry at least one concrete verification
     item.
   - Record provisional Class, `multiAgency`, or external-ingress assumptions
     in a top-level `configurationAssumptions` list. Give each item `field`,
     `value`, `confidence`, `evidence`, `assumptions`, and `manualReview`
     fields.
   - Summarize counts by namespace, resolution source, status, and confidence.

If the operator explicitly requests direct-label overrides, also emit
`label-overrides.sh`. Begin it with `FOR OPERATOR REVIEW AND EXECUTION`, state
that the skill never runs it, and pin every suggestion to the reviewed
`--context`. Recommend moving accepted overrides into Helm or deployment
manifests. For CronJobs, put the profile in CronJob `metadata.labels` or
`spec.jobTemplate.spec.template.metadata.labels`; the plugin inventories the
CronJob and suppresses its generated Jobs. Do not rely on
`spec.jobTemplate.metadata.labels`, which the plugin does not score. Put an
override directly in one-shot and Helm-hook Job manifests.

Ask once whether any Ingress/Gateway class is fronted by a load balancer built
outside Kubernetes. Include `internetAccessibleIngressClasses` or
`internetAccessibleGatewayClasses` for high-confidence observed or
operator-confirmed classes. If outside-Kubernetes reachability is unanswered,
make a conservative best guess from active route objects, controller Services,
addresses, annotations, and class purpose. Annotate the key with confidence and
manual-review comments, and record the assumption in
`configurationAssumptions`. Do not invent Gateway classes when no active
Gateway objects exist. Omit the keys when the best-supported conclusion is
that there are none. When an omission is not high confidence, put confidence
and manual-review comments at the corresponding location in `scoring.yaml` and
also report the omission in the terminal.

Always write `vdr-fedramp.yaml` after a successful inventory and classification
pass, even when some assignments or configuration values are medium or low
confidence. Uncertainty belongs in comments and reports, not in a withheld
artifact.

Do not put PAIN word thresholds in the ConfigMap. Those remain governed
`--scoring-config` policy and are intentionally not cluster-overridable.

If the user supplies a proprietary-term deny-list, scan reusable content and
generated files case-insensitively. Parameterize a required namespace or
workload identifier rather than leaking it or targeting a guessed resource.

### 8. Validate without touching the cluster

Before handoff:

- parse the outer YAML and embedded `scoring.yaml`;
- verify every decision trace has three registered reasons and matching H/M/L
  values, every direct vector has three independent valid levels, and every
  named archetype resolves to its declared vector;
- verify every assignment rule or coherent rule group has a confidence comment
  and every non-high-confidence rule has a manual-review comment;
- verify Class, `multiAgency`, and emitted or provisionally omitted
  internet-accessibility keys have the required confidence and manual-review
  comments;
- verify all rule and label values resolve exactly without requiring trace
  duplication in the archetype catalog;
- verify all 27 vectors are represented when requested;
- check rule globs, ordering, and duplicate/shadowed entries;
- resolve every inventory entry using actual precedence: workload SIP label,
  namespace SIP label, `nameRule`, `kindRule`, `namespaceRule`, then default and
  fail-safe;
- fail validation if any workload resolves to `unclassified`, if an unknown or
  conflicting explicit label blocks its intended rule, or if any inventory
  entry is absent from `assignment-coverage.json`;
- verify the inventory equation: assignments equal the inventory total, with
  no duplicate workload entries; report the same accounting by namespace,
  resolution source, status, and confidence;
- verify every coverage entry has a valid confidence, evidence, assumptions,
  and manual-review shape, and every non-high-confidence entry has at least one
  manual-review item;
- verify every emitted assignment rule matches at least one inventoried
  workload unless the operator explicitly attests a forward-looking rule;
- when `label-overrides.sh` exists, run `bash -n` on it;
- print the mandatory confidence report with:

  ```bash
  python3 <skill-dir>/scripts/report_confidence.py \
    ./vdr-configmap-output/assignment-coverage.json
  ```

  Treat a nonzero exit as a validation failure. The report must print every
  medium- and low-confidence assignment and configuration assumption with the
  selected trace/value, evidence basis, and concrete manual-review action. It
  must print an explicit `none` result when all decisions are high confidence.
- run the proprietary-term deny-list scan when applicable;
- keep the `skills/` and `.agents/skills/` copies byte-identical.

When a sibling `trivy-plugin-vdr` checkout is available, prefer an offline
parser/smoke test against that implementation. Treat warnings about an invalid
cluster scoring config as failures even when the command exits zero.

Never execute any generated artifact.

## Handoff

Report the inventory total, operator-confirmed count, agent-inferred count,
confidence counts, and any precedence conflicts. Repeat the non-high-confidence
manual-review list in the terminal handoff; do not hide it behind the YAML.
Do not call generation complete when the accounting rule fails. Tell the
operator to review all required files and apply the ConfigMap manually or
through the owning GitOps repository. Mention label overrides only when they
were explicitly requested. Re-run the skill after estate, Class, scope, policy,
or reviewed assumptions change.
