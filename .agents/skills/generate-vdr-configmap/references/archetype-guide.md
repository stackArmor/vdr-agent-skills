# Compositional archetype attestation guide

Use this guide to turn operator answers and read-only evidence into an auditable
decision trace and deterministic CR/IR/AR vector.

## Contents

1. [Model](#model)
2. [Reason registries](#reason-registries)
3. [Five-question interview](#five-question-interview)
4. [Availability calibration](#availability-calibration)
5. [Classification rules](#classification-rules)
6. [All 27 vectors](#all-27-vectors)
7. [Reusable examples](#reusable-examples)
8. [Runtime compilation and resolution](#runtime-compilation-and-resolution)

## Model

The archetype value is a compact decision trace:

```text
<disclosure>.<trusted-change>.<dependency>
```

- The disclosure reason determines Confidentiality Requirement (CR).
- The trusted-change reason determines Integrity Requirement (IR).
- The dependency reason determines Availability Requirement (AR).

Each reason maps to exactly one level: Low, Medium, or High. The combined value
must be no longer than 63 characters and must satisfy Kubernetes label-value
syntax. It explains *why* the vector applies while remaining machine-checkable.

H, M, and L have their normal CVSS v3.1 environmental weights: 1.5, 1.0, and
0.5. Choose each dimension independently; do not start from a single product
category and copy one preset vector.

## Reason registries

### Disclosure -> CR

| Level | Allowed reasons | Meaning |
|---|---|---|
| L | `public-content`, `opaque-transit`, `routing-metadata`, `synthetic-data` | Disclosure is intentionally public, opaque, structural only, or synthetic. |
| M | `service-content`, `ops-metadata`, `security-evidence`, `control-metadata`, `scoped-access` | Disclosure affects private service content, operational/control evidence, or a bounded credential. |
| H | `federal-records`, `regulated-data`, `restricted-evidence`, `root-secrets`, `privileged-access` | Disclosure exposes federal/regulated records, restricted evidence, durable trust material, or broad administrative capability. |

### Trusted change -> IR

| Level | Allowed reasons | Meaning |
|---|---|---|
| L | `advisory-output`, `opaque-forwarding`, `disposable-state`, `isolated-testing` | Output is advisory, forwarding cannot alter plaintext, state is disposable, or changes remain isolated. |
| M | `bounded-processing`, `scoped-write`, `record-keeping`, `coordination-state` | Corruption affects a bounded processor, scoped write path, non-authoritative record, or coordination state. |
| H | `authoritative-record`, `config-control`, `identity-control`, `security-enforcement`, `release-control`, `foundation-control`, `trust-anchor` | Corruption changes authoritative data, configuration, identity, enforcement, releases, shared foundations, or trust roots. |

### Dependency/outage -> AR

| Level | Allowed reasons | Meaning |
|---|---|---|
| L | `deferrable-work`, `optional-tooling`, `nonproduction` | Work can wait, the feature is optional, or the operator attests truly low-impact nonproduction use. |
| M | `bounded-service`, `operations-support`, `shared-degradation`, `change-deferred` | A bounded service or operations capability degrades, or changes must wait. |
| H | `shared-critical-path`, `mission-essential`, `protection-critical`, `recovery-critical` | Loss blocks a shared path, mission function, mandatory protection, or recovery/failover. |

Use the most explanatory reason when several reasons map to the same level.
Never invent a new token ad hoc; update the governed registry and validator
first.

## Five-question interview

Ask these questions for one workload or a coherent group:

1. **Environment intent:** Should this environment mirror production impact,
   or is it explicitly isolated and low impact?
2. **Disclosure:** What data, credentials, or administrative capability could
   compromise expose?
3. **Trusted change:** What record, action, identity, configuration, or control
   could compromise alter?
4. **Population:** Would complete logical loss affect CSP operators, a bounded
   user subset, or all users?
5. **Consequence:** Ignoring HA and failover, would that loss be limited,
   serious, severe, recovery-critical, or protection-critical?

Class and `multiAgency` are separate required attestations. Population does not
set `multiAgency`, and `multiAgency` does not select an archetype.

An environment name is not evidence of low impact. When the operator chooses
production equivalence, use production data types, authority, and outage
consequences even if current test data is synthetic and isolated.

## Availability calibration

Start with consequence, then use affected population as supporting evidence:

| Affected population | Limited consequence | Serious consequence | Severe consequence |
|---|---:|---:|---:|
| CSP-internal operators | L | M | H |
| Bounded user subset | L | M | H |
| All/systemwide users | M | H | H |

Population is not an automatic multiplier. A systemwide optional feature can
still be Medium, while a bounded recovery or protection function can be High.
Document the causal consequence.

### HA is separate

Do not lower AR because the workload has replicas, zones, failover, a disruption
budget, or an autoscaler. Security requirements describe the consequence of
complete logical loss of the workload class. A shared vulnerability can affect
every replica. Record HA as mitigation evidence outside the CR/IR/AR vector.

For persistent-storage drivers, distinguish the driver from the data store.
A node-side CSI driver can still be `recovery-critical` when its loss prevents
new mounts, rescheduling, failover, or restoration across stateful services.

## Classification rules

1. Establish whether production-equivalent scoring applies.
2. Inspect structural evidence: workload spec, service account, RBAC, routing,
   webhooks, host access, resource references, and dependency edges.
3. Select the strongest credible consequence separately for CR, IR, and AR.
4. Join the three exact reasons with dots and mechanically derive the vector.
5. Show the trace, vector, evidence, assumptions, and confidence to the
   operator. Assign it only after explicit confirmation.

### Privilege and control

- Broad Secret access, service-account token creation, IAM/RBAC mutation,
  deployment mutation, impersonation, or cross-service administration supports
  `privileged-access` and a High integrity control reason.
- A service account is not itself a secret. Use `scoped-access` for bounded
  workload credentials and `privileged-access` only for broad authority.
- Merely referencing a Secret does not make a workload `root-secrets`. Use that
  reason when durable trust keys, signing keys, session roots, or cross-estate
  credentials are central to the role.
- Privileged mode, host namespaces, writable host mounts, runtime sockets, and
  powerful capabilities can justify `foundation-control` even when the product
  name sounds like simple tooling.

### Data and telemetry

- Log processors inherit the most sensitive content logs may contain. Email
  addresses, identifiers, payload fragments, or credentials support
  `regulated-data` rather than `ops-metadata`.
- Metrics without payload remain `ops-metadata`; do not elevate them merely
  because they support monitoring.
- A payload broker and system-of-record database may both use
  `regulated-data.authoritative-record`, while a telemetry-only bus should use
  operational or security metadata reasons.
- Backups inherit the protected data type. Use `recovery-critical` only when
  loss of the backup capability creates severe recovery consequences.

### Ownership and managed components

- Namespace is not ownership. Customer-installed add-ons in system namespaces
  should receive direct workload labels.
- Use narrow `nameRules` for provider-controlled workloads that cannot retain
  customer labels.
- Avoid broad namespace fallbacks where privilege varies. An unfamiliar future
  add-on should remain `unclassified` H/H/H until attested.
- An inactive platform or OS-specific variant still needs an intended-role
  attestation. Do not lower it from replica count alone.
- Inventory and attest standalone and custom-owned Jobs. Suppress Jobs whose
  controller owner is a CronJob, which represents the repeated execution.
  Apply the durable trace in CronJob `metadata.labels` or
  `spec.jobTemplate.spec.template.metadata.labels`; do not use
  `spec.jobTemplate.metadata.labels`, which the plugin does not score. Apply
  the trace directly in one-shot or Helm-hook Job manifests.
- Node-owned static or mirror Pods can remain independently visible to the
  plugin even when they implement the same role as a managed node component.
  Cover them with a narrow, stable provider prefix rule rather than embedding
  node-specific suffixes or assuming another controller will suppress them.

## All 27 vectors

The registry supports all 27 permutations. These canonical traces are coverage
representatives, not automatic workload assignments:

| Vector | Canonical trace |
|---|---|
| L/L/L | `public-content.advisory-output.deferrable-work` |
| L/L/M | `public-content.advisory-output.bounded-service` |
| L/L/H | `public-content.advisory-output.shared-critical-path` |
| L/M/L | `public-content.bounded-processing.deferrable-work` |
| L/M/M | `public-content.bounded-processing.bounded-service` |
| L/M/H | `public-content.bounded-processing.shared-critical-path` |
| L/H/L | `public-content.authoritative-record.deferrable-work` |
| L/H/M | `public-content.authoritative-record.bounded-service` |
| L/H/H | `public-content.authoritative-record.shared-critical-path` |
| M/L/L | `service-content.advisory-output.deferrable-work` |
| M/L/M | `service-content.advisory-output.bounded-service` |
| M/L/H | `service-content.advisory-output.shared-critical-path` |
| M/M/L | `service-content.bounded-processing.deferrable-work` |
| M/M/M | `service-content.bounded-processing.bounded-service` |
| M/M/H | `service-content.bounded-processing.shared-critical-path` |
| M/H/L | `service-content.authoritative-record.deferrable-work` |
| M/H/M | `service-content.authoritative-record.bounded-service` |
| M/H/H | `service-content.authoritative-record.shared-critical-path` |
| H/L/L | `regulated-data.advisory-output.deferrable-work` |
| H/L/M | `regulated-data.advisory-output.bounded-service` |
| H/L/H | `regulated-data.advisory-output.shared-critical-path` |
| H/M/L | `regulated-data.bounded-processing.deferrable-work` |
| H/M/M | `regulated-data.bounded-processing.bounded-service` |
| H/M/H | `regulated-data.bounded-processing.shared-critical-path` |
| H/H/L | `regulated-data.authoritative-record.deferrable-work` |
| H/H/M | `regulated-data.authoritative-record.bounded-service` |
| H/H/H | `regulated-data.authoritative-record.shared-critical-path` |

Run `scripts/reason_codes.py --cover-27 <confirmed-trace>...` to add only the
canonical entries needed to fill gaps left by the confirmed workload traces.

## Reusable examples

| Role and evidence | Decision trace | Vector |
|---|---|---:|
| Static public content; bounded module | `public-content.bounded-processing.bounded-service` | L/M/M |
| Private API; bounded data processing and outage | `service-content.bounded-processing.bounded-service` | M/M/M |
| System-of-record with sensitive records on a shared path | `regulated-data.authoritative-record.shared-critical-path` | H/H/H |
| Log collector whose records may contain identifiers | `regulated-data.record-keeping.operations-support` | H/M/M |
| Payload-free metrics collector | `ops-metadata.record-keeping.operations-support` | M/M/M |
| Shared identity service holding durable keys | `root-secrets.identity-control.shared-critical-path` | H/H/H |
| Administrative migration job | `privileged-access.config-control.change-deferred` | H/H/M |
| Cluster DNS | `routing-metadata.foundation-control.shared-critical-path` | L/H/H |
| End-to-end encrypted control tunnel | `routing-metadata.opaque-forwarding.shared-critical-path` | L/L/H |
| Privileged node-side persistent-disk driver | `privileged-access.foundation-control.recovery-critical` | H/H/H |
| Sensitive-data backup required for restoration | `regulated-data.authoritative-record.recovery-critical` | H/H/H |
| Secret reconciler whose outage delays rotation | `root-secrets.identity-control.change-deferred` | H/H/M |

These are patterns, not name-based defaults. Confirm the actual role and
consequence for the target estate.

## Runtime compilation and resolution

The current plugin resolves the label value as an exact archetype key; it does
not derive the vector from the three segments. Compile every used trace:

```yaml
archetypes:
  privileged-access.foundation-control.recovery-critical:
    {lens: composite, cr: H, ir: H, ar: H}
```

Validate segment order, token membership, label length, and declared vector
before emission. Every rule and suggested label must reference an exact catalog
entry.

Resolution remains most-specific-first:

```text
workload archetype label
  -> namespace archetype label
  -> name rule
  -> kind rule
  -> namespace rule
  -> unclassified H/H/H fail-safe
```

An unknown explicit label does not fall through to a quieter rule; it reaches
the fail-safe. This protects against typo-based downgrades.
