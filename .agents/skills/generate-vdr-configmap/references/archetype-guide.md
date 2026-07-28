# Asset security-impact profile classification guide

Use this guide to turn operator answers and read-only evidence into an auditable
decision trace and deterministic CR/IR/AR vector.

## Contents

1. [Model](#model)
2. [Reason registries](#reason-registries)
3. [Five-question interview](#five-question-interview)
4. [Availability calibration](#availability-calibration)
5. [Classification rules](#classification-rules)
6. [Confidence and review](#confidence-and-review)
7. [The catalog](#the-catalog)
8. [All 27 vectors](#all-27-vectors)
9. [Reusable examples](#reusable-examples)
10. [Runtime representation and resolution](#runtime-representation-and-resolution)

## Model

The required model is an independently dimensional CR/IR/AR asset
security-impact profile. The runtime accepts a direct vector such as
`cr-h_ir-m_ar-l`, a named entry from the optional archetype catalog, or a
compact compositional decision trace:

```text
<disclosure>.<trusted-change>.<dependency>
```

- The disclosure reason determines Confidentiality Requirement (CR).
- The trusted-change reason determines Integrity Requirement (IR).
- The dependency reason determines Availability Requirement (AR).

Each trace reason maps to exactly one level: Low, Medium, or High. The combined value
must be no longer than 63 characters and must satisfy Kubernetes label-value
syntax. It explains *why* the vector applies while remaining machine-checkable.

H, M, and L have their normal CVSS v3.1 environmental weights: 1.5, 1.0, and
0.5. Choose each dimension independently; do not start from a single product
category and copy one preset vector. Prefer a decision trace when no other
governed method preserves equivalent rationale. A direct vector preserves
dimensional independence but needs an external evidence record; a named
archetype is a reusable assignment convention, not the required model.

If a CSP uses scalar asset value upstream, it must translate High, Medium, or
Low to `cr-h_ir-h_ar-h`, `cr-m_ir-m_ar-m`, or `cr-l_ir-l_ar-l` before runtime
assignment. There is no separate asset-value label or rule field. Record that
lossy derivation because it forces CR, IR, and AR equal and erases the
independent reason chain.

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

Class and `multiAgency` are separate configuration decisions. Record operator
attestations when provided and clearly mark provisional agent inferences when
they are not. Population does not set `multiAgency`, and `multiAgency` does not
select a security-impact profile.

An environment name is not evidence of low impact. When the operator chooses
production equivalence, use production data types, authority, and outage
consequences even if current test data is synthetic and isolated.

When the operator delegates workload-level judgment or gives a range such as
"potentially all, depending on workload," stop repeating broad questions. Use
the inventory, routing, RBAC, and common workload role to select the strongest
credible consequence for each dimension. Preserve uncertainty in confidence
and manual-review notes instead of leaving the workload unassigned.

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
   operator. Assign the best-supported trace even when confirmation is
   unavailable; distinguish operator-confirmed from agent-inferred decisions.

## Confidence and review

Confidence measures evidence quality, not impact severity:

| Confidence | Use when | Required output |
|---|---|---|
| High | The operator directly attests the assignment, or structural evidence unambiguously establishes the role and all three impact dimensions. | Record the evidence and an empty manual-review list. |
| Medium | The role is well supported, but at least one impact dimension depends on a conventional inference about data, authority, population, or consequence. | State the assumption and a concrete verification action. |
| Low | Evidence is sparse, conflicting, mostly name-based, or depends on infrastructure outside Kubernetes. | Choose the strongest credible consequence and prominently identify what could change it. |

Do not convert uncertainty into a quieter vector. If both Medium and High
consequences are credible, select High and describe the evidence needed to
lower it. Do not assign `unclassified` merely because an operator did not
answer; ordinary uncertainty produces a medium- or low-confidence inferred
trace.

In `vdr-fedramp.yaml`, put a confidence comment immediately above every
assignment rule or coherent rule group. Put a manual-review comment beside
every medium- or low-confidence rule. Mirror the same information structurally
in `assignment-coverage.json` so terminal reporting is deterministic.

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

- Namespace is not ownership, and ownership does not select the assignment
  mechanism. Put every inventoried workload in the central ConfigMap assignment
  plan, including customer applications and third-party add-ons.
- Prefer exact `nameRules`. Use a narrow stable pattern only when every current
  match is a coherent assigned group. Direct workload labels are optional
  operator-requested overrides, not the default assignment mechanism.
- Avoid broad namespace fallbacks where privilege varies. An unfamiliar future
  add-on should remain `unclassified` H/H/H until classified.
- Classify an inactive platform or OS-specific variant by its intended role.
  Do not lower it from replica count alone.
- Inventory and classify standalone and custom-owned Jobs. Suppress Jobs whose
  controller owner is a CronJob, which represents the repeated execution.
  Assign the CronJob with a central rule. If the operator requests a direct
  label override, put the durable trace in CronJob `metadata.labels` or
  `spec.jobTemplate.spec.template.metadata.labels`; do not use
  `spec.jobTemplate.metadata.labels`, which the plugin does not score. Give
  one-shot and Helm-hook Jobs explicit central rules; use a namespace- and
  name-scoped `kindRule` when generated names defeat exact `nameRules`.
- Node-owned static or mirror Pods can remain independently visible to the
  plugin even when they implement the same role as a managed node component.
  Cover them with a narrow, stable provider prefix rule rather than embedding
  node-specific suffixes or assuming another controller will suppress them.

The following catalog is an illustrative optional archetype assignment system,
not the SIP data model. A CSP may use these names, direct vectors, the
decision-trace method above, or another governed method that produces
independent CR/IR/AR profiles. Runtime transport remains the single SIP field
and label in every case.

## The catalog

<!-- Generated by sync-vdr-policy; edit trivy-plugin-vdr/policy/vdr-policy.yaml. -->
<!-- Source SHA-256: d1a33738f164b7df94a6eb9500f69104158da2002e20dc8912813510e21e4f47 -->

CR/IR/AR: H = High (1.5), M = Medium (1.0), L = Low (0.5) in the CVSS v3.1
environmental formula. This catalog is the plugin's built-in rubric; a CSP may
override entries via the ConfigMap's embedded `scoring.yaml`, but should own
and justify any change.

| Archetype | Lens | CR | IR | AR | Typical members |
|---|---|---|---|---|---|
| `cicd-pipeline` | control | H | H | M | build and deployment runners, artifact signing services, artifact registries |
| `orchestrator` | control | M | M | H | control planes, etcd and schedulers, coordination services, CNI and CSI controllers |
| `config-actuation` | control | M | H | M | IaC and GitOps controllers, schema registries, administrative and migration jobs |
| `identity-secrets` | control | H | M | M | identity providers and SSO, KMS and secrets managers, session and token stores |
| `privileged-identity` | control | H | H | M | organization, account, subscription, and project administrators, IAM roles and service accounts that can mutate IAM policy, identities with deployment, impersonation, or broad cross-service access |
| `scoped-identity` | control | M | H | M | workload service accounts, IAM roles constrained to one application or service, identities without privilege escalation or broad administrative access |
| `security-tooling` | control | M | H | M | scanners and SIEM, EDR and runtime security, admission policy |
| `change-record` | control | M | M | M | ITSM and ticketing systems that record but do not actuate changes |
| `platform-foundation` | control | L | H | H | DNS and NTP, service discovery, metadata-only L4 internal load balancers |
| `data-sensitive` | data | H | H | M | PII and CUI datastores |
| `public-data` | data | L | M | M | intentionally public storage buckets, public datasets and static downloads |
| `telemetry-data` | data | M | M | M | log archives, metrics and trace storage, operational audit data without regulated payloads |
| `data-backbone` | data | H | H | M | payload queues and brokers, system-of-record databases |
| `telemetry-backbone` | data | M | M | M | metrics and trace pipelines, telemetry queues, event buses carrying no agency payload |
| `app-tier` | data | M | M | M | stateless services and APIs, user interfaces, caches |
| `batch-analytics` | data | M | M | L | ETL, reporting, analytics jobs |
| `public-edge` | data | M | M | H | TLS-terminating ingress and gateways, public web front doors |
| `passthrough-edge` | data | L | L | H | L4 and SNI passthrough, managed load balancers whose keys remain outside the boundary |
| `internal-tooling` | data | L | L | L | dashboards, metrics and log agents |
| `dev-test` | data | L | L | L | non-production workloads |
| `generic-high` | generic | H | H | H | coarsely classified high-impact assets |
| `generic-medium` | generic | M | M | M | coarsely classified moderate-impact assets |
| `generic-low` | generic | L | L | L | coarsely classified low-impact assets |
| `unclassified` | control | H | H | H | fail-safe default for untagged assets |

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

Run `scripts/reason_codes.py --cover-27 <assigned-trace>...` to add only the
canonical entries needed to fill gaps left by the assigned workload traces.

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

These are patterns, not name-based defaults. Determine the actual role and
consequence from target-estate evidence. When evidence remains incomplete,
apply the closest defensible pattern with medium or low confidence and report
the needed review.

## Runtime representation and resolution

The plugin resolves all three profile representations natively:

```yaml
nameRules:
  - {namespace: recovery, match: disk-controller, securityImpactProfile: privileged-access.foundation-control.recovery-critical}
  - {namespace: records, match: archival-export, securityImpactProfile: cr-h_ir-m_ar-l}
  - {namespace: platform, match: cluster-dns, securityImpactProfile: platform-foundation}
```

The first rule uses a decision trace, the second a direct vector, and the third
an illustrative named archetype. Do not compile decision traces into duplicate
`archetypes` entries. Validate segment order, token membership, label length,
and derived vector before emission. A named value must resolve to an exact
catalog entry.

Resolution remains most-specific-first:

```text
workload vdr.fedramp.io/security-impact-profile label
  -> namespace security-impact-profile label
  -> name rule
  -> kind rule
  -> namespace rule
  -> unclassified H/H/H fail-safe
```

An unknown explicit label does not fall through to a quieter rule; it reaches
the fail-safe. This protects against typo-based downgrades.
