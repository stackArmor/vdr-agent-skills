# Security objectives derivation guide

Turn operator answers, product/agency research, and read-only cluster evidence
into an auditable per-component Security Requirements vector. No real product,
vendor, or agency names appear in this guide or in any example artifact; use
generic system-type language when writing reusable content.

## Contents

1. [Model](#model)
2. [Combination math](#combination-math)
3. [Breakout categories](#breakout-categories)
4. [Calibration rules](#calibration-rules)
5. [System-type starting profiles](#system-type-starting-profiles)
6. [Wizard question bank](#wizard-question-bank)
7. [Class-vs-data divergence protocol](#class-vs-data-divergence-protocol)
8. [Multi-agency determination](#multi-agency-determination)
9. [Component-objective methodology](#component-objective-methodology)
10. [Confidence and review](#confidence-and-review)
11. [Artifact schemas](#artifact-schemas)
12. [Runtime mechanics](#runtime-mechanics)

## Model

Three per-objective vectors, each `{C, I, A}` over `{L, M, H}` with L < M < H:

- **System Security Objectives (SSO):** what the product holds and does by
  design — from consented web research the operator confirms, the data-type
  checklist, ingestion/contamination paths, and the agency-device footprint.
- **Agency Security Objectives (ASO):** a per-objective estimate of the data
  the deploying agency would actually place in this system. Never the agency's
  overall FIPS 199 high-water mark; always objective-level. Grounded in agency
  research, statutory/contractual overlays, and any known objective-level
  categorization from solicitations, privacy impact assessments, or the agency
  authorization package.
- **Component Security Objectives (CSO):** the per-workload role evaluation
  from structural evidence and focused impact questions (section 9).

CR/IR/AR carry the standard CVSS environmental weights (H=1.5, M=1.0, L=0.5)
at runtime; this guide only decides which letter each component gets.

## Combination math

Per objective `o` in `{C, I, A}`:

```text
envelope(o) = min(SSO(o), ASO(o))    # agency caps system; a higher agency value never raises it
final(o)    = min(CSO(o), envelope(o))
```

The envelope is only ever a cap, never a floor. Contamination evidence raises
SSO during the wizard; role evidence raises CSO; the formula itself raises
nothing. Record the raw CSO and the final vector for every component, with a
per-objective `capped` flag, so every cap is visible in review.

Compute with `scripts/derive_requirements.py --derive <input.json>` — never by
hand. The script also rejects malformed breakouts.

Worked example (generic): a project-management SaaS deployed for one agency.
SSO `{M, M, M}` (durable planning records; permanent loss is serious), ASO
`{M, M, L}` (agency places moderate planning data; loss of this instance is
limited for them) → envelope `{M, M, L}`. A system-of-record database with CSO
`{H, H, M}` finalizes at `{M, M, L}` — all three capped, all three recorded. An
update service that ships endpoint agents to agency devices with CSO
`{M, H, L}` takes an integrity breakout and finalizes at `{M, H, L}`.

## Breakout categories

A component may exceed the envelope on an objective only when its compromise
reaches beyond the system's own data. The closed list:

| Category token | Meaning |
|---|---|
| `agency-endpoint-delivery` | Delivery, update, or control paths for software installed on agency devices. Compromise executes on endpoints outside the boundary. |
| `cross-system-trust-anchor` | Trust anchors and durable key material honored beyond this system (federation signing, cross-estate credentials). |
| `shared-csp-infrastructure` | Shared provider infrastructure whose blast radius exceeds this authorization boundary. |

Rules:

- A breakout restores `final(o) = CSO(o)` for that objective only.
- A breakout is valid only when `CSO(o)` exceeds the envelope; declaring one
  that does not change the result is an input error (fix the narrative).
- Every breakout carries a written justification and at least one
  manual-review item; a breakout assignment is never `high` confidence.
- Extending this list is a governed edit to this guide and the validators in
  `derive_requirements.py` and `report_confidence.py` — never an ad hoc
  decision during a run.

## Calibration rules

- **Federal-sourced data is the primary High driver.** Direct access to,
  processing of, or transit of actual federal-government-sourced records
  drives C and I toward High.
- **Vulnerability and change data are C:M baseline.** Raw vulnerability scans
  and change-management records rate Moderate confidentiality at most, even
  with strong asset correlation: capable adversaries continuously and
  autonomously probe internet-accessible systems, so possession of a
  vulnerability inventory accelerates them less than it once did. An operator
  may raise this with a written justification; do not raise it by default.
- **Availability means complete logical loss, including durable records.**
  Assess system and agency availability objectives against permanent loss of
  the system and its records — not transient outage tolerance. A
  downtime-tolerant system whose permanent record loss would be a serious
  adverse effect rates A:M or higher. Reserve A:L for genuinely ephemeral or
  reconstructible systems. (This mirrors the component rule: HA never lowers
  AR.)
- **Contamination raises SSO.** Uploads, attachments, free-text fields, and
  feeds from agency systems are where higher-impact content leaks into a
  nominally moderate boundary. Confirmed ingestion paths raise the affected
  SSO objectives; the categorization is usually fine — the boundary
  enforcement is the finding.
- **Agency-device footprint raises the stakes.** Software the system installs
  on agency endpoints (logging, SSO, EDR agents) extends the blast radius
  beyond the system's data and makes the components that ship or control that
  software breakout candidates.

## System-type starting profiles

Starting estimates only — the wizard must confirm or adjust every value.
These are rough profiles by system type, not named products.

| System type | C | I | A | Drivers |
|---|---|---|---|---|
| Project & portfolio management | M | M | M | Portfolio aggregation, PII linkage, durable planning records |
| Legal case management | H | H | M | Privileged/litigation material; legally operative records |
| Electronic medical records | H | H | H | Health records; care delivery cannot pause |
| Security operations / SIEM | M | H | H | Telemetry with identifiers (C:M baseline); alert integrity and protection-critical availability |
| EDR / endpoint management | M | H | H | Agent control channel is code execution on managed endpoints |
| Identity / SSO provider | H | H | H | Credentials and durable trust material |
| Vulnerability management | M | M | M | C:M baseline per calibration |
| Change management / ITSM | M | M | M | Change records drive production change; C:M baseline |
| Document / records management | L-H | M | M | C tracks the stored corpus |
| Learning management | L-M | M | L-M | Mostly public content; workforce rosters raise C |

## Wizard question bank

Ask with the stated why. Unanswered questions never block generation: make the
strongest evidence-backed inference, mark confidence, and add manual-review
items. Never present an inference as an operator attestation.

**Phase A — system identity → SSO**

1. What company and product is this system? May I research it on the public
   web? *(Why: public documentation establishes the product's data profile by
   design; you confirm what I derive.)*
2. Here is the description I derived — what is wrong or missing?
   *(Why: research is an estimate; the system objectives rest on the
   confirmed purpose.)*
3. Which data types are in scope: federal-government-sourced records, PII and
   sensitive PII, CUI, tax information, health information, criminal-justice
   information, legal-privileged material, financial/confidential business
   information, security telemetry, change/configuration data, public
   content? *(Why: each type maps to per-objective drivers under the
   calibration rules.)*
4. Can users or integrations introduce content beyond the designed data model
   — uploads, attachments, free-text fields, email ingest, API feeds from
   agency systems? *(Why: contamination paths are where higher-impact content
   leaks into a moderate boundary; confirmed paths raise the system
   objectives.)*
5. Does the system require software on agency devices (logging, SSO, EDR
   agents)? Which cluster components ship, update, or control them?
   *(Why: endpoint software extends compromise beyond the system's data and
   drives breakout eligibility.)*
6. Are any records legally operative or decision-driving, and what is the
   consequence of permanent record loss — not just downtime?
   *(Why: integrity and availability objectives need more than a
   confidentiality story; availability is assessed against complete logical
   loss.)*

**Phase B — agency → ASO**

7. Which agency or agencies actually use this deployment? "None yet" is fine.
   *(Why: the deploying agency's data propensity sets the per-objective
   ceiling on component requirements.)*
8. If none is definite: which agencies are you targeting? *(Why: target
   agencies guide the data-profile estimate only; they are never evidence of
   multi-agency scope.)*
9. For each agency, here is my per-objective estimate of the data they would
   place in this system, with rationale — confirm or adjust. Which statutory
   or contractual overlays are in scope (tax, criminal-justice, health,
   confidentiality statutes, data-use agreements)? *(Why: overlays are often
   the binding constraint and determine whether an authorizing official can
   accept risk at all.)*
10. Do you know the objective-level categorization from a solicitation,
    privacy impact assessment, or the agency authorization package?
    *(Why: an actual categorization beats any estimate.)*

**Phase C — authorization and scope**

11. What FedRAMP authorization does the offering hold (Ready → A, Low → B,
    Moderate → C, High → D)? *(Why: the Class selects the remediation
    deadline table, and serves as a prior for the divergence protocol — it is
    never authority over the data profile.)*
12. Are multiple agencies served from this cluster, and where is the tenancy
    boundary — whole cluster or per namespace? *(Why: a compromise that
    crosses agencies raises the PAIN tier; namespace tenancy is delivered
    centrally without labeling.)*
13. Should this environment use production-equivalent values, or is it an
    intentionally isolated low-impact environment? *(Why: environment names
    never establish impact.)*

**Phase D — per component** (per coherent workload group, at most five)

14. What could disclosure from this component expose?
15. What trusted action, record, identity, or control could compromise alter?
16. Who is affected by complete logical loss: operators, a bounded subset, or
    all users?
17. Ignoring replicas and failover, is that loss limited, serious, severe, or
    recovery/protection critical?

## Class-vs-data divergence protocol

Per objective, for each agency:

1. Build the ASO estimate blind to Class: research + confirmed data types +
   overlays.
2. Derive the Class prior: D → expect High-impact data in scope; C →
   Moderate; B → Low; A → treat as B unless evidence says otherwise.
3. Compare:
   - **Agreement:** ASO = estimate; record Class as corroborating evidence
     (raises confidence).
   - **Estimate below prior** (moderate data on a High authorization):
     surface the divergence and ask the operator to attest what actually
     lands in this deployment — agencies commonly over-house moderate data on
     High platforms out of risk aversion. An attested lower value wins and is
     recorded operator-confirmed with the divergence preserved. Unanswered:
     the prior (higher value) wins at low confidence with a manual-review
     item. Never lower on an unconfirmed inference.
   - **Estimate above prior** (High data on a Moderate authorization): ASO
     stays at the estimate — Class never caps ASO. Statutory or contractual
     driver: add a prominent manual-review item noting an authorizing
     official cannot accept that risk on someone else's behalf. Agency
     categorization driver: record it as explicit risk-acceptance territory.
4. Record estimate, prior, divergence, resolution, and attestation status in
   `security-objectives.json` under `classPrior.divergences`.

## Multi-agency determination

- Cluster scope, `multiAgency: "true"`: compromise of the cluster can affect
  several agencies and tenancy is not namespace-partitioned.
- Namespace scope: cluster default `"false"` plus `multiAgencyNamespaces`
  globs in the embedded scoring document — central delivery, no labeling.
  Namespace/workload `vdr.fedramp.io/multi-agency` labels stay available as
  operator-applied exceptions, not the default mechanism.
- Never inferred from workload population, and never inferred from a
  target-agency list supplied for data profiling.
- Record scope, values, and justification in `security-objectives.json`.

## Component-objective methodology

Determine each component's role from structural evidence, then select the
strongest credible consequence per objective. Privilege evidence outweighs
product naming.

Evidence to inspect: workload spec and owner references; service account and
RBAC (Roles, ClusterRoles, bindings); Service/Ingress/Gateway routing;
validating and mutating webhooks; host access (privileged mode, host
PID/network/IPC, writable host mounts, runtime sockets, added capabilities);
Secret/ConfigMap/PVC references; node selectors; dependency edges.

Strong privilege signals: broad Secret access, service-account token
creation, IAM/RBAC mutation, `pods/exec`, workload mutation, privileged mode,
host namespaces, writable host mounts, runtime sockets, powerful Linux
capabilities.

Confidentiality (component): what the component can read or is entrusted
with — service payloads, credentials, administrative capability. A bounded
workload credential is not broad privileged access; referencing a Secret does
not make a component a trust anchor.

Integrity (component): what corruption of the component can alter —
authoritative records, configuration, identity, enforcement, releases, shared
foundations, trust roots rate High; bounded processors and scoped writes rate
Medium; advisory output and disposable state rate Low.

Availability (component): the consequence of complete logical loss of the
workload class across all replicas. HA, replicas, zones, disruption budgets,
and autoscalers never lower AR — record them as mitigating evidence outside
the vector. Population informs consequence but is not a multiplier. For
storage drivers, distinguish the driver from the data store: a node-side
driver can still be recovery-critical when its loss prevents mounts,
rescheduling, failover, or restoration.

Telemetry: log processors inherit the most sensitive content logs may
contain; payload-free metrics stay moderate operational metadata. Backups
inherit the protected data type.

Environment names never establish impact. When the operator requires
production parity, classify nonproduction workloads by intended production
data and consequences even when current data is synthetic.

Ownership and mechanism: namespace is not ownership, and ownership never
selects the assignment mechanism. Every inventoried workload gets a central
ConfigMap rule — provider-controlled, customer-controlled, third-party, and
application workloads alike. Prefer exact `nameRules`; use a narrow stable
pattern only when every current match shares the same final vector; use a
`namespaceRule` only when every relevant workload in the namespace shares the
same final vector; treat `kindRules` as exceptional. Give standalone and
Helm-hook Jobs explicit rules; suppress CronJob-owned Jobs (the CronJob is the
durable scorable workload).

## Confidence and review

Confidence measures evidence quality, never impact severity.

| Confidence | Use when | Required output |
|---|---|---|
| high | Direct operator attestation, or structural evidence unambiguously establishes the role and all three objectives. | Evidence recorded; empty manual-review list. |
| medium | Role well supported, but at least one objective relies on a conventional inference about data, authority, population, or consequence. | State the assumption and a concrete verification action. |
| low | Evidence sparse, conflicting, name-based, or dependent on infrastructure outside Kubernetes. | Choose the strongest credible consequence and identify what would change it. |

Never lower a vector because confidence is low. When Medium and High are both
credible, select High and state what evidence would lower it. Breakout
assignments are never high confidence. Reserve `unclassified` for technical
validation failures, never as a substitute for best-effort assignment.

## Artifact schemas

`security-objectives.json` (validated by `report_confidence.py`):

```json
{
  "systemProfile": {
    "product": "generic product name",
    "confirmedDescription": "operator-confirmed purpose and data summary",
    "dataTypes": ["..."],
    "contaminationPaths": ["..."],
    "agencyDeviceFootprint": {"present": false, "agents": [], "controllingComponents": []},
    "sso": {"c": {"level": "M", "rationale": "..."},
             "i": {"level": "M", "rationale": "..."},
             "a": {"level": "M", "rationale": "..."}},
    "status": "operator-confirmed",
    "confidence": "high",
    "assumptions": [],
    "manualReview": []
  },
  "agencyProfiles": [
    {"agency": "...", "relationship": "definite",
     "overlays": [{"name": "...", "statuteGrounded": true}],
     "aso": {"c": {"level": "M", "rationale": "..."},
              "i": {"level": "M", "rationale": "..."},
              "a": {"level": "L", "rationale": "..."}},
     "status": "operator-confirmed", "confidence": "high",
     "assumptions": [], "manualReview": []}
  ],
  "classPrior": {"class": "C", "divergences": []},
  "sso": {"c": "M", "i": "M", "a": "M"},
  "aso": {"c": "M", "i": "M", "a": "L"},
  "envelope": {"c": "M", "i": "M", "a": "L"},
  "ceilingMode": "semi-hard",
  "multiAgencyDetermination": {
    "scope": "cluster", "clusterDefault": false,
    "justification": "...", "status": "operator-confirmed",
    "confidence": "high", "assumptions": [], "manualReview": []}
}
```

Rules: top-level `envelope` must equal per-objective `min(sso, aso)`;
`systemProfile.sso` levels must match top-level `sso`; with definite agency
profiles, top-level `aso` equals the per-objective max over them; namespace
scope requires non-empty `multiAgencyNamespaces`. Optional fields —
`systemProfile.dataTypes`, `systemProfile.contaminationPaths`,
`systemProfile.agencyDeviceFootprint`, and a `governingSource` string on each
divergence — are recorded when known; the gate tolerates and ignores extra
keys.

`assignment-coverage.json`: top-level `context`, `inventoryTotal`,
`assignments`, `configurationAssumptions`, `summary`. One assignment per
inventoried workload:

```json
{"namespace": "...", "kind": "...", "name": "...",
 "componentObjectives": {"c": {"level": "H", "reason": "..."},
                          "i": {"level": "H", "reason": "..."},
                          "a": {"level": "M", "reason": "..."}},
 "vector": "M/M/L",
 "securityRequirements": "cr-m_ir-m_ar-l",
 "capped": {"c": true, "i": true, "a": true},
 "breakouts": [],
 "resolutionSource": "nameRule",
 "status": "agent-inferred",
 "confidence": "medium",
 "evidence": "...",
 "assumptions": ["..."],
 "manualReview": ["..."]}
```

The gate enforces the envelope math, capped-flag accuracy, label/vector
consistency, breakout legitimacy, the inventory equation, and the confidence
contract.

## Runtime mechanics

- The label key is delivered by renaming the plugin's archetype key inside the
  embedded scoring document:

  ```yaml
  labelKeys:
    archetype: vdr.fedramp.io/security-requirements
  ```

  This works with the current plugin and retires `vdr.fedramp.io/asset-archetype`
  for the cluster (single-string field; no dual-key support). Legacy archetype
  labels found in inventory are inert — report them as stale cleanup items.
- Label values are dot-free opaque catalog keys `cr-[lmh]_ir-[lmh]_ar-[lmh]`.
  Dots are reserved by the plugin for the legacy compositional grammar; never
  emit a dotted value. Every value used by a label or rule must exist in the
  `archetypes` catalog; always emit all 27 entries via
  `derive_requirements.py --emit-catalog`.
- The rule field name remains `archetype:` inside `nameRules`/`kindRules`/
  `namespaceRules` — a plugin schema constant, not a vocabulary statement.
- Resolution precedence is unchanged: workload label → namespace label →
  nameRule → kindRule → namespaceRule → `unclassified` H/H/H fail-safe. An
  explicit label with a value missing from the catalog short-circuits to the
  fail-safe; it never falls through to a quieter rule.
- The envelope exists only at generation time. Nothing at runtime caps a
  vector, and the H/H/H fail-safe is untouched.
- `humanReviewCompleted` is a human-only attestation marker in the ConfigMap:
  always generated `"false"`, comment-fenced, never read, reported,
  summarized, analyzed, or modified by AI agents or automated tooling, and
  never carried forward from a previous ConfigMap.
