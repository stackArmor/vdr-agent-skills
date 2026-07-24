# Security Requirements ConfigMap Skill — Design

- Date: 2026-07-24
- Status: approved design, pending final spec review
- Supersedes: the archetype decision-trace assignment model in `generate-vdr-configmap`

## Problem

The archetype approach assigns CR/IR/AR purely from component role. In practice
the correct Security Requirements vector is not a function of the component
alone: it also depends on the purpose and data profile of the overall system
(a project-management SaaS holds different data than a security-monitoring
tool, a legal case-management system, or an electronic-medical-records system)
and on the data propensity of the agency deploying it. The archetype
abstraction, while auditable, limits agility from system to system.

The redesign derives each component's final vector from three per-objective
inputs — system, agency, and component security objectives — and delivers it
through a `security-requirements` label vocabulary. Justifications move out of
the label into reviewable JSON artifacts.

Policy conformance: the VDR RFC states the scoring formula requires only a
per-asset Security Requirements vector; `asset-archetype` is an optional
metadata mapping. Any governed vocabulary whose values map deterministically to
a documented CR/IR/AR gradient conforms. This redesign is such a vocabulary.

## Goals

1. New skill `generate-security-requirements-configmap` (mirrored byte-identical
   under `.agents/skills/`) producing the `vdr-fedramp` ConfigMap plus
   justification artifacts, repeatably.
2. A transparent wizard that collects system context, agency context, and
   component impact answers, stating why each question matters.
3. A deterministic, auditable combination method for
   system/agency/component security objectives.
4. Multi-agency determination at cluster or namespace scope.
5. Deprecation of `generate-vdr-configmap` without breaking
   `tag-terraform-vdr-assets`.

## Non-goals

- No `trivy-plugin-vdr` code changes (none are required).
- No update to `tag-terraform-vdr-assets` (future work; its path imports of
  `reason_codes.py` and `archetype-guide.md` keep working because the old
  skill's files remain on disk).
- No changes to `capture-dataflow`.
- No changes to PAIN word thresholds or the plugin's embedded policy.

## Ground rules carried over unchanged

Read-only `kubectl get`/`kubectl config` only; never retrieve Secret values;
artifacts written only under `./vdr-configmap-output/`; every inventoried
workload receives an assignment; ordinary uncertainty produces a medium/low
confidence inference, never an omission; confidence never lowers a vector; HA
never lowers AR; operator attestations stay distinct from agent inferences;
Python scripts are stdlib-only, python3 >= 3.8; `skills/` and
`.agents/skills/` copies stay byte-identical.

## The three-vector model

Each input is a per-objective vector `{C, I, A}` over `{L, M, H}`.

### System Security Objectives (SSO)

What the product holds and does by design. Derived from:

- web research on the company/product (with operator consent; the operator
  confirms or corrects the derived description and adds anything missed —
  declining research means profiles come from operator description alone);
- a data-type checklist (federal-government-sourced records, PII tiers,
  CUI/FTI/PHI/CJI, legal-privileged material, financial/confidential business
  information, security telemetry, change/configuration data, public content);
- ingestion/contamination paths (uploads, attachments, free-text fields,
  API/email feeds from agency systems) — these raise SSO, reflecting the
  recurring failure mode where a nominally moderate system accumulates
  higher-impact content through artifacts;
- agency-device footprint (agents installed on agency endpoints: logging, SSO,
  EDR) and which cluster components ship or control them.

Calibration rules baked into the reference guide:

- Direct access to, processing of, or transit of actual federal-government
  -sourced data is the primary High driver for C and I.
- Raw vulnerability scan data and change-management data are C:M baseline,
  even with strong asset correlation. Adversaries with capable autonomous
  tooling can continuously probe internet-accessible systems; possession of a
  vulnerability inventory accelerates them less than it once did. Operators may
  still raise this with justification.
- Availability objectives are assessed as the consequence of complete logical
  loss of the system including its durable records — not transient outage
  tolerance. A downtime-tolerant system whose permanent record loss would be a
  serious adverse effect rates A:M or higher. A:L is reserved for genuinely
  ephemeral or reconstructible systems.

The guide carries generic system-type starting profiles (project & portfolio
management, legal case management, electronic medical records, security
operations/SIEM, EDR/endpoint management, identity/SSO, vulnerability
management, change management/ITSM, learning management), each flagged as an
estimate the wizard must confirm. No real product, vendor, or agency names
appear anywhere in skill files.

### Agency Security Objectives (ASO)

A per-objective estimate of the data the deploying agency would actually place
in this system — objective-level, never the agency's overall FIPS 199
high-water mark. Derived from agency research, statutory/contractual overlays
in scope (tax information, criminal-justice information, health information,
statutory confidentiality regimes, data-use agreements), and any known
objective-level categorization from solicitations, PIAs, or the agency ATO.

Rules:

- A definite deploying agency sets the ceiling. Multiple definite agencies:
  per-objective max across them.
- No definite agency: operator-named target agencies guide the estimate only.
  A target-agency list is never evidence for multi-agency scope.
- No agencies at all: ASO defaults to SSO (a non-binding ceiling), low
  confidence, manual-review flagged.
- Class is a prior, never authority, and never caps ASO (see divergence
  protocol).

### Class-vs-data divergence protocol

Per objective, for each agency:

1. Build the ASO estimate blind to Class (research + data types + overlays).
2. Derive the Class prior: D → expect High-impact data in scope; C → Moderate;
   B → Low; A → Ready posture, treat as B unless evidence says otherwise.
3. Compare:
   - Agreement → ASO = estimate; Class recorded as corroborating evidence
     (raises confidence).
   - Estimate below prior (moderate data on a High authorization): surface the
     divergence transparently and ask the operator to attest what data actually
     lands in this deployment. Attested lower value wins and is recorded as
     operator-confirmed with the divergence and prior preserved. Unanswered:
     the Class prior wins (higher value), low confidence, manual review —
     never lower on an unconfirmed inference.
   - Estimate above prior (High data on a Moderate authorization): ASO stays at
     the estimate. Statutory/contractual driver → prominent manual-review flag
     noting an authorizing official cannot accept that risk on someone else's
     behalf. Agency-categorization driver → recorded as explicit AO
     risk-acceptance territory.
4. Estimate, prior, divergence, governing source, attestation status, and
   confidence all land in `security-objectives.json`.

### Component Security Objectives (CSO)

The existing role methodology, unchanged: structural evidence (workload spec,
service account, RBAC, routing, webhooks, host access, resource references,
dependency edges); privilege evidence outweighs product naming; strongest
credible consequence per objective; at most five focused questions per
coherent workload group; environment names never establish impact;
production-equivalent scoring when the operator requires parity; high/medium/
low confidence measuring evidence quality, not severity.

### Combination

Per objective `o ∈ {C, I, A}`, with L < M < H:

```
envelope(o) = min(SSO(o), ASO(o))     # agency caps system; a higher agency value never raises the system
final(o)    = min(CSO(o), envelope(o))
```

The envelope is only ever a cap, never a floor. Contamination raises SSO
during the wizard; role evidence raises CSO; the formula itself raises
nothing.

**Breakouts (semi-hard ceiling).** A component may exceed the envelope on an
objective only when it belongs to an enumerated category whose compromise
reaches beyond the system's own data:

1. delivery, update, or control paths for software installed on agency
   devices;
2. cross-system trust anchors and durable key material;
3. shared CSP infrastructure whose blast radius exceeds this authorization
   boundary.

A breakout restores `final(o) = CSO(o)` for that objective and always carries
a written justification plus a manual-review flag. Breakout categories are a
closed list in the reference guide; extending the list is a governed edit, not
an ad hoc decision.

**Fail-safe interplay.** The plugin's H/H/H fail-safe for unknown or
unclassified assets is untouched. The envelope exists only inside the skill's
derivation; nothing at runtime caps a vector.

**Audit record.** Both the raw CSO and the final vector are recorded, with
per-objective capped flags, so every cap and every breakout is visible.

## The wizard

Four phases, roughly thirteen top-level questions plus the per-component
interview. Every question states why it is needed. Unanswered questions never
block generation: the skill makes the strongest evidence-backed inference,
marks confidence, and flags manual review.

**Phase A — system identity → SSO.**
1. Company and product name, and consent to web research (why: public
   documentation establishes the product's data profile by design).
2. Confirm or correct the researched system description; add anything the
   research missed (why: research is an estimate; the SSO rests on the
   confirmed purpose).
3. Data-type checklist (why: each type maps to per-objective drivers, and the
   guide's calibration rules key off them).
4. Ingestion/contamination paths (why: attachments, free text, and feeds are
   where higher-impact content leaks into nominally moderate boundaries).
5. Agency-device footprint and which components ship or control those agents
   (why: endpoint software extends the blast radius beyond the system's data
   and drives breakout eligibility).
6. Integrity and availability posture: are records legally operative or
   decision-driving; what is the consequence of permanent record loss, not
   just downtime (why: objective-level categorization requires more than
   confidentiality).

**Phase B — agency → ASO.**
7. Which agency or agencies actually use this deployment ("none yet" is
   acceptable) (why: the deploying agency's data propensity sets the
   per-objective ceiling).
8. If none definite: target agencies (why: guides the data-profile estimate
   only; explicitly never multi-agency evidence).
9. Per agency: present the researched per-objective estimate with rationale
   for confirmation or adjustment, and ask which statutory/contractual
   overlays are in scope (why: overlays are frequently the binding constraint
   and determine whether risk acceptance is even available).
10. Any known objective-level categorization from solicitations, PIAs, or the
    agency ATO (why: actual categorization beats estimates).

**Phase C — authorization and scope.**
11. Existing FedRAMP authorization → Class A–D (why: selects the remediation
    deadline table, and serves as a prior in the divergence protocol — not
    authority over the data profile).
12. Multi-agency: which agencies are served from this cluster and where the
    tenancy boundary sits (why: decides cluster-level `multiAgency` versus
    namespace-scoped delivery; a compromise crossing agencies raises the PAIN
    tier).
13. Environment intent: production-equivalent or intentionally isolated
    low-impact (why: environment names never establish impact).

**Phase D — per component.** The existing focused-impact interview (at most
five questions per coherent group), feeding CSO.

## Multi-agency determination

- Cluster-level `multiAgency: "true"` when compromise of the cluster can
  affect several agencies and tenancy is not namespace-partitioned.
- Namespace-scoped: cluster default `"false"` plus `multiAgencyNamespaces`
  globs in the embedded scoring document (central delivery; no labeling
  required). Namespace/workload `vdr.fedramp.io/multi-agency` labels remain
  available as operator-applied exceptions but are not the default mechanism.
- Never inferred from workload population, and never inferred from a
  target-agency list supplied for data profiling.
- The determination, its scope, and its justification are recorded in
  `security-objectives.json`.

## Artifacts

All under `./vdr-configmap-output/`.

1. **`workload-inventory.json`** — exact successful output of the adapted
   `list_workloads.py`; reports both legacy `vdr.fedramp.io/asset-archetype`
   and new `vdr.fedramp.io/security-requirements` labels found on workloads
   and namespaces.

2. **`vdr-fedramp.yaml`** — Namespace `fedramp-vdr-trivy`, ConfigMap
   `vdr-fedramp`:
   - Quoted scalars `class` and `multiAgency`, each with a confidence comment
     and manual-review comment when not high confidence.
   - `humanReviewCompleted: "false"` — always emitted false; fenced by
     comments instructing AI agents to never read, report, summarize, analyze,
     or act on the value, and that only a human flips it. The skill never sets
     it true, never carries a prior value forward on regeneration (a fresh
     artifact is unreviewed by definition), and never mentions the value in
     terminal output, coverage JSON, or handoff. The plugin ignores unknown
     data keys, so the field is runtime-inert.
   - Embedded `scoring.yaml` containing:
     - `labelKeys: {archetype: vdr.fedramp.io/security-requirements}` — works
       with the current plugin; retires the `asset-archetype` key for this
       cluster (single-string field; no dual-key support).
     - an `archetypes` catalog of all 27 dot-free entries
       `cr-l_ir-l_ar-l` … `cr-h_ir-h_ar-h`, each
       `{lens: requirements, cr: X, ir: Y, ar: Z}`. Dots are impossible: the
       plugin reserves dotted values for the legacy compositional grammar.
     - `nameRules`/`kindRules`/`namespaceRules` referencing those values via
       the plugin's `archetype:` rule field (a plugin schema constant; the
       guide notes the field name does not change).
     - `multiAgencyNamespaces` globs when the determination is
       namespace-scoped.
     - `internetAccessibleIngressClasses`/`internetAccessibleGatewayClasses`
       handling unchanged from the current skill.
   - Rule-scoping gates unchanged: exact `nameRules` by default; narrow stable
     patterns only for coherent assigned groups; `namespaceRules`/`kindRules`
     only under uniformity gates; explicit rules for standalone and Helm-hook
     Jobs; CronJob-owned Jobs suppressed; no blanket Job fallbacks; unknown
     future components fail loud via the untouched `unclassified` H/H/H
     default.
   - Confidence comment above every rule or coherent rule group; manual-review
     comment for every non-high-confidence rule.

3. **`security-objectives.json`** — the derivation record: product research
   summary and confirmed description; data types; contamination paths;
   agency-device footprint; SSO with per-objective rationale; per-agency
   profiles (definite vs target, overlays with statute-grounded flags, ASO
   with rationale); Class prior and divergence-protocol outcomes; envelope
   with derivation; ceiling mode; multi-agency determination with scope and
   justification. Every value carries status (`operator-confirmed` or
   `agent-inferred`) and confidence, with manual-review items for non-high
   confidence.

4. **`assignment-coverage.json`** — top-level `context`, `inventoryTotal`,
   `assignments`, `configurationAssumptions`, `summary`. Each assignment:
   `namespace`, `kind`, `name`, `componentObjectives` (raw CSO with
   per-objective reasons), per-objective `capped` flags, optional `breakout`
   (category + justification), final `vector`, `securityRequirements` label
   value, `resolutionSource`, status, confidence, `evidence`, `assumptions`,
   `manualReview` (empty iff high confidence). Inventory equation: assignments
   equal inventory total, no duplicates.

Optional `label-overrides.sh` on explicit operator request only, with the same
rules as today (review banner, pinned `--context`, CronJob label placement
guidance).

## Scripts and references

- `scripts/list_workloads.py` — copied from the old skill; label constants
  extended to capture both old and new keys.
- `scripts/derive_requirements.py` — replaces `reason_codes.py`. Input:
  SSO/ASO/CSO values (CLI or JSON). Computes envelope and final vectors
  deterministically (the min() math and breakout handling live in code, not
  prose); emits the 27-entry catalog YAML; validates label-value syntax,
  dot-freeness, and that every emitted value has a catalog entry.
- `scripts/report_confidence.py` — adapted to the new coverage schema; still
  the mandatory terminal gate (nonzero exit = validation failure); prints
  every medium/low-confidence decision, every capped component, and every
  breakout; prints an explicit `none` result when empty; never prints
  `humanReviewCompleted`.
- `references/security-objectives-guide.md` — replaces the archetype guide:
  the three-vector model; calibration rules (federal-data driver,
  vulnerability/change-data C:M baseline, availability-as-complete-loss);
  generic system-type starting profiles; the wizard question bank with
  why-text; the divergence protocol; the closed breakout-category list; the
  component-role methodology ported from the archetype guide (privilege
  heuristics, data/telemetry rules, availability calibration table, HA rule,
  ownership rules); confidence contract.
- `assets/vdr-fedramp.example.yaml` — fictional example using generic
  system-type language only.

## Validation (before handoff)

- Parse outer YAML and embedded `scoring.yaml`.
- Every emitted label value matches `cr-[lmh]_ir-[lmh]_ar-[lmh]`, is dot-free,
  and has a catalog entry whose cr/ir/ar match the value's own encoding.
- Every final vector equals `min(CSO, envelope)` per objective unless a
  recorded breakout applies; every breakout has a category from the closed
  list, a justification, and a manual-review item.
- `humanReviewCompleted` present, `"false"`, with its comment fence; its value
  never appears in any report.
- Confidence comments on `class`, `multiAgency`, internet-accessibility keys,
  and every rule; manual-review comments wherever confidence is not high.
- Resolution simulation over actual precedence (workload label → namespace
  label → nameRule → kindRule → namespaceRule → fail-safe); fail if any
  workload resolves to `unclassified`, or if an explicit
  `security-requirements` label carries a value absent from the catalog (it
  would short-circuit to the H/H/H fail-safe instead of the intended rule).
  Legacy `asset-archetype` labels become inert once `labelKeys` is renamed;
  report them as stale so the operator can clean them up.
- Inventory equation holds; coverage entries well-formed; every emitted rule
  matches at least one inventoried workload unless operator-attested
  forward-looking.
- `report_confidence.py` exits zero; offline smoke test against a sibling
  `trivy-plugin-vdr` checkout when available (warnings about invalid cluster
  scoring config are failures).
- Proprietary-term deny-list scan when supplied; `bash -n` on
  `label-overrides.sh` when it exists; `skills/` and `.agents/skills/` copies
  byte-identical.

## Handoff

Report inventory total, operator-confirmed vs agent-inferred counts,
confidence counts, capped-component count, breakout list, and precedence
conflicts. Repeat the non-high-confidence manual-review list in the terminal.
Never state the `humanReviewCompleted` value. Instruct the operator to review
and apply manually or via GitOps, and to flip `humanReviewCompleted` to
`"true"` only as a deliberate human action after review.

## Deprecation and housekeeping

- `generate-vdr-configmap` receives a deprecation blockquote (pattern used for
  capture-dataflow's beta note) pointing to the new skill; its files remain on
  disk untouched.
- README: new skill section, deprecation language for the old, updated
  guarantees wording.
- Builds on the current working tree (the uncommitted confidence/manual-review
  overhaul is retained foundation).
- Release follows the existing convention (plugin.json + marketplace.json
  version bump, `vX.Y.Z` tag, release commit) when the operator is ready.

## Risks and mitigations

- **Stale legacy labels**: adopting `labelKeys.archetype =
  vdr.fedramp.io/security-requirements` stops the plugin reading
  `asset-archetype` labels; any found in inventory are reported as stale
  (inert) so nothing silently changes behavior.
- **Dotted-value collision**: impossible by construction — the new grammar is
  dot-free and validated.
- **Under-rating via ceiling**: every cap is recorded per objective with the
  raw CSO preserved; breakouts exist for the enumerated
  beyond-the-boundary categories; the runtime fail-safe stays H/H/H.
- **Over-asking the operator**: unanswered questions never block generation;
  best-effort inference with confidence and manual-review annotations.
