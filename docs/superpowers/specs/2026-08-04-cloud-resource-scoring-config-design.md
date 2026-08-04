# Central cloud-resource scoring config (`vdr-cloud.yaml`) — design

Date: 2026-08-04
Status: approved design, pending implementation plan

## Goal

Give non-Kubernetes cloud resources the same centralized, reviewable
assignment surface that `vdr-fedramp` gives Kubernetes workloads: a single
YAML document that declares Certification Class, agency scope, and
security-impact profiles for cloud object storage, VMs, managed SQL, and the
other CIS Foundations-addressed resource families — matched by name, tags,
network, resource type, or whole account/project.

The document becomes the **primary assignment surface** for cloud resources.
Per-resource `vdr.fedramp.io/*` tags (the `tag-terraform-vdr-assets` path)
remain valid but are demoted to the exception/override mechanism, exactly
mirroring how explicit workload labels relate to the central ConfigMap rules
in the Kubernetes model.

A new standalone skill (working name `generate-cloud-vdr-config`) discovers
live resources with read-only cloud CLIs, interviews the operator, and emits
the document plus a coverage ledger. Nothing is ever applied to a cloud
account.

## Decisions made during brainstorming

| Question | Decision |
|---|---|
| Consumer | The document is the primary assignment surface, replacing per-resource tagging as the default path; tags become overrides. It is a **proposed integration contract** — `trivy-plugin-vdr` does not consume it today, and every artifact and skill statement must say so plainly (same caveat discipline as the `TerraformAssetClassifications` sidecar). |
| Providers (v1) | GCP + AWS discovery and patterns; schema is provider-neutral so Azure slots in later without schema changes. |
| Document scope | One multi-scope document; each GCP project / AWS account is a `scopes:` entry. |
| Skill shape | New standalone skill alongside the existing four. `generate-vdr-configmap` stays Kubernetes-only; `tag-terraform-vdr-assets` stays as the tag/override path. Shared references (`archetype-guide.md`, reason registry, CIS scope) are reused, not duplicated. |
| Rule model | Rule families with family-tier precedence (Approach A), mirroring `scoring.yaml`, not a unified ordered selector list. |
| Managed-pattern default SIP | `service-content.disposable-state.deferrable-work` → M/L/L. CR:M is a deliberate failsafe because staged code/templates can embed sensitive material. |

## The document schema

A standalone YAML file (not a Kubernetes object), emitted to
`./vdr-cloud-output/vdr-cloud.yaml`:

```yaml
apiVersion: vdr.fedramp.io/v1alpha1
kind: CloudResourceScoringConfig

# Global fallbacks. Fail-closed provisional values when unattested: class "D",
# multiAgency "true", each annotated with confidence and manual-review
# comments, same as the Kubernetes skill.
defaults:
  class: "C"
  multiAgency: "false"

# Optional named-archetype catalog, same semantics as scoring.yaml. Only for a
# CSP that intentionally runs a named-archetype system; never to compile a
# decision trace.
archetypes: {}

scopes:
  - provider: gcp
    project: acme-prod            # AWS scopes use `account: "123456789012"`
    # confidence: high | operator-confirmed FedRAMP Moderate authorization
    class: "C"
    # confidence: high | operator-confirmed single-agency deployment
    multiAgency: "false"

    nameRules:                    # glob against the type's primary identifier
      # confidence: high | operator attested customer PHI store
      - {type: storage.googleapis.com/Bucket, match: "acme-prod-customer-data",
         securityImpactProfile: regulated-data.record-keeping.mission-essential}
      # confidence: high | operator attested cross-agency exchange bucket;
      # SIP still resolves from broader rules
      - {type: storage.googleapis.com/Bucket, match: "acme-prod-agency-exchange",
         multiAgency: "true"}
      # builtin-pattern: gcp-cloudfunctions-staging
      # confidence: medium | provider-created transient artifact store; contents
      #   are deploy-time only and overwritten on update
      # manual-review: CR:M is a failsafe for sensitive material embedded in
      #   code/templates; an operator may attest down with a direct vector after
      #   verifying contents. Confirm nothing re-consumes artifacts post-deploy.
      - {type: storage.googleapis.com/Bucket, match: "gcf-sources-*",
         securityImpactProfile: service-content.disposable-state.deferrable-work}

    tagRules:                     # every key/value must match; values may be globs
      # confidence: high | operator-governed data classification taxonomy
      - {matchTags: {data-class: "phi"},
         securityImpactProfile: regulated-data.record-keeping.mission-essential}

    networkRules:                 # network-attached resources only (VMs, SQL, ...)
      # confidence: medium | prod VPC hosts only the core service path
      # manual-review: verify no ancillary workloads share prod-vpc
      - {network: prod-vpc, type: "sqladmin.googleapis.com/Instance",
         securityImpactProfile: regulated-data.authoritative-record.mission-essential}

    typeRules:                    # whole resource family in this scope
      # confidence: medium | fleet role inferred from instance templates
      # manual-review: confirm no VM holds regulated payload data locally
      - {type: "compute.googleapis.com/Instance",
         securityImpactProfile: service-content.record-keeping.operations-support}
```

### Resolution semantics

Precedence per resource, most specific first:

1. the resource's own `vdr.fedramp.io/*` tag or label (override; canonical or
   provider-encoded form);
2. `nameRules`;
3. `tagRules`;
4. `networkRules`;
5. `typeRules`;
6. scope `class` / `multiAgency` / optional scope `securityImpactProfile`;
7. global `defaults`;
8. fail-safe.

Within a family, first match in document order wins. Families never mix: a
matching `nameRule` always beats every `tagRule`.

Both the scope block and global `defaults` may carry an optional
`securityImpactProfile` fallback, but the skill discourages it where
resource roles vary — the preferred posture is fail-loud: a resource no rule
matches fails validation rather than inheriting a broad default, matching
the Kubernetes skill's stance on broad namespace fallbacks.

**Each attribute resolves independently down the same chain.** SIP resolves
from the first rule that sets `securityImpactProfile`; multiAgency resolves
from the first rule that sets `multiAgency`. A one-line `nameRule` can flip
multiAgency for a single resource while its SIP continues to resolve from a
broader rule. Any rule in any family may carry either or both attributes.

### Matching fields

- `type` — provider asset-inventory type strings
  (`storage.googleapis.com/Bucket`, `sqladmin.googleapis.com/Instance`,
  `compute.googleapis.com/Instance`, `AWS::S3::Bucket`, `AWS::EC2::Instance`,
  `AWS::RDS::DBInstance`, ...). These are exactly what `gcloud asset list` and
  AWS Config/tagging APIs emit, so discovery needs no mapping layer. Required
  on `typeRules`; strongly recommended on `nameRules` (name globs are
  meaningless across types); optional narrowing constraint on `tagRules` and
  `networkRules`.
- `match` — glob against the type's **primary identifier**, fixed by a table
  in the skill reference: bucket name, Cloud SQL instance name, GCE instance
  name, EC2 instance **ID**, RDS DB identifier, and so on. AWS Name-tag
  matching goes through `tagRules` (`matchTags: {Name: "web-*"}`), never
  `nameRules`, so a resource never has two competing name identities.
- `matchTags` — map of tag/label key → value; all entries must match; values
  may be globs.
- `network` — VPC name or identifier; optional `subnet` narrows it. Applies
  only to network-attached resource types; a `networkRule` can never match a
  global resource like a bucket.
- Optional secondary constraints (`region`, `matchTags` on a `nameRule`, ...)
  AND together within a rule, so compound matches need no extra mechanism.

### Value and comment conventions

- SIP values use canonical dotted form: direct vector, governed decision
  trace, or named archetype. Provider label encodings (GCP `__` separators,
  Azure `.` keys) apply only to actual cloud tags, never inside this document.
- `class` and `multiAgency` are quoted strings, same as `vdr-fedramp`.
- `# confidence: high|medium|low` immediately above every rule or coherent
  rule group; `# manual-review: ...` on every non-high rule. Confidence
  describes evidence quality, never impact severity, and never lowers a
  CR/IR/AR value.
- Existing `vdr.fedramp.io/*` tags found during discovery are reported as
  override agreements/conflicts, and are not treated as operator attestations
  unless reconfirmed.

## Discovery workflow

Mirrors the Kubernetes skill: confirm target → inventory read-only → mine
evidence → interview → propose rules. Ground rules carry over: read-only
verbs only (`list` / `describe` / `get`), never dump secret-bearing config
(instance user-data, function environment values) into artifacts, nothing is
ever applied.

1. **Establish scopes.** Ask whether this is a single- or multi-scope run.
   - AWS: ask which named CLI profiles to use, one per account. Validate each
     with `aws sts get-caller-identity --profile <p>`, show the resolved
     account ID and ARN, and confirm the profile → account mapping before any
     inventory. Every call pins `--profile`. The skill never assumes roles
     itself; cross-account access is whatever the operator's profiles already
     do.
   - GCP: offer `gcloud projects list` to enumerate accessible projects, let
     the operator select the in-scope set, and pin `--project` on every call.
   Each confirmed account/project becomes one `scopes:` entry. A scope whose
   inventory fails is excluded from the document and reported as failed —
   never emitted as a silently partial block.
2. **Inventory via a stdlib-only Python script** that shells out to the CLIs,
   restricted to the CIS Foundations-addressed families (reusing the
   `cis-asset-map` scope):
   - GCP: prefer `gcloud asset list` (Cloud Asset Inventory) filtered to the
     allowlisted asset types; fall back to per-service commands
     (`gcloud storage buckets list`, `gcloud sql instances list`,
     `gcloud compute instances list`, ...) when the Asset API is unavailable,
     recorded as a degraded-inventory warning, never a silent gap.
   - AWS: `aws resourcegroupstaggingapi get-resources` for the tag sweep plus
     per-service `describe`/`list` calls for the CIS families (S3, EC2, RDS,
     EBS, ...).
   - Captured per resource: type, primary identifier, region/zone,
     tags/labels, network attachment where applicable, and creation metadata.
   - The exact successful JSON is preserved as
     `./vdr-cloud-output/resource-inventory.json` — the coverage baseline,
     never reconstructed or filtered afterward.
3. **Mine existing tags.** Summarize the tag vocabulary in use (keys, value
   distributions, coverage). This informs proposing `tagRules` where a
   coherent operator taxonomy already exists (`data-class`, `env`, `owner`,
   ...) and surfaces existing `vdr.fedramp.io/*` tags as potential overrides.
4. **Detect built-in managed-resource patterns** and pre-classify the matches
   so interview questions are spent on resources humans actually control.
5. **Group and interview.** Cluster remaining resources into coherent groups
   (type + naming pattern + shared tags + network), then run the archetype
   guide's five-question interview per group — at most five questions, with
   evidence-backed best-effort inference and confidence marking when the
   operator delegates. Environment names never establish impact; HA never
   lowers AR.

## Built-in managed-resource patterns

A machine-readable catalog at `references/managed-resource-patterns.json`
plus a prose guide, mirroring how `cis-asset-map.json` works. Each entry
pins:

- `id` (`gcp-cloudfunctions-staging`, `aws-cloudformation-templates`, ...),
  provider, resource type;
- match criteria — name globs and/or provider marker tags. Initial catalog
  candidates:
  - GCP: `gcf-sources-*`, `*_cloudbuild`, `run-sources-*`,
    `dataproc-staging-*` / `dataproc-temp-*`, `artifacts.<project>.appspot.com`,
    `<project>.appspot.com` staging, `goog-managed-by` labels;
  - AWS: `cf-templates-*`, `cdk-*-assets-*`,
    `elasticbeanstalk-<region>-<account>`, `aws-athena-query-results-*`,
    `aws:cloudformation:stack-name` tags;
- rationale — which managing service creates the resource and why tagging
  control is limited;
- default SIP — the governed trace
  `service-content.disposable-state.deferrable-work` → **M/L/L**. CR:M is a
  deliberate failsafe because staged source archives and templates can embed
  sensitive material; IR:L because contents are deploy-time inputs that
  updates overwrite (`disposable-state`); AR:L because an outage defers
  deployments without degrading running services (`deferrable-work`);
- a standing manual-review note: an operator may attest CR down with a direct
  vector after verifying staged contents are non-sensitive; confirm nothing
  re-consumes artifacts post-deploy (which would raise IR).

Behavior: when discovery matches a pattern, the skill **materializes an
explicit rule** in the scope's `nameRules`/`tagRules` with a
`# builtin-pattern: <id>` comment, capped at **medium confidence**
(name/marker-based inference), which per repo convention forces the
manual-review comment. Nothing from the catalog is ever assumed silently, an
unmatched pattern emits nothing, and the operator reviews pattern rules in
the same review table as everything else.

## Outputs

Three required artifacts under `./vdr-cloud-output/`:

1. `resource-inventory.json` — exact per-scope discovery output, including
   per-scope provenance: AWS profile name, resolved account ID / GCP project,
   and caller identity. Profile names stay in the ledger, never in
   `vdr-cloud.yaml` (they are local machine config).
2. `vdr-cloud.yaml` — the multi-scope document described above.
3. `assignment-coverage.json` — top-level `scopes`, `inventoryTotal`,
   `assignments`, `configurationAssumptions`, and `summary`. One assignment
   entry per inventoried resource: scope, `type`, `identifier`,
   `securityImpactProfile`, `derivationMethod` (`direct-vector`,
   `decision-trace`, `named-archetype`), resolved rule family and rule,
   `vector`, status (`operator-confirmed`, `agent-inferred`, or
   `builtin-pattern`), confidence, `evidence`, `assumptions`, `manualReview`.
   Non-high-confidence entries carry at least one concrete manual-review
   item. `configurationAssumptions` records provisional class/multiAgency
   values. `summary` counts by scope, rule family, status, and confidence.

## Validation (no cloud access required)

Before handoff:

- parse `vdr-cloud.yaml` and validate the schema shape;
- validate every SIP value: decision traces against the shared governed
  registry via the sibling skill's `reason_codes.py`, direct vectors against
  independent H/M/L constraints, named archetypes against the catalog;
- replay resolution for every inventoried resource through the actual
  precedence chain (tag override → nameRule → tagRule → networkRule →
  typeRule → scope → defaults → fail-safe); fail if any resource lands on
  fail-safe unexplained or is absent from `assignment-coverage.json`;
- verify the inventory equation: assignments equal the inventory total with
  no duplicates, accounted by scope, family, status, and confidence;
- fail if any emitted rule matches zero inventoried resources, unless the
  operator explicitly attests a forward-looking rule;
- detect shadowed and duplicate rules within each family; flag a
  `networkRule` whose `type` is not network-attached;
- verify every rule or coherent group has a confidence comment and every
  non-high-confidence rule has a manual-review comment;
- report existing `vdr.fedramp.io/*` resource tags as override
  agreements/conflicts, since a conflicting tag prevents the intended rule
  from resolving;
- print the mandatory confidence report (per `report_confidence.py`
  conventions: every medium/low decision with value, evidence, and a concrete
  manual-review action; explicit `none` when everything is high confidence);
  treat a nonzero exit as a validation failure;
- run the proprietary-term deny-list scan when the user supplies one;
- keep `skills/` and `.agents/skills/` copies byte-identical.

## Error handling

- Failed scope inventory: exclude the scope from the document, report it in
  the terminal and ledger. Never emit a partial scope silently.
- Degraded inventory (Asset API unavailable, a service listing denied):
  proceed with per-service fallbacks where possible and record explicit
  warnings naming what could not be enumerated.
- Unattested Class / agency scope: fail-closed provisional values (`D`,
  `"true"`) with confidence and manual-review annotations, recorded in
  `configurationAssumptions`. Missing answers never withhold the artifact.
- Ordinary uncertainty is not an exception: assign the strongest credible
  profile, lower confidence, flag for review. Reserve `unclassified`-style
  failure for technical validation errors only.

## Testing

Following the existing `tests/` conventions (stdlib `unittest`, fixtures, no
network):

- schema validation tests: valid/invalid documents, rule-family field
  constraints, canonical SIP value forms;
- resolution replay tests: fixture inventories exercising every precedence
  tier, independent SIP/multiAgency resolution, first-match-within-family,
  shadowed-rule detection, network-rule type gating;
- pattern catalog tests: each built-in pattern's match criteria against
  fixture resource names/tags, the pinned default trace validating against
  the governed registry, medium-confidence capping;
- inventory script tests with mocked CLI outputs: scope pinning, degraded
  fallback recording, tag-vocabulary summarization, secret-material
  exclusion;
- coverage ledger tests: inventory equation, manual-review shape for
  non-high entries.

## Explicitly out of scope (v1)

- Azure discovery and patterns (schema already accommodates an `azure`
  provider with `subscription` scopes).
- Plugin-side consumption in `trivy-plugin-vdr`. Until that lands, every
  artifact and the skill's handoff text state that `vdr-cloud.yaml` is a
  proposed integration contract that no current scanner consumes.
- Org-level scopes (GCP organizations/folders, AWS Organizations OUs) as rule
  carriers; v1 scopes are projects and accounts only.
- Emitting split per-scope files; one multi-scope document only.
