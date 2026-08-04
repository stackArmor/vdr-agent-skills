# `vdr-cloud.yaml` schema and resolution reference

`vdr-cloud.yaml` (`kind: CloudResourceScoringConfig`) is the central,
reviewable assignment surface for non-Kubernetes cloud resources: object
storage, VMs, managed SQL, and the other CIS Foundations-addressed families,
matched by name, tags, network, resource type, or whole account/project. It is
the cloud analogue of the `vdr-fedramp` scoring ConfigMap. Per-resource
`vdr.fedramp.io/*` tags (the `tag-terraform-vdr-assets` path) remain valid but
are demoted to the exception/override mechanism.

**This document is a proposed integration contract. `trivy-plugin-vdr` does not
consume `vdr-cloud.yaml` today.** Every artifact and every skill statement must
say so plainly, exactly as the `TerraformAssetClassifications` sidecar does.
Until plugin-side consumption lands, the document is a reviewed, versioned
record of cloud-resource impact assignments, not a runtime input.

## Contents

1. [Document schema](#document-schema)
2. [Resolution precedence](#resolution-precedence)
3. [Independent per-attribute resolution](#independent-per-attribute-resolution)
4. [Rule-family fields](#rule-family-fields)
5. [Primary identifiers](#primary-identifiers)
6. [Value and comment conventions](#value-and-comment-conventions)
7. [Fail-loud stance on broad defaults](#fail-loud-stance-on-broad-defaults)
8. [Assignment-plan JSON shape](#assignment-plan-json-shape)

## Document schema

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

One multi-scope document only: each GCP project / AWS account is one `scopes:`
entry. There is no per-scope split file. A scope whose inventory failed is
excluded and reported, never emitted as a silently partial block.

## Resolution precedence

Precedence per resource, most specific first:

1. the resource's own `vdr.fedramp.io/*` tag or label (override; canonical or
   provider-encoded form);
2. `nameRules`;
3. `tagRules`;
4. `networkRules`;
5. `typeRules`;
6. scope `class` / `multiAgency` / optional scope `securityImpactProfile`;
7. global `defaults`;
8. fail-loud validation error.

Within a family, the first match in document order wins. Families never mix: a
matching `nameRule` always beats every `tagRule`, and so on down the chain. A
resource that no rule matches and that no scope or global default covers is a
**validation error**, not a silent inheritance.

## Independent per-attribute resolution

Each attribute resolves independently down the same chain. `securityImpactProfile`
resolves from the first rule (in family then document order) that sets
`securityImpactProfile`; `multiAgency` resolves from the first rule that sets
`multiAgency`. A one-line `nameRule` can flip `multiAgency` for a single
resource while its SIP continues to resolve from a broader rule. Any rule in
any family may carry either attribute or both; a rule must carry at least one.

## Rule-family fields

`type` compares **exactly** (provider asset-inventory type strings, exactly
what `gcloud asset list` and the AWS Config/tagging APIs emit, so discovery
needs no mapping layer). Every other match field — `match`, `matchTags` values,
`network`, `subnet`, `region` — is an `fnmatch` glob.

Under the GCP Cloud Asset API inventory path, Compute Engine instance `region`
values are zone-granular (e.g. `us-central1-a`), while the per-service fallback
records the true region (`us-central1`), so write region globs tolerant of both
(e.g. `us-central1*`).

| Family | Required field | Optional narrowing fields | Notes |
|---|---|---|---|
| `nameRules` | `match` | `type` (strongly recommended), `matchTags`, `region` | name globs are meaningless across types, so always pin `type` |
| `tagRules` | `matchTags` | `type`, `region` | every key/value in `matchTags` must match; values may be globs |
| `networkRules` | `network` | `subnet`, `type`, `region` | applies only to network-attached types; can never match a global resource such as a bucket |
| `typeRules` | `type` | `region` | matches a whole resource family in the scope |

Any rule may also set `securityImpactProfile`, `multiAgency`, or both; at least
one is required. Optional secondary constraints AND together within a rule, so
compound matches need no extra mechanism. A `networkRule` whose `type` is a
global (non-network-attached) type fails validation.

## Primary identifiers

`match` globs against the resource type's **primary identifier**, fixed by this
table. AWS Name-tag matching goes through `tagRules` (`matchTags: {Name:
"web-*"}`), never `nameRules`, so a resource never has two competing name
identities.

| Provider | Resource type | Primary identifier |
|---|---|---|
| GCP | `storage.googleapis.com/Bucket` | bucket name |
| GCP | `sqladmin.googleapis.com/Instance` | Cloud SQL instance name |
| GCP | `compute.googleapis.com/Instance` | GCE instance name |
| GCP | `bigquery.googleapis.com/Dataset` | BigQuery dataset id |
| AWS | `AWS::S3::Bucket` | S3 bucket name |
| AWS | `AWS::EC2::Instance` | EC2 **instance ID** (Name-tag matching goes through `tagRules`) |
| AWS | `AWS::RDS::DBInstance` | RDS DB identifier |

## Value and comment conventions

- SIP values use **canonical dotted form** inside this document: a direct
  vector (`cr-h_ir-m_ar-l`), a governed decision trace
  (`<disclosure>.<trusted-change>.<dependency>`), or a named archetype. Provider
  label encodings (GCP `vdr_fedramp_io_*` keys and `__` trace separators, Azure
  `.` keys) apply only to actual cloud tags and are decoded at discovery; they
  never appear inside `vdr-cloud.yaml`. See
  `../../tag-terraform-vdr-assets/references/cis-asset-map.md` for the encoding
  rules.
- `class` and `multiAgency` are quoted strings (`"A"`–`"D"`, `"true"`/`"false"`),
  same as `vdr-fedramp`.
- `# confidence: high|medium|low` sits immediately above every rule or coherent
  rule group and above every `class`/`multiAgency` value, even
  operator-confirmed ones. `# manual-review: ...` accompanies every non-high
  rule and value. Confidence describes evidence quality; it never lowers a
  CR/IR/AR value.
- Materialized managed-resource patterns carry a `# builtin-pattern: <id>`
  comment above their `# confidence:` line; they are always capped at medium
  confidence and always carry a manual-review comment.
- Existing `vdr.fedramp.io/*` tags found during discovery are reported as
  override agreements/conflicts, not treated as operator attestations unless
  reconfirmed.

## Fail-loud stance on broad defaults

Both the scope block and global `defaults` may carry an optional
`securityImpactProfile` fallback, but the skill discourages it where resource
roles vary. The preferred posture is **fail-loud**: a resource that no rule
matches fails validation rather than inheriting a broad default, matching the
Kubernetes skill's stance on broad namespace fallbacks. When Class or agency
scope is unattested, the skill still emits fail-closed provisional values
(class `"D"`, multiAgency `"true"`) with confidence and manual-review
annotations rather than withholding the document — but it does not paper over
unresolved SIP with a broad default.

## Assignment-plan JSON shape

The agent authors `./vdr-cloud-output/assignment-plan.json`; `render_cloud_config.py`
turns it into `vdr-cloud.yaml`, and `validate_cloud_config.py` replays it. The
schema below is the complete contract for authoring a plan without reading the
script source.

```json
{
  "defaults": {
    "class": {"value": "C", "confidence": "high",
              "evidence": "operator-confirmed FedRAMP Moderate", "manualReview": []},
    "multiAgency": {"value": "false", "confidence": "high",
                    "evidence": "operator-confirmed single agency", "manualReview": []},
    "securityImpactProfile": null
  },
  "archetypes": {},
  "scopes": [
    {
      "provider": "gcp",
      "project": "acme-prod",
      "class": {"value": "C", "confidence": "high", "evidence": "operator-confirmed", "manualReview": []},
      "multiAgency": {"value": "false", "confidence": "high", "evidence": "operator-confirmed", "manualReview": []},
      "securityImpactProfile": null,
      "nameRules": [
        {"type": "storage.googleapis.com/Bucket", "match": "gcf-sources-*",
         "securityImpactProfile": "service-content.disposable-state.deferrable-work",
         "multiAgency": null, "region": null, "matchTags": null,
         "confidence": "medium", "builtinPattern": "gcp-cloudfunctions-staging",
         "evidence": "provider-created transient artifact store",
         "manualReview": ["attest CR down with a direct vector only after verifying staged contents are non-sensitive",
                          "confirm nothing re-consumes artifacts post-deploy (would raise IR)"]}
      ],
      "tagRules": [],
      "networkRules": [],
      "typeRules": []
    }
  ]
}
```

Field notes:

- **Scope identity.** GCP scopes carry `"project": "<id>"`; AWS scopes carry
  `"account": "<12-digit-id>"`. The scope key used everywhere (coverage,
  validation, reports) is `"<provider>/<project-or-account>"`.
- **Attestations** (`class`, `multiAgency` at the defaults and scope levels) are
  objects with `value`, `confidence` (`high|medium|low`), `evidence`, and a
  `manualReview` list. A non-high confidence with an empty `manualReview` is a
  render-time `ValueError`.
- **`securityImpactProfile`** at defaults/scope level is a canonical SIP string
  or `null` (prefer `null` and let rules fail loud).
- **Rules** carry the family match fields (see the field table above),
  `securityImpactProfile` and/or `multiAgency` (at least one non-null),
  `confidence`, optional `builtinPattern` id, `evidence`, and a `manualReview`
  list. `type` compares exactly; `match`, `matchTags` values, `network`,
  `subnet`, and `region` use `fnmatch.fnmatchcase` globs. Unused fields may be
  `null` or omitted.
- **`archetypes`** is usually `{}`. A non-empty entry renders as
  `name: {description: ..., cr: H, ir: M, ar: L}`.

The paired coverage ledger (`assignment-coverage.json`) that `validate_cloud_config.py`
checks has top-level `scopes`, `inventoryTotal`, `assignments`,
`configurationAssumptions`, and `summary`. Each assignment entry records
`scope`, `type`, `identifier`, `securityImpactProfile`, `derivationMethod`
(`direct-vector` | `decision-trace` | `named-archetype`), `vector`,
`resolutionSource` (the resolving rule, e.g. `nameRules[0]`, or `tag-override`
/ `scope-default` / `global-default`), `multiAgency`, `multiAgencySource`,
`status` (`operator-confirmed` | `agent-inferred` | `builtin-pattern`),
`confidence`, `evidence`, `assumptions`, and `manualReview`. Non-high entries
carry at least one concrete manual-review item. `summary` counts by scope,
rule family, status, and confidence.
