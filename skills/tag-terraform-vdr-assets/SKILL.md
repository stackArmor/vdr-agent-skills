---
name: tag-terraform-vdr-assets
description: Inventory Terraform for AWS, Azure, and GCP resources addressed by the CIS Foundations Benchmarks; classify only those assets with operator-attested VDR compositional asset-archetypes; add provider-valid labels or tags without applying infrastructure; and optionally place Certification Class and multi-agency scope on Terraform-managed GCP projects or AWS accounts. Use for selective Terraform PAIN metadata, CIS-scoped cloud asset tagging, or review of which IaC resources should remain untagged.
---

# Tag Terraform VDR Assets

Select only CIS-addressed cloud assets, attest their impact, and add metadata for
VDR PAIN scoring. Resolve `<skill-dir>` to the directory containing this file.

## Ground rules

- Inspect the requested Terraform tree before editing it. Never run `terraform
  apply`, mutate state, use a provider-wide `default_tags`/`default_labels`
  block, or tag every resource.
- Never read `.tfstate` or plan files. Read `.tfvars` only when classification
  evidence requires it; do not reproduce credentials or other secret values.
- Treat CIS applicability and PAIN impact as separate decisions. Resource type
  establishes eligibility, never the CR/IR/AR vector.
- Preserve existing tags, labels, expressions, comments, and unrelated user
  changes. Never replace a whole metadata map merely to add VDR keys.
- Do not add an unsupported `labels`, `tags`, or `user_labels` argument. Report
  a benchmark-relevant but untaggable asset as a coverage gap.
- Require operator confirmation for each archetype and for Class or agency
  scope. Existing environment names and labels are evidence, not attestation.

## Canonical metadata

Use the compositional value:

```text
<disclosure>.<trusted-change>.<dependency>
```

Read `../generate-vdr-configmap/references/archetype-guide.md` completely before
classifying any asset. It governs the reason registries, five-question
interview, CR/IR/AR derivation, availability rules, and exact value length.

Read `references/cis-asset-map.md` completely before inventory or edits. It
defines the benchmark scope, exclusions, provider key/value encodings, native
metadata surfaces, and the proposed fallback for untaggable assets. The raw
machine mapping used by inventory is `references/cis-asset-map.json`.

## Workflow

### 1. Establish scope and safety

Confirm the Terraform root and whether the request authorizes edits or only a
review. Inspect `git status --short`; preserve all pre-existing changes. Locate
`.terraform/modules/modules.json` if it already exists, but never initialize or
download modules merely to classify the tree without the user's approval.

### 2. Inventory CIS-addressed assets

Run:

```bash
python3 <skill-dir>/scripts/inventory_terraform_assets.py <terraform-root>
```

Use `--format json` for structured analysis and `--include-unknown` only to
audit exclusions. The script reads `.tf` source only, skips `.terraform`, and
does not modify files.

Review three groups separately:

1. `native`: a directly declared resource with a known provider metadata field.
2. `none`: CIS-addressed, but the provider type has no native metadata field.
3. `module-review`: a module likely creates eligible assets; inspect its pinned
   implementation and verify that a metadata input is forwarded to the target
   resource before editing the call.

Do not infer eligibility from a generic `labels` or `tags` argument. Use the
asset map and the actual resource or module implementation.

### 3. Gather role and consequence evidence

For each candidate or coherent group, inspect only the HCL needed to determine:

- payload or data sensitivity;
- read, write, IAM, impersonation, deployment, or trust authority;
- affected service and population if the asset is logically unavailable;
- whether the resource is primary or merely a child/configuration attachment;
- whether production-equivalent impact is intended.

Prefer first-class assets over their implementation debris. For example,
classify a bucket, not every bucket object; a VM, not each IAM attachment; a
managed database instance, not each DNS record. Keep a child resource only
when the CIS recommendation or compliance finding directly evaluates it.

### 4. Interview, propose, and confirm

Ask no more than the five questions in the archetype guide for an asset or
coherent group. Then show a review table containing:

- Terraform address and CIS section;
- exact canonical trace and derived CR/IR/AR;
- one-line evidence and assumptions;
- provider encoding and metadata surface;
- confidence and confirmation status.

Leave unresolved candidates unchanged. Do not replace uncertainty with a
resource-type default. Use `asset-value` only when the operator explicitly
chooses the simpler H/M/L fallback.

### 5. Confirm optional cloud scope

Ask whether Terraform-managed GCP projects and AWS accounts in the selected
stack should carry scope defaults. Map the existing FedRAMP authorization:

| Authorization | Class |
|---|---|
| FedRAMP Ready | A |
| FedRAMP Low | B |
| FedRAMP Moderate | C |
| FedRAMP High | D |

Confirm `multi-agency` independently (`true` only when compromise of that
project/account can affect more than one agency). Add Class and agency scope
only to the project/account carrier, not to every child resource. Do not create
a project or account solely to hold metadata.

### 6. Edit provider-native metadata

Use the provider encodings in `references/cis-asset-map.md` exactly. Preserve
literal maps by inserting keys. Preserve computed maps with a non-destructive
`merge(existing_expression, { ... })` only when type-compatible. For GCP SQL,
edit `settings.user_labels` or a module input demonstrably forwarded there.

Validate and encode each confirmed metadata set before editing:

```bash
python3 <skill-dir>/scripts/encode_vdr_metadata.py \
  --provider gcp \
  --archetype '<confirmed-trace>' \
  --class C \
  --multi-agency false
```

Omit the scope flags for ordinary assets. The script imports the governed
reason registry from the sibling ConfigMap skill, derives CR/IR/AR, and emits a
JSON metadata map; it never edits Terraform.

For module calls, inspect the pinned module variable and its target resource.
Do not assume an input named `labels` or `tags` exists. When one module call
creates several independently different assets, do not force one archetype
onto all of them; modify the module interface only with explicit scope and
approval.

The current `trivy-plugin-vdr` scoring keys are canonical Kubernetes/AWS-style
keys. GCP and Azure require transport aliases. State clearly that a downstream
Terraform/compliance finding consumer must normalize those aliases before PAIN
scoring; do not claim an unsupported integration already consumes them.

### 7. Handle untaggable assets

Never add an invalid argument. Report the Terraform address, proposed trace,
and missing provider surface. If the user asks for machine-readable coverage,
emit the proposed `vdr-terraform-assets.yaml` sidecar described in the reference
using canonical keys. Label it as an integration contract, not metadata that a
current provider or plugin automatically consumes.

### 8. Validate without deploying

After edits:

1. Run the inventory script again and compare candidate coverage.
2. Validate every trace against the governed reason registries and derive its
   vector mechanically.
3. Check provider key/value grammar, including GCP's encoded trace and lowercase
   Class.
4. Run `terraform fmt` only on touched `.tf` files.
5. Run `terraform validate` only when the tree is already initialized and it
   requires no downloads or credentials.
6. Review `git diff --check` and the full diff. Confirm that no unknown,
   auxiliary, or provider-default resource was tagged.
7. Keep the `skills/` and `.agents/skills/` copies byte-identical.

Never run a plan with refresh or apply the changes.

## Handoff

Report confirmed native tags, confirmed scope defaults, unchanged ambiguous
assets, untaggable coverage gaps, and excluded resource families. Include the
normalization requirement for any GCP/Azure aliases and state which validation
commands ran.
