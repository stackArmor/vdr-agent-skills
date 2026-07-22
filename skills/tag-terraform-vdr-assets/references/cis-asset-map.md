# CIS Foundations Terraform asset map

## Contents

1. [Selection rule](#selection-rule)
2. [Benchmark-derived asset families](#benchmark-derived-asset-families)
3. [Explicit exclusions](#explicit-exclusions)
4. [Metadata transport schema](#metadata-transport-schema)
5. [Native metadata surfaces](#native-metadata-surfaces)
6. [Module calls](#module-calls)
7. [Untaggable sidecar proposal](#untaggable-sidecar-proposal)

## Selection rule

This map is a conservative allowlist derived from these supplied benchmarks:

- CIS Google Cloud Platform Foundation Benchmark v5.0.0
- CIS Amazon Web Services Foundations Benchmark v7.0.0
- CIS Microsoft Azure Foundations Benchmark v5.0.0

Include a Terraform block only when it declares the asset evaluated by a
benchmark recommendation, declares an authoritative scope/identity object, or
is the direct target of a compliance finding for that recommendation. A
benchmark mention does not make every supporting Terraform object a PAIN asset.

The JSON mapping is an inventory aid, not proof that a particular provider
version accepts metadata. Confirm the installed provider schema or pinned
module implementation before editing.

## Benchmark-derived asset families

| Provider | Benchmark sections | Primary asset families |
|---|---|---|
| GCP | 1 IAM | organizations, folders, projects, IAM roles/policies, service accounts and keys, API keys, KMS keys, Secret Manager secrets, functions whose environment may expose secrets |
| GCP | 2 Logging and Monitoring | audit/log sinks and buckets, log metrics, alert policies, notification channels, asset inventory/access settings, HTTP(S) load balancers |
| GCP | 3 Networking | VPCs, subnets, firewall rules/policies, routes, DNS managed zones/policies, service perimeters, Private Service Connect, load balancers and SSL policies |
| GCP | 4 Virtual Machines | VM instances/templates/groups, disks, snapshots/images, App Engine, Cloud Run/functions when they are the scanned compute asset |
| GCP | 5-8 Data services | Cloud Storage buckets, Cloud SQL instances, BigQuery datasets/tables, Dataproc clusters |
| AWS | 2 IAM | Organizations, OUs, accounts, organization policies, IAM users/groups/roles/policies/keys/certificates, instance profiles, access analyzers |
| AWS | 3 Storage | S3 buckets, RDS instances/clusters, EFS file systems |
| AWS | 4-5 Logging and Monitoring | CloudTrail, AWS Config, KMS keys, VPC flow logs, log groups/metric filters/alarms, notification topics, Security Hub |
| AWS | 6 Networking | EC2 instances/launch templates, EBS volumes/AMIs, VPCs/subnets, NACLs, security groups, route tables, peering, endpoints, and managed web front ends whose access logging is evaluated |
| Azure | 2-3 Analytics and Compute | Databricks workspaces, VMs/scale sets, managed disks/images |
| Azure | 4-5 Database and Identity | database services referenced by the Foundations benchmark, Entra users/groups/apps/service principals/roles/conditional access, managed identities, Azure role definitions/assignments |
| Azure | 6-8 Governance, Network, Security | subscriptions/resource groups/policies/locks, diagnostic settings, Log Analytics, alerts/Application Insights, VNets/subnets/NSGs/routes/public IPs/VPNs/private endpoints/Application Gateway/WAF/Bastion/DDoS, Defender settings, Key Vault/keys/secrets/certificates/HSM |
| Azure | 9 Storage | storage accounts, file shares, blob containers/blobs |

Database types in Azure section 4 are an explicit service-category reference,
not detailed Foundations recommendations. Keep them eligible because database
compliance findings and Defender database controls identify the database as the
affected asset; record the mapping as `Azure 4 (reference), 8.1.7`.

## Explicit exclusions

Exclude by default:

- `data` blocks, provider configuration, variables, outputs, and locals;
- `terraform_data`, `null_resource`, `random_*`, `local_file`, time/tls helper
  resources, and generated files;
- API-enablement resources such as `google_project_service`;
- bucket objects when the benchmark evaluates the bucket;
- DNS record sets when the benchmark evaluates the managed zone, DNSSEC policy,
  or network logging;
- IAM member/binding/attachment resources when they are only implementation
  edges for an already classified principal or asset; retain them only when the
  compliance finding directly targets the assignment/policy relationship;
- certificates, health checks, forwarding helpers, and similar implementation
  children unless a cited recommendation evaluates that exact object;
- module calls whose source and implementation do not establish an allowlisted
  asset family.

Do not use a provider-level default metadata block. It defeats this allowlist.

## Metadata transport schema

The semantic keys remain the existing VDR keys:

| Meaning | Canonical key | Value |
|---|---|---|
| Asset archetype | `vdr.fedramp.io/asset-archetype` | exact three-part dotted trace |
| Asset value fallback | `vdr.fedramp.io/asset-value` | `High`, `Medium`, or `Low` |
| Certification Class | `vdr.fedramp.io/class` | `A`, `B`, `C`, or `D` |
| Agency scope | `vdr.fedramp.io/multi-agency` | `true` or `false` |

Encode only where provider grammar requires it:

| Provider | Key encoding | Archetype value encoding | Class encoding |
|---|---|---|---|
| AWS tags | canonical key unchanged | canonical dotted trace | uppercase A-D |
| Azure tags | replace the `/` with `.`; e.g. `vdr.fedramp.io.asset-archetype` | canonical dotted trace | uppercase A-D |
| GCP labels | replace every `.`, `/`, and `-` in the key with `_`; e.g. `vdr_fedramp_io_asset_archetype` | replace the two trace separators `.` with `__`; e.g. `regulated-data__authoritative-record__shared-critical-path` | lowercase `a`-`d` |

GCP reason tokens contain hyphens but no underscores, so `__` is a reversible
separator for the governed registry. Never replace all hyphens in the value.
Decode the GCP alias and separators before validating the canonical trace.

These aliases are a transport proposal. A Terraform/compliance scanner must
normalize them to canonical keys and values before calling the current VDR
scoring engine. Kubernetes labels and AWS tags can use the canonical form
directly; current Cloud Run project/service label collection does not by itself
normalize the GCP aliases.

## Native metadata surfaces

Use only a surface present in the installed provider schema:

- AWS commonly uses top-level `tags`.
- Azure ARM resources commonly use top-level `tags`; AzureAD resources and
  role-assignment objects often have no tag surface.
- GCP varies: `labels` is common on projects, VMs/disks/images/snapshots,
  buckets, KMS crypto keys, secrets, DNS zones, BigQuery, Dataproc, and current
  Cloud Run/function resources. Cloud SQL uses `settings.user_labels`.
  Monitoring policies may use `user_labels`. Service accounts, IAM bindings,
  networks, firewall rules, routes, logging sinks, and KMS key rings commonly
  have no native label surface.

Treat `none` in the JSON map as a coverage report, never permission to invent an
argument. Treat `verify` as requiring installed-provider inspection.

## Module calls

A module name or source path is only a candidate hint. Inspect the pinned module
implementation and verify all of the following:

1. It creates an allowlisted primary asset.
2. Its metadata input reaches that asset's native surface.
3. One value is correct for every asset receiving the input.
4. Adding the input does not silently propagate to unrelated child resources.

If `.terraform/modules/modules.json` exists, use it to locate the exact cached
module. Otherwise inspect a local source path or ask before downloading.

## Untaggable sidecar proposal

Use this only when the user requests machine-readable coverage for provider
resources with no native metadata. It is a proposed integration contract, not
an input currently consumed by `trivy-plugin-vdr`:

```yaml
apiVersion: vdr.fedramp.io/v1alpha1
kind: TerraformAssetClassifications
assets:
  - address: google_service_account.example
    cisBenchmark:
      name: CIS Google Cloud Platform Foundation Benchmark
      version: 5.0.0
      sections: ["1.5", "1.6"]
    metadata:
      vdr.fedramp.io/asset-archetype: privileged-access.identity-control.change-deferred
```

Use stable Terraform addresses, canonical keys, and canonical dotted values.
Do not include secret material or inferred Class/multi-agency defaults on every
entry. Scope defaults belong on a Terraform-managed GCP project or AWS account.
