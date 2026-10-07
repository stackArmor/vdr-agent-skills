# GKE infrastructure and admission-policy coverage

Use cloud rules for clusters, node pools, fleet memberships, project Binary
Authorization policies, subnets and load-balancer proxies. Kubernetes objects
inside a cluster use the separate ConfigMap skills. Preserve existing scores
when maintaining coverage; a new finding is not a new asset.

## Evidence and identities

Cloud Asset Inventory discovers these types through RESOURCE content.
Cluster and membership primary identifiers are their names. Node pools use the
full project/location/cluster/nodePool path so repeated pool names remain distinct.
Binary Authorization uses `projects/PROJECT/policy`. Subnets/proxies use names
within the selected project. Keep full provider URIs for precise SCC joins.
Record the cluster owning each node pool and the node subnet separately from
other similarly named subnets: a PGA finding on an endpoint subnet does not
describe the cluster's node subnet.

The per-service fallback lists GKE clusters and their returned node pools and
reads the project Binary Authorization policy. API-disabled/permission failures
remain explicit coverage warnings; never enable services during discovery.
An unavailable policy is unknown, not evidence of an absent policy. CAI is
eventually consistent, so use current read-only `gcloud container clusters
describe` and `gcloud container binauthz policy export` when enforcement matters.

## Independent CR/IR/AR

| Asset | CR evidence | IR evidence | AR evidence |
|---|---|---|---|
| Cluster | Tenant data and identities reachable through its authority; public configuration alone does not imply H | Control of scheduling, workload identity and admitted releases | Complete logical loss of this cluster function: mission runtime, recovery dependency or deferrable platform work |
| Node pool | Data/authority reachable by workloads placed on that pool | Node trust, credentials and workload isolation | Actual role of the pool; independently assess runtime/recovery dependency and a pool used only for builds |
| Fleet membership | Connect authority and exposed metadata | Accepted administration of the registered cluster | Whether loss prevents mandatory operations or recovery |
| Binary Authorization policy | Usually configuration and attestor-reference metadata; inspect sensitivity independently | Ability to admit untrusted releases or alter the trust boundary | Deployment/release delay versus a verified recovery-critical dependency; policy loss does not necessarily stop running workloads |
| Subnet / LB proxy | Topology, endpoint and enforcement metadata | Trusted routing, isolation or TLS policy | Shared service connectivity versus a deferrable/unused component |

Use the governed traces already in the archetype guide. No family-wide H/H/H
default and no new taxonomy reasons are needed. HA and current SCC severity
do not lower the asset's logical availability requirement.

## Binary Authorization applicability

Policy existence alone proves no enforcement. Read both sides:

1. GKE cluster `binaryAuthorization.enabled` / `evaluationMode` (for the
   singleton policy, `PROJECT_SINGLETON_POLICY_ENFORCE`).
2. Project policy's default/cluster admission rules, evaluation and enforcement
   modes, required attestors, image allowlists, namespace and Kubernetes
   service-account rules, and global-policy evaluation.

Record the effective applicable rule and any unsigned-image exceptions in the
decision ledger. `ALWAYS_ALLOW`, dry-run enforcement and image allowlists can
permit unsigned releases even when the cluster opted in. Namespace/service-account
exceptions are admission-policy controls, not VDR scoring rules. Respect documented
rule precedence; if overlapping rules or available metadata cannot establish
coverage, mark it unknown and require review. Do not infer compliance merely
because a signature exists; the configured attestor and enforcement must match.

For Cloud Run, inspect the actual service/job Binary Authorization setting and
its referenced policy plus any breakglass use. GKE namespace exceptions do not
automatically exempt a Cloud Run service/job. Keep admission evidence distinct
from the asset's CR/IR/AR profile. The scripts retain allowlisted metadata and
mark runtime coverage unverified; the operator/agent must complete this review.

SCC `BINARY_AUTHORIZATION_DISABLED` is attached to a cluster and can mean either
cluster opt-out or a policy that permits all images. Score the affected cluster;
score a policy separately only when it is itself a target or a separately
inventoried control needing coverage. Workload hardening checks sometimes attach
aggregate findings to the cluster: retain the scanner resource identity and
record workload details for later evidence-backed resource substitution.

References: [SCC detector](https://docs.cloud.google.com/security-command-center/docs/concepts-vulnerabilities-findings#binary_authorization_disabled),
[GKE enforcement](https://docs.cloud.google.com/binary-authorization/docs/enable-binauthz),
[GKE policy rules](https://docs.cloud.google.com/binary-authorization/docs/creating-policy).
