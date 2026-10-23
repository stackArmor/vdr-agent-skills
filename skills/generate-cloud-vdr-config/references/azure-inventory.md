# Azure cloud classification

The cloud generation and coverage-update workflows support Azure Commercial
(`AzureCloud`) and Azure US Government (`AzureUSGovernment`) with the existing
Azure CLI login. They generate the same `vdr-cloud.yaml` consumed by TSW.
No Azure infrastructure or authentication configuration is changed.

## Scope and credentials

Ask the operator to select each subscription explicitly. Show the subscription
ID, tenant, principal, and active cloud from read-only `az account show` and
`az cloud show`, and obtain scope confirmation before inventory. Recommend a
read-only identity. Do not run `az login`, `az account set`, `az cloud set`,
extension installation, or token commands. An existing `AZURE_CONFIG_DIR` may
select the operator's CLI environment; never read its credential files.

```bash
python3 <skill-dir>/scripts/inventory_cloud_resources.py \
  --provider azure --subscription '<confirmed-subscription-uuid>' \
  --output ./vdr-cloud-output/scope-azure-<subscription>.json
```

Every resource query pins `--subscription`. Subscription UUIDs are normalized
to lowercase. The helper checks the principal, tenant, subscription, and cloud
again before returning. A change invalidates the run; reconfirm before retrying.

## Inventory and exclusions

`az resource list` supplies IDs, names, ARM types, locations, and tags.
Read-only parent projections enumerate VNet subnets, load-balancer rules and
application-gateway listeners, backend pools, and probes. SQL database and
Service Bus queue/topic/subscription children use explicit service list calls.
VM NIC/subnet references provide known network attachments. No Resource Graph
extension is needed.

The supported assignment families follow TSW's Azure cloud-scoring types:

- VMs, VNets/subnets, network/application security groups, routes, gateways,
  Azure Firewall, and public IPs;
- load balancers, application gateways, their rule/listener/pool/probe children,
  and application-gateway WAF policies;
- storage accounts, SQL servers/databases/managed instances, PostgreSQL/MySQL
  flexible servers, and Cosmos DB accounts;
- Service Bus queues/topics/subscriptions and Container Apps services/jobs.

Unsupported types are reported in `provenance.excludedResourceTypes` rather
than silently counted as classified. Failed child/enrichment queries retain
their parent resource and record warnings plus failed collection results.
A failed subscription-wide inventory aborts that scope. Preserve these limits
in coverage and handoff; an empty result from a failed query is not absence.

CLI queries project only metadata. Never fetch or retain VM user-data,
container environment values or secrets, certificate/private-key data,
storage keys, database contents, or credentials. Resource names and tags may
still be sensitive metadata.

## Identity and matching

Azure scopes use `provider: azure` and `subscription: '<uuid>'`; never put the
subscription in `project` or `account`.

Inventory `identifier` and `providerUri` are the complete, normalized ARM ID.
Coverage keys retain that full ID so same-named resources in different resource
groups remain distinct. The separate `name` field is the resource's short name,
including the final child name for nested resources.

**TSW name rules match that short `name`, not the ARM ID.** Always pin the ARM
`type` and inspect all current matches. When names collide, use reviewed tag or
region constraints, or verified coherent grouping. Do not claim a name rule
distinguishes resource groups that its selectors cannot distinguish.

Known network/subnet ARM IDs and their short names support network-rule replay
case-insensitively, matching TSW. Do not infer attachments from private
endpoints, firewall allowlists, or nearby resources. Storage accounts are not
network-attached assignment targets; their network ACLs do not make a
`networkRules` selector valid.

Provider-native dotted VDR tags remain available as metadata evidence and
`matchTags` selectors. Do not treat an encoded tag as a runtime override unless
the deployed consumer accepts that exact key. Materialize an operator-reviewed
typed rule where needed; keep the profile in canonical form in the YAML.

## Review and publication

Use the same independent CR/IR/AR taxonomy, Class and multi-agency attestations,
confidence notes, and coverage equation as AWS/GCP. Render with the shared
renderer and validate the inventory, plan, coverage, and output before handoff.
See `../assets/vdr-cloud.azure.example.yaml` for a fictional policy.

The operator publishes approved policy to the agreed storage location. TSW
supports Azure Blob Storage for Azure deployments; coordinate the account,
container/blob location, and ingestion configuration with the engagement team.
Discovery does not establish that a particular collector is deployed.

For later additive coverage maintenance, use `update-cloud-vdr-config`; retain
existing Azure assignments, including scopes not inventoried in this run.

References: [Azure resource CLI](https://learn.microsoft.com/en-us/cli/azure/resource),
[Azure account CLI](https://learn.microsoft.com/en-us/cli/azure/account),
[Azure cloud CLI](https://learn.microsoft.com/en-us/cli/azure/cloud).
