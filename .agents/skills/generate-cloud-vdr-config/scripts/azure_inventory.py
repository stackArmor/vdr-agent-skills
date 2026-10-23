"""Read-only Azure CLI discovery for TSW's existing cloud scoring contract.

Only metadata projections are returned by the CLI. No Resource Graph extension,
login, account/cloud switching, secret, storage-key, or data-plane calls occur.
"""

import json
import uuid


AZURE_TYPES = (
    "Microsoft.Compute/virtualMachines",
    "Microsoft.Network/virtualNetworks",
    "Microsoft.Network/virtualNetworks/subnets",
    "Microsoft.Network/networkSecurityGroups",
    "Microsoft.Network/applicationSecurityGroups",
    "Microsoft.Network/routeTables",
    "Microsoft.Network/natGateways",
    "Microsoft.Network/virtualNetworkGateways",
    "Microsoft.Network/azureFirewalls",
    "Microsoft.Network/publicIPAddresses",
    "Microsoft.Network/loadBalancers",
    "Microsoft.Network/applicationGateways",
    "Microsoft.Network/loadBalancers/loadBalancingRules",
    "Microsoft.Network/applicationGateways/httpListeners",
    "Microsoft.Network/loadBalancers/backendAddressPools",
    "Microsoft.Network/applicationGateways/backendAddressPools",
    "Microsoft.Network/loadBalancers/probes",
    "Microsoft.Network/applicationGateways/probes",
    "Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies",
    "Microsoft.Storage/storageAccounts",
    "Microsoft.Sql/servers",
    "Microsoft.Sql/servers/databases",
    "Microsoft.Sql/managedInstances",
    "Microsoft.DBforPostgreSQL/flexibleServers",
    "Microsoft.DBforMySQL/flexibleServers",
    "Microsoft.DocumentDB/databaseAccounts",
    "Microsoft.ServiceBus/namespaces/queues",
    "Microsoft.ServiceBus/namespaces/topics",
    "Microsoft.ServiceBus/namespaces/topics/subscriptions",
    "Microsoft.App/containerApps",
    "Microsoft.App/jobs",
)
TYPE_NAMES = {name.lower(): name for name in AZURE_TYPES}
CLOUDS = {"AzureCloud": "azure", "AzureUSGovernment": "azure-us-government"}
ROW = "{id:id,name:name,type:type,location:location,resourceGroup:resourceGroup,tags:tags}"
CHILDREN = {
    "Microsoft.Network/virtualNetworks": ("subnets",),
    "Microsoft.Network/loadBalancers": ("loadBalancingRules", "backendAddressPools", "probes"),
    "Microsoft.Network/applicationGateways": ("httpListeners", "backendAddressPools", "probes"),
}


def subscription_id(value):
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, AttributeError) as exc:
        raise ValueError("Azure subscription must be a UUID") from exc


def arm_id(value, subscription):
    value = str(value or "").rstrip("/")
    parts = value.strip("/").split("/")
    if (len(parts) < 8 or parts[0].lower() != "subscriptions"
            or parts[1].lower() != subscription or parts[2].lower() != "resourcegroups"
            or parts[4].lower() != "providers" or len(parts[6:]) % 2):
        raise RuntimeError("Azure returned a malformed or out-of-scope resource ID")
    return "/" + "/".join(parts).lower()


def _resource_type(raw_id):
    parts = raw_id.strip("/").split("/")
    provider_index = next((i for i, value in enumerate(parts) if value.lower() == "providers"), None)
    if provider_index is None or len(parts) <= provider_index + 2:
        return ""
    return "/".join([parts[provider_index + 1]] + parts[provider_index + 2::2])


def discover(subscription, patterns, runner, build_resource, summarize_tags):
    subscription = subscription_id(subscription)

    def query(args, projection):
        return json.loads(runner(["az"] + args + ["--subscription", subscription,
                          "--query", projection, "--output", "json", "--only-show-errors"]))

    def identity():
        return query(["account", "show"],
                     "{id:id,tenantId:tenantId,environmentName:environmentName,user:user.name}")

    before = identity()
    if subscription_id(before.get("id")) != subscription:
        raise RuntimeError("Azure CLI resolved a different subscription")
    cloud = json.loads(runner(["az", "cloud", "show", "--query", "name",
                               "--output", "json", "--only-show-errors"]))
    if cloud not in CLOUDS or before.get("environmentName") != cloud:
        raise RuntimeError("Azure CLI cloud must match the reviewed AzureCloud or AzureUSGovernment subscription")

    raw_resources = query(["resource", "list"], "[]." + ROW)
    if not isinstance(raw_resources, list):
        raise RuntimeError("Azure resource inventory did not return a list")
    provider_patterns = [p for p in patterns if p.get("provider") == "azure"]
    resources, raw_by_id, warnings, results = {}, {}, [], []

    def add(row, parent=None):
        raw_id = str(row.get("id") or "").rstrip("/")
        if not raw_id.lower().startswith("/subscriptions/" + subscription + "/"):
            raise RuntimeError("Azure returned a malformed or out-of-scope resource ID")
        rtype = TYPE_NAMES.get(_resource_type(raw_id).lower())
        if str(row.get("type") or "").lower() in TYPE_NAMES and not rtype:
            raise RuntimeError("Azure resource type and resource ID disagree")
        # Subscription-level policy/extension objects are excluded, not invalid
        # resource-group assignments. Never interpret them as classified.
        if not rtype:
            raw_by_id[raw_id.lower()] = row
            return
        rid = arm_id(raw_id, subscription)
        raw_by_id[rid] = row
        tags = row.get("tags") or (resources.get(rid) or {}).get("tags") or {}
        tags = {str(k): str(v) for k, v in tags.items() if v is not None}
        resource = build_resource(rtype, rid, row.get("location") or (parent or {}).get("location"),
                                  tags, None, None, provider_patterns, provider="azure")
        # TSW matches nameRules against resource.name; full ARM identity keeps
        # same-named resources in different resource groups distinct in coverage.
        resource.update(provider="azure", name=str(row.get("name") or row["id"]).rsplit("/", 1)[-1],
                        providerUri=rid, metadata={"resourceGroup": rid.split("/")[4]})
        if rid in resources:
            for key in ("network", "subnet", "networks", "subnets"):
                if key in resources[rid]:
                    resource[key] = resources[rid][key]
        resources[rid] = resource

    for row in raw_resources:
        add(row)

    def collect(args, projection, label):
        try:
            data = query(args, projection)
            if data is None or not isinstance(data, (dict, list)):
                raise ValueError("query returned no usable projected metadata")
            results.append({"collection": label, "status": "complete"})
            return data
        except (RuntimeError, ValueError) as exc:
            warnings.append("Azure %s was not fully inventoried: %s" % (label, str(exc).splitlines()[0]))
            results.append({"collection": label, "status": "failed"})
            return None

    def attach(rid, subnets):
        resource = resources.get(rid)
        if not resource:
            return
        subnet_ids = sorted({arm_id(s, subscription) for s in subnets if s})
        network_ids = sorted({s.rsplit("/subnets/", 1)[0] for s in subnet_ids if "/subnets/" in s})
        resource["subnets"] = subnet_ids
        resource["networks"] = network_ids
        resource["subnet"] = subnet_ids[0] if subnet_ids else None
        resource["network"] = network_ids[0] if network_ids else None

    for rid, row in list(raw_by_id.items()):
        rtype = TYPE_NAMES.get(_resource_type(rid).lower())
        if rtype in CHILDREN:
            fields = CHILDREN[rtype]
            projection = "{" + ",".join(f + ":properties." + f + "[].{id:id,name:name}" for f in fields)
            projection += ",subnetIds:[properties.gatewayIPConfigurations[].properties.subnet.id,properties.frontendIPConfigurations[].properties.subnet.id][]}"
            data = collect(["resource", "show", "--ids", rid], projection, rid)
            if data is None:
                continue
            attach(rid, data.get("subnetIds") or [])
            for field in fields:
                for child in data.get(field) or []:
                    child_id = arm_id(child.get("id"), subscription)
                    if not child_id.startswith(rid + "/" + field.lower() + "/"):
                        raise RuntimeError("Azure child resource belongs to a different parent")
                    add(child, row)
                    if field == "subnets":
                        attach(child_id, [child_id])
                        resources[child_id]["subnet"] = None
                        resources[child_id]["subnets"] = []
                    else:
                        attach(child_id, data.get("subnetIds") or [])
        elif rtype == "Microsoft.Compute/virtualMachines":
            data = collect(["resource", "show", "--ids", rid],
                           "properties.networkProfile.networkInterfaces[].id", rid + " network interfaces")
            subnets = []
            for nic in data or []:
                nic_id = arm_id(nic, subscription)
                values = collect(["resource", "show", "--ids", nic_id],
                                 "properties.ipConfigurations[].properties.subnet.id", nic_id)
                subnets.extend(values or [])
            attach(rid, subnets)
        elif rtype == "Microsoft.Sql/servers":
            children = collect(["sql", "db", "list", "--server", row["name"],
                                "--resource-group", rid.split("/")[4]], "[]." + ROW, rid + " databases")
            for child in children or []:
                child_id = arm_id(child.get("id"), subscription)
                if not child_id.startswith(rid + "/databases/"):
                    raise RuntimeError("Azure database belongs to a different server")
                add(child, row)
        # Namespaces are discovery parents, not scoreable resource assignments.
        elif _resource_type(rid).lower() == "microsoft.servicebus/namespaces":
            prefix = ["--namespace-name", row["name"], "--resource-group", rid.split("/")[4]]
            for family in ("queue", "topic"):
                children = collect(["servicebus", family, "list"] + prefix,
                                   "[]." + ROW, rid + " " + family)
                for child in children or []:
                    child_id = arm_id(child.get("id"), subscription)
                    suffix = "/queues/" if family == "queue" else "/topics/"
                    if not child_id.startswith(rid + suffix):
                        raise RuntimeError("Azure messaging resource belongs to a different namespace")
                    add(child, row)
                    if family == "topic":
                        subscriptions = collect(["servicebus", "topic", "subscription", "list"] + prefix
                                                + ["--topic-name", str(child["name"]).rsplit("/", 1)[-1]],
                                                "[]." + ROW, child_id + " subscriptions")
                        for item in subscriptions or []:
                            item_id = arm_id(item.get("id"), subscription)
                            if not item_id.startswith(child_id + "/subscriptions/"):
                                raise RuntimeError("Azure message subscription belongs to a different topic")
                            add(item, row)

    if identity() != before:
        raise RuntimeError("Azure CLI identity changed during inventory; reconfirm the subscription and principal")
    after_cloud = json.loads(runner(["az", "cloud", "show", "--query", "name",
                                    "--output", "json", "--only-show-errors"]))
    if after_cloud != cloud:
        raise RuntimeError("Azure CLI cloud changed during inventory")
    excluded = {}
    for rid in raw_by_id:
        kind = _resource_type(rid)
        if kind.lower() not in TYPE_NAMES:
            excluded[kind] = excluded.get(kind, 0) + 1
    output = sorted(resources.values(), key=lambda r: (r["type"], r["identifier"]))
    return {"provider": "azure", "subscription": subscription,
            "provenance": {"inventorySource": "azure-cli", "resolvedScope": subscription,
                           "callerIdentity": before.get("user"), "tenantId": before.get("tenantId"),
                           "cloudEnvironment": CLOUDS[cloud], "collectionResults": results,
                           "excludedResourceTypes": excluded},
            "resources": output, "tagSummary": summarize_tags(output), "warnings": warnings}
