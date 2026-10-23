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

    def add(row, parent=None, inherit_tags=False):
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
        tags = ((parent or {}).get("tags") or {}) if inherit_tags else (
            row.get("tags") if row.get("tags") is not None else (resources.get(rid) or {}).get("tags", {}))
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

    def attach(rid, subnets=(), networks=()):
        resource = resources.get(rid)
        if not resource:
            return
        subnet_ids = sorted({arm_id(s, subscription) for s in subnets if s})
        network_ids = sorted({arm_id(n, subscription) for n in networks if n}
                             | {s.rsplit("/subnets/", 1)[0] for s in subnet_ids if "/subnets/" in s})
        resource.update(subnets=subnet_ids, networks=network_ids,
                        subnet=subnet_ids[0] if subnet_ids else None,
                        network=network_ids[0] if network_ids else None)

    nic_cache = {}

    def nic_data(nic):
        nic = arm_id(nic, subscription)
        if nic not in nic_cache:
            nic_cache[nic] = collect(["resource", "show", "--ids", nic],
                "{ipConfigurations:properties.ipConfigurations[].{id:id,subnet:properties.subnet.id,"
                "asgs:properties.applicationSecurityGroups[].id}}", nic) or {}
        return nic_cache[nic].get("ipConfigurations") or []

    def backend_subnets(ip_config_ids):
        subnets = []
        for ipc in ip_config_ids:
            ipc = arm_id(ipc, subscription)
            for config in nic_data(ipc.rsplit("/ipconfigurations/", 1)[0]):
                if str(config.get("id") or "").lower() == ipc and config.get("subnet"):
                    subnets.append(config["subnet"])
        return subnets

    # Explicit subnet references only. ACLs/private endpoints are not attachment.
    subnet_projections = {
        "Microsoft.Network/networkSecurityGroups": "properties.subnets[].id",
        "Microsoft.Network/routeTables": "properties.subnets[].id",
        "Microsoft.Network/natGateways": "properties.subnets[].id",
        "Microsoft.Network/virtualNetworkGateways": "properties.ipConfigurations[].properties.subnet.id",
        "Microsoft.Network/azureFirewalls": "[properties.ipConfigurations[].properties.subnet.id,properties.managementIPConfiguration.subnet.id][]",
        "Microsoft.Sql/managedInstances": "[properties.subnetId]",
        "Microsoft.DBforPostgreSQL/flexibleServers": "[properties.network.delegatedSubnetResourceId]",
        "Microsoft.DBforMySQL/flexibleServers": "[properties.network.delegatedSubnetResourceId]",
    }
    # VNet subnet references also provide NAT gateway reverse attachments.
    nat_subnets = {}
    for rid, row in list(raw_by_id.items()):
        rtype = TYPE_NAMES.get(_resource_type(rid).lower())
        if rtype in CHILDREN:
            fields = CHILDREN[rtype]
            child_projection = ("{id:id,name:name,subnet:properties.subnet.id,"
                "frontend:properties.frontendIPConfiguration.id,network:properties.virtualNetwork.id,"
                "backendIPs:properties.backendIPConfigurations[].id,"
                "backendAddresses:properties.loadBalancerBackendAddresses[].{network:properties.virtualNetwork.id,"
                "subnet:properties.subnet.id,ipConfig:properties.networkInterfaceIPConfiguration.id},"
                "natGateway:properties.natGateway.id}")
            projection = "{" + ",".join(f + ":properties." + f + "[]." + child_projection for f in fields)
            projection += (",gatewaySubnets:properties.gatewayIPConfigurations[].properties.subnet.id,"
                           "frontends:properties.frontendIPConfigurations[].{id:id,subnet:properties.subnet.id}}")
            data = collect(["resource", "show", "--ids", rid], projection, rid)
            if data is None:
                continue
            gateways = data.get("gatewaySubnets") or []
            frontends = data.get("frontends") or []
            parent_subnets = gateways + [f["subnet"] for f in frontends if f.get("subnet")]
            attach(rid, parent_subnets)
            for field in fields:
                for child in data.get(field) or []:
                    child_id = arm_id(child.get("id"), subscription)
                    if not child_id.startswith(rid + "/" + field.lower() + "/"):
                        raise RuntimeError("Azure child resource belongs to a different parent")
                    # TSW network-child normalizers inherit the parent's labels,
                    # even when an embedded child's own tags differ.
                    add(child, row, inherit_tags=True)
                    if field == "subnets":
                        attach(child_id, networks=[rid])
                        if child.get("natGateway"):
                            nat_subnets.setdefault(arm_id(child["natGateway"], subscription), []).append(child_id)
                    elif field == "probes":
                        # Probe -> balancer is not a direct network attachment.
                        attach(child_id)
                    elif field in ("httpListeners", "loadBalancingRules"):
                        matched = next((f for f in frontends if str(f.get("id") or "").lower()
                                        == str(child.get("frontend") or "").lower()), None)
                        if matched is None and len(frontends) == 1:
                            matched = frontends[0]
                        subnet = (gateways[0] if field == "httpListeners" and gateways else None)
                        subnet = subnet or (matched or {}).get("subnet")
                        attach(child_id, [subnet] if subnet else [])
                    elif field == "backendAddressPools":
                        subnets = backend_subnets(child.get("backendIPs") or [])
                        networks = []
                        for address in child.get("backendAddresses") or []:
                            if address.get("network"):
                                networks.append(address["network"])
                            elif address.get("subnet"):
                                subnets.append(address["subnet"])
                            elif address.get("ipConfig"):
                                subnets.extend(backend_subnets([address["ipConfig"]]))
                        candidates = {arm_id(n, subscription) for n in networks}
                        candidates.update(arm_id(s, subscription).rsplit("/subnets/", 1)[0]
                                          for s in subnets + parent_subnets if s)
                        if rtype == "Microsoft.Network/applicationGateways":
                            primary = gateways[0].rsplit("/subnets/", 1)[0] if gateways else None
                        else:
                            primary = child.get("network")
                        primary = primary or min(candidates, default=None)
                        # TSW pools expose only the primary VNet, no subnet.
                        attach(child_id, networks=[primary] if primary else [])
        elif rtype == "Microsoft.Compute/virtualMachines":
            data = collect(["resource", "show", "--ids", rid],
                           "properties.networkProfile.networkInterfaces[].id", rid + " network interfaces")
            subnets = [config["subnet"] for nic in data or [] for config in nic_data(nic) if config.get("subnet")]
            attach(rid, subnets)
        elif rtype in subnet_projections:
            subnets = collect(["resource", "show", "--ids", rid], subnet_projections[rtype], rid + " subnet attachments")
            attach(rid, subnets or [])
        elif rtype == "Microsoft.Network/applicationSecurityGroups":
            subnets = []
            for nic_id in list(raw_by_id):
                if _resource_type(nic_id).lower() == "microsoft.network/networkinterfaces":
                    for config in nic_data(nic_id):
                        if rid in {str(a).lower() for a in config.get("asgs") or []} and config.get("subnet"):
                            subnets.append(config["subnet"])
            attach(rid, subnets)
        elif rtype in ("Microsoft.App/containerApps", "Microsoft.App/jobs"):
            data = collect(["resource", "show", "--ids", rid],
                           "{environment:properties.environmentId,managedEnvironment:properties.managedEnvironmentId}", rid + " environment")
            environment = (data or {}).get("environment") or (data or {}).get("managedEnvironment")
            subnets = []
            if environment:
                environment = arm_id(environment, subscription)
                subnets = collect(["resource", "show", "--ids", environment],
                    "[properties.vnetConfiguration.infrastructureSubnetId]", environment + " subnet") or []
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

    for rid, subnets in nat_subnets.items():
        attach(rid, subnets + (resources.get(rid, {}).get("subnets") or []))

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
