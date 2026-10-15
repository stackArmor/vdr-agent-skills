"""Read-only service API discovery using the same asset envelope as Cloud Asset.

Failed queries contribute no records. Their exclusions remain explicit; a denied
or disabled API does not prove that its resources do not exist.
"""

import json
from urllib.parse import urlsplit


class ServiceQueries:
    def __init__(self, project, runner, warnings, results):
        self.project = project
        self.runner = runner
        self.warnings = warnings
        self.results = results

    def read(self, command, target=None):
        args = ["gcloud"] + command + ["--project", self.project, "--format", "json"]
        return self.read_args(args, target)

    def read_args(self, args, target=None):
        result = {"command": args, "target": target or self.project}
        try:
            output = self.runner(args)
            data = json.loads(output) if output else []
            if not isinstance(data, (list, dict)):
                raise ValueError("expected a JSON list or object")
        except (RuntimeError, OSError, ValueError) as exc:
            reason = " ".join(str(exc).split())
            lowered = reason.lower()
            disabled = any(marker in lowered for marker in (
                "service_disabled", "accessnotconfigured", "has not been used",
                "api is disabled", "api has been disabled", "it is disabled",
            ))
            result.update(status="service-disabled" if disabled else "unavailable",
                          reason=reason, recordCount=0)
            self.warnings.append(
                "%s for %s: %s; no resources included from this query. %s"
                % (" ".join(args[1:]), result["target"], result["status"], reason))
            data = []
        else:
            result.update(status="listed", recordCount=len(data) if isinstance(data, list) else 1)
        self.results.append(result)
        return data


def _last(value):
    return str(value or "").rsplit("/", 1)[-1]


def _location(data):
    name = data.get("name") or ""
    if "/locations/" in name:
        return name.split("/locations/", 1)[1].split("/", 1)[0]
    return (_last(data.get("zone")) or _last(data.get("region"))
            or data.get("location") or None)


def _uri(service, path):
    if path.startswith("//"):
        return path
    return "//%s/%s" % (service, path)


def _asset(kind, path, data, location=None):
    # Cloud SQL's inventory type and resource-name service differ.
    service = "cloudsql.googleapis.com" if kind == "sqladmin.googleapis.com/Instance" else kind.split("/", 1)[0]
    return {"assetType": kind, "name": _uri(service, path),
            "resource": {"location": location, "data": data}}


def service_assets(project, runner, warnings, results):
    query = ServiceQueries(project, runner, warnings, results)
    assets = []

    for command, kind, collection in (
        (["storage", "buckets", "list"], "storage.googleapis.com/Bucket", "buckets"),
        (["sql", "instances", "list"], "sqladmin.googleapis.com/Instance", "instances"),
        (["pubsub", "topics", "list"], "pubsub.googleapis.com/Topic", "topics"),
        (["pubsub", "subscriptions", "list"], "pubsub.googleapis.com/Subscription", "subscriptions"),
        (["functions", "list"], "cloudfunctions.googleapis.com/Function", "functions"),
        (["secrets", "list"], "secretmanager.googleapis.com/Secret", "secrets"),
        (["container", "fleet", "memberships", "list", "--location", "-"],
         "gkehub.googleapis.com/Membership", "memberships"),
    ):
        for data in query.read(command):
            path = str(data["name"])
            if kind == "storage.googleapis.com/Bucket":
                path = (path[5:] if path.startswith("gs://") else path).rstrip("/")
                # gcloud storage uses snake_case, unlike the provider API.
                data = dict(data, encryption={"defaultKmsKeyName": data.get("default_kms_key")}) if "default_kms_key" in data else data
            elif not path.startswith(("projects/", "//")):
                path = "projects/%s/%s/%s" % (project, collection, path)
            assets.append(_asset(kind, path, data, _location(data)))

    project_data = query.read(["projects", "describe", project])
    if isinstance(project_data, dict) and project_data:
        assets.append(_asset("cloudresourcemanager.googleapis.com/Project",
                             "projects/" + str(project_data.get("projectNumber") or project),
                             project_data, "global"))

    # Compute list commands aggregate their regional/zonal resources by default.
    for command, kind, collection in (
        (["instances"], "Instance", "instances"),
        (["networks"], "Network", "networks"),
        (["firewall-rules"], "Firewall", "firewalls"),
        (["networks", "subnets"], "Subnetwork", "subnetworks"),
        (["images"], "Image", "images"),
        (["target-http-proxies"], "TargetHttpProxy", "targetHttpProxies"),
        (["target-https-proxies"], "TargetHttpsProxy", "targetHttpsProxies"),
        (["target-ssl-proxies"], "TargetSslProxy", "targetSslProxies"),
        (["target-tcp-proxies"], "TargetTcpProxy", "targetTcpProxies"),
        (["target-grpc-proxies"], "TargetGrpcProxy", "targetGrpcProxies"),
    ):
        flags = ["--no-standard-images"] if kind == "Image" else []
        for data in query.read(["compute"] + command + ["list"] + flags):
            if data.get("selfLink"):
                path = urlsplit(data["selfLink"]).path.split("/projects/", 1)[-1]
                path = "projects/" + path
            else:
                scope = ("zones/" + _last(data["zone"]) if data.get("zone") else
                         "regions/" + _last(data["region"]) if data.get("region") else "global")
                path = "projects/%s/%s/%s/%s" % (project, scope, collection, data["name"])
            assets.append(_asset("compute.googleapis.com/" + kind, path, data, _location(data)))

    # bq follows all pages up to max_results; its default is only 50 datasets.
    datasets = query.read_args(["bq", "ls", "--project_id", project, "--format", "json",
                               "--max_results", "2147483647", "--all=true"])
    for data in datasets:
        name = (data.get("datasetReference") or {}).get("datasetId") or data.get("id", "").split(":")[-1]
        path = "projects/%s/datasets/%s" % (project, name)
        # Dataset listing omits IAM/access and some metadata. Show only metadata.
        details = query.read_args(["bq", "show", "--project_id", project, "--format", "json",
                                   "%s:%s" % (project, name)], path)
        data = details if isinstance(details, dict) else data
        assets.append(_asset("bigquery.googleapis.com/Dataset", path, data, data.get("location")))

    for collection, kind in (("services", "Service"), ("jobs", "Job")):
        # Omit --region deliberately: gcloud lists across all managed regions.
        for data in query.read(["run", collection, "list", "--platform", "managed"] if collection == "services"
                               else ["run", collection, "list"]):
            metadata = data.get("metadata") or {}
            name = metadata.get("name") or data.get("name") or ""
            location = (metadata.get("labels") or {}).get("cloud.googleapis.com/location") or _location(data)
            path = name if name.startswith("projects/") else "projects/%s/locations/%s/%s/%s" % (project, location, collection, name)
            assets.append(_asset("run.googleapis.com/" + kind, path, data, location))

    for cluster in query.read(["alloydb", "clusters", "list", "--region", "-"]):
        location = _location(cluster)
        assets.append(_asset("alloydb.googleapis.com/Cluster", cluster["name"], cluster, location))
        for instance in query.read(["alloydb", "instances", "list", "--region", location,
                                    "--cluster", _last(cluster["name"])], cluster["name"]):
            assets.append(_asset("alloydb.googleapis.com/Instance", instance["name"], instance, location))

    for cluster in query.read(["container", "clusters", "list"]):
        location = cluster.get("location") or _last(cluster.get("zone"))
        path = "projects/%s/locations/%s/clusters/%s" % (project, location, cluster["name"])
        assets.append(_asset("container.googleapis.com/Cluster", path, cluster, location))
        pools = cluster.get("nodePools")
        if pools is None:
            pools = query.read(["container", "node-pools", "list", "--cluster", cluster["name"],
                                "--location", location], path)
        for pool in pools:
            assets.append(_asset("container.googleapis.com/NodePool", path + "/nodePools/" + pool["name"], pool, location))

    policy = query.read(["container", "binauthz", "policy", "export"])
    if isinstance(policy, dict) and policy:
        assets.append(_asset("binaryauthorization.googleapis.com/Policy", "projects/%s/policy" % project, policy, "global"))

    # Global and regional Secret Manager resources have distinct list endpoints.
    for location in query.read(["secrets", "locations", "list"]):
        location_id = location.get("locationId") or _last(location.get("name"))
        if location_id == "global":
            continue
        for secret in query.read(["secrets", "list", "--location", location_id], location_id):
            assets.append(_asset("secretmanager.googleapis.com/Secret", secret["name"], secret, location_id))

    for location in query.read(["kms", "locations", "list"]):
        location_id = location.get("locationId") or _last(location.get("name"))
        for ring in query.read(["kms", "keyrings", "list", "--location", location_id], location_id):
            assets.append(_asset("cloudkms.googleapis.com/KeyRing", ring["name"], ring, location_id))
            for key in query.read(["kms", "keys", "list", "--location", location_id,
                                   "--keyring", _last(ring["name"])], ring["name"]):
                assets.append(_asset("cloudkms.googleapis.com/CryptoKey", key["name"], key, location_id))

    for account in query.read(["iam", "service-accounts", "list"]):
        path = "projects/%s/serviceAccounts/%s" % (project, account["uniqueId"])
        assets.append(_asset("iam.googleapis.com/ServiceAccount", path, account, "global"))
        for key in query.read(["iam", "service-accounts", "keys", "list", "--iam-account", account["email"]], path):
            assets.append(_asset("iam.googleapis.com/ServiceAccountKey", key["name"], key, "global"))
    for role in query.read(["iam", "roles", "list"]):
        details = query.read(["iam", "roles", "describe", _last(role["name"])], role["name"])
        assets.append(_asset("iam.googleapis.com/Role", role["name"], details if isinstance(details, dict) else role, "global"))

    for repository in query.read(["artifacts", "repositories", "list", "--location", "all"]):
        path = repository["name"]
        location = _location(repository)
        assets.append(_asset("artifactregistry.googleapis.com/Repository", path, repository, location))
        if repository.get("format") == "DOCKER":
            docker_path = "%s-docker.pkg.dev/%s/%s" % (location, project, _last(path))
            for image in query.read(["artifacts", "docker", "images", "list", docker_path], path):
                # gcloud's legacy view keeps the provider's exact image ID here.
                name = (image.get("metadata") or {}).get("name") or image.get("name")
                if not name:
                    warnings.append("Artifact image identity missing in %s; image excluded" % path)
                    continue
                assets.append(_asset("artifactregistry.googleapis.com/DockerImage", name, image, location))
    return assets


def service_policies(project, resources, runner, warnings, results):
    """Read attached policies on project and supported resource policy surfaces."""
    query = ServiceQueries(project, runner, warnings, results)
    project_resource = next((r for r in resources if r["type"] == "cloudresourcemanager.googleapis.com/Project"), None)
    project_uri = (project_resource or {}).get("providerUri") or "//cloudresourcemanager.googleapis.com/projects/" + project
    targets = [(project_uri, "cloudresourcemanager.googleapis.com/Project", ["projects", "get-iam-policy", project])]
    for resource in resources:
        kind = resource["type"]
        uri = resource.get("providerUri")
        if not uri:
            continue
        path = uri.split(".googleapis.com/", 1)[-1]
        name = _last(path)
        location = (resource.get("region") or
                    (path.split("/locations/", 1)[1].split("/", 1)[0] if "/locations/" in path else None))
        command = None
        if kind == "storage.googleapis.com/Bucket":
            command = ["storage", "buckets", "get-iam-policy", "gs://" + name]
        elif kind == "secretmanager.googleapis.com/Secret":
            command = ["secrets", "get-iam-policy", name]
            if "/locations/" in path:
                command += ["--location", path.split("/locations/", 1)[1].split("/", 1)[0]]
        elif kind in {"cloudkms.googleapis.com/KeyRing", "cloudkms.googleapis.com/CryptoKey"}:
            key = kind.endswith("CryptoKey")
            command = ["kms", "keys" if key else "keyrings", "get-iam-policy", name, "--location", location]
            if key:
                command += ["--keyring", path.split("/keyRings/", 1)[1].split("/", 1)[0]]
        elif kind == "iam.googleapis.com/ServiceAccount":
            command = ["iam", "service-accounts", "get-iam-policy", resource["identifier"]]
        elif kind.startswith("pubsub.googleapis.com/"):
            command = ["pubsub", "topics" if kind.endswith("Topic") else "subscriptions", "get-iam-policy", path]
        elif kind.startswith("run.googleapis.com/"):
            command = ["run", "services" if kind.endswith("Service") else "jobs", "get-iam-policy", name, "--region", location]
        elif kind in {"cloudfunctions.googleapis.com/Function", "cloudfunctions.googleapis.com/CloudFunction"}:
            command = ["functions", "get-iam-policy", name, "--region", location]
        elif kind == "artifactregistry.googleapis.com/Repository":
            command = ["artifacts", "repositories", "get-iam-policy", name, "--location", location]
        elif kind == "binaryauthorization.googleapis.com/Policy":
            command = ["container", "binauthz", "policy", "get-iam-policy"]
        elif kind in {"compute.googleapis.com/Instance", "compute.googleapis.com/Image", "compute.googleapis.com/Subnetwork"}:
            collection = {"Instance": ["instances"], "Image": ["images"], "Subnetwork": ["networks", "subnets"]}[kind.split("/")[1]]
            command = ["compute"] + collection + ["get-iam-policy", name]
            if "/zones/" in path:
                command += ["--zone", path.split("/zones/", 1)[1].split("/", 1)[0]]
            elif "/regions/" in path:
                command += ["--region", path.split("/regions/", 1)[1].split("/", 1)[0]]
        elif kind == "bigquery.googleapis.com/Dataset":
            command = ["bq", "get-iam-policy", "--project_id", project,
                       "--format", "json", "--dataset=true", "%s:%s" % (project, name)]
        if command:
            targets.append((uri, kind, command))
    policies = []
    for uri, kind, command in targets:
        policy = query.read_args(command, uri) if command[0] == "bq" else query.read(command, uri)
        if isinstance(policy, dict):
            policies.append({"name": uri, "assetType": kind, "iamPolicy": policy})
    return policies
