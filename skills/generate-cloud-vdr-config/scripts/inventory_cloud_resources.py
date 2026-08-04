#!/usr/bin/env python3
"""Inventory cloud resources and annotate them for VDR config generation.

Read-only discovery only: this script never invokes a mutating cloud verb, and
it never captures secret-bearing fields (instance user-data/metadata blobs).
Standard library only (Python >= 3.8).
"""

import argparse
import fnmatch
import json
import subprocess
import sys
from pathlib import Path

GCP_ASSET_TYPES = [
    "storage.googleapis.com/Bucket",
    "compute.googleapis.com/Instance",
    "sqladmin.googleapis.com/Instance",
    "bigquery.googleapis.com/Dataset",
]

GCP_KEY_ALIASES = {
    "vdr_fedramp_io_security_impact_profile": "vdr.fedramp.io/security-impact-profile",
    "vdr_fedramp_io_class": "vdr.fedramp.io/class",
    "vdr_fedramp_io_multi_agency": "vdr.fedramp.io/multi-agency",
}


def run_command(args):
    """Run a read-only CLI command and return stdout; raise on nonzero exit."""
    proc = subprocess.run(args, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError("command failed: %s\n%s" % (" ".join(args), proc.stderr))
    return proc.stdout


def load_patterns(path):
    with open(path) as handle:
        return json.load(handle)


def match_patterns(resource, patterns):
    matched = []
    for entry in patterns:
        if entry["type"] not in ("*", resource["type"]):
            continue
        name_hit = any(fnmatch.fnmatchcase(resource["identifier"], glob)
                       for glob in entry["nameGlobs"])
        marker = entry["markerTags"]
        tag_hit = bool(marker) and all(
            key in resource.get("tags", {}) and
            fnmatch.fnmatchcase(str(resource["tags"][key]), str(value))
            for key, value in marker.items())
        if name_hit or tag_hit:
            matched.append(entry["id"])
    return sorted(matched)


def decode_vdr_tags(provider, tags):
    decoded = {}
    if provider == "gcp":
        for raw_key, canonical in GCP_KEY_ALIASES.items():
            if raw_key not in tags:
                continue
            value = tags[raw_key]
            if canonical.endswith("security-impact-profile") and "__" in value:
                value = value.replace("__", ".")
            if canonical.endswith("/class"):
                value = value.upper()
            decoded[canonical] = value
    else:
        for key, value in tags.items():
            if key.startswith("vdr.fedramp.io/"):
                decoded[key] = value
    return decoded


def summarize_tags(resources):
    """Roll raw provider tags/labels across resources into count/value histograms.

    Summarizes the operator's existing tag vocabulary (env, data-class, owner,
    ...) so downstream tagRule proposals can key off coherent taxonomies. VDR
    override provenance lives in vdrTags and is reported separately.
    """
    summary = {}
    for resource in resources:
        for key, value in resource.get("tags", {}).items():
            entry = summary.setdefault(key, {"count": 0, "values": {}})
            entry["count"] += 1
            entry["values"][value] = entry["values"].get(value, 0) + 1
    return summary


def _load_json(output):
    if isinstance(output, str):
        output = output.strip()
    return json.loads(output) if output else []


def _last_segment(value):
    return value.rsplit("/", 1)[-1] if value else value


def _build_resource(rtype, identifier, region, tags, network, subnet,
                    provider_patterns):
    resource = {
        "type": rtype,
        "identifier": identifier,
        "region": region,
        "network": network,
        "subnet": subnet,
        "tags": tags,
    }
    resource["vdrTags"] = decode_vdr_tags("gcp", tags)
    resource["builtinPatterns"] = match_patterns(resource, provider_patterns)
    return resource


def _gcp_caller_identity(runner):
    output = runner(["gcloud", "auth", "list", "--filter=status:ACTIVE",
                     "--format", "json"])
    accounts = _load_json(output)
    if accounts:
        return accounts[0].get("account")
    return None


def _map_asset(asset, provider_patterns):
    asset_type = asset.get("assetType")
    identifier = _last_segment(asset.get("name", ""))
    resource_block = asset.get("resource") or {}
    data = resource_block.get("data") or {}
    region = resource_block.get("location")

    network = None
    subnet = None
    if asset_type == "sqladmin.googleapis.com/Instance":
        settings = data.get("settings") or {}
        tags = settings.get("userLabels") or {}
        private_network = (settings.get("ipConfiguration") or {}).get("privateNetwork")
        if private_network:
            network = _last_segment(private_network)
    else:
        tags = data.get("labels") or {}
        nics = data.get("networkInterfaces") or []
        if nics:
            nic = nics[0]
            if nic.get("network"):
                network = _last_segment(nic["network"])
            if nic.get("subnetwork"):
                subnet = _last_segment(nic["subnetwork"])

    return _build_resource(asset_type, identifier, region, tags, network,
                           subnet, provider_patterns)


def _gcp_asset_inventory(project, runner, provider_patterns):
    output = runner(["gcloud", "asset", "list", "--project", project,
                     "--asset-types", ",".join(GCP_ASSET_TYPES),
                     "--content-type", "resource", "--format", "json"])
    return [_map_asset(asset, provider_patterns) for asset in _load_json(output)]


def _gcp_service_inventory(project, runner, provider_patterns, warnings):
    resources = []

    buckets = _load_json(runner(["gcloud", "storage", "buckets", "list",
                                 "--project", project, "--format", "json"]))
    for bucket in buckets:
        resources.append(_build_resource(
            "storage.googleapis.com/Bucket", bucket.get("name"),
            bucket.get("location"), bucket.get("labels") or {}, None, None,
            provider_patterns))

    instances = _load_json(runner(["gcloud", "sql", "instances", "list",
                                   "--project", project, "--format", "json"]))
    for instance in instances:
        settings = instance.get("settings") or {}
        tags = settings.get("userLabels") or {}
        private_network = (settings.get("ipConfiguration") or {}).get("privateNetwork")
        network = _last_segment(private_network) if private_network else None
        resources.append(_build_resource(
            "sqladmin.googleapis.com/Instance", instance.get("name"),
            instance.get("region"), tags, network, None, provider_patterns))

    computes = _load_json(runner(["gcloud", "compute", "instances", "list",
                                  "--project", project, "--format", "json"]))
    for compute in computes:
        zone = _last_segment(compute.get("zone") or "")
        region = zone.rsplit("-", 1)[0] if zone else None
        nics = compute.get("networkInterfaces") or []
        network = None
        subnet = None
        if nics:
            if nics[0].get("network"):
                network = _last_segment(nics[0]["network"])
            if nics[0].get("subnetwork"):
                subnet = _last_segment(nics[0]["subnetwork"])
        # Copy only name/zone/labels/networkInterfaces; never metadata blobs.
        resources.append(_build_resource(
            "compute.googleapis.com/Instance", compute.get("name"), region,
            compute.get("labels") or {}, network, subnet, provider_patterns))

    try:
        datasets = _load_json(runner(["bq", "ls", "--project_id", project,
                                      "--format", "json"]))
    except RuntimeError as exc:
        first_line = str(exc).splitlines()[0] if str(exc) else ""
        warnings.append(
            "BigQuery datasets were not enumerated for project %s: %s"
            % (project, first_line))
    else:
        for dataset in datasets:
            identifier = (dataset.get("id")
                          or (dataset.get("datasetReference") or {}).get("datasetId"))
            resources.append(_build_resource(
                "bigquery.googleapis.com/Dataset", identifier,
                dataset.get("location"), dataset.get("labels") or {}, None, None,
                provider_patterns))

    return resources


def _asset_fallback_warning(project, error_line):
    message = ("Cloud Asset API was not used for project %s; the per-service "
               "fallback covers buckets, SQL, compute, and BigQuery only."
               % project)
    if error_line:
        message += " Cloud Asset API error: %s" % error_line
    return message


def inventory_gcp(project, patterns, runner=run_command, use_asset_api=True):
    provider_patterns = [p for p in patterns if p.get("provider") == "gcp"]
    warnings = []
    caller_identity = _gcp_caller_identity(runner)

    resources = []
    inventory_source = None
    asset_error_line = None
    if use_asset_api:
        try:
            resources = _gcp_asset_inventory(project, runner, provider_patterns)
            inventory_source = "asset-api"
        except RuntimeError as exc:
            asset_error_line = str(exc).splitlines()[0] if str(exc) else ""

    if inventory_source is None:
        resources = _gcp_service_inventory(project, runner, provider_patterns,
                                           warnings)
        inventory_source = "per-service-fallback"
        warnings.insert(0, _asset_fallback_warning(project, asset_error_line))

    provenance = {
        "inventorySource": inventory_source,
        "callerIdentity": caller_identity,
        "profile": None,
        "resolvedScope": project,
    }

    return {
        "provider": "gcp",
        "project": project,
        "provenance": provenance,
        "resources": resources,
        "tagSummary": summarize_tags(resources),
        "warnings": warnings,
    }


def merge_scopes(scope_docs):
    resource_count = 0
    by_type = {}
    for scope in scope_docs:
        for resource in scope.get("resources", []):
            resource_count += 1
            rtype = resource.get("type")
            by_type[rtype] = by_type.get(rtype, 0) + 1
    return {
        "scopes": scope_docs,
        "summary": {
            "scopeCount": len(scope_docs),
            "resourceCount": resource_count,
            "byType": by_type,
        },
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Inventory cloud resources and annotate them for VDR "
                    "config generation.")
    parser.add_argument("--provider", choices=["gcp", "aws"])
    parser.add_argument("--project")
    parser.add_argument("--profile")
    parser.add_argument("--region", action="append")
    parser.add_argument("--no-asset-api", action="store_true")
    default_patterns = (Path(__file__).parent.parent / "references"
                        / "managed-resource-patterns.json")
    parser.add_argument("--patterns", default=str(default_patterns))
    parser.add_argument("--merge", nargs="+")
    parser.add_argument("--output")
    args = parser.parse_args(argv)

    if args.merge:
        scope_docs = []
        for path in args.merge:
            with open(path) as handle:
                scope_docs.append(json.load(handle))
        document = merge_scopes(scope_docs)
    else:
        if not args.provider:
            parser.error("--provider is required unless --merge is given")
        if args.provider == "aws":
            parser.error("AWS inventory is not yet supported; use --provider gcp")
        if not args.project:
            parser.error("--project is required for --provider gcp")
        patterns = load_patterns(Path(args.patterns))
        document = inventory_gcp(args.project, patterns,
                                 use_asset_api=not args.no_asset_api)

    rendered = json.dumps(document, indent=2)
    if args.output:
        with open(args.output, "w") as handle:
            handle.write(rendered + "\n")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RuntimeError as exc:
        sys.stderr.write("error: %s\n" % exc)
        sys.exit(1)
