#!/usr/bin/env python3
"""Read-only inventory of cluster workloads for vdr-fedramp ConfigMap generation.

Usage: list_workloads.py            (all namespaces)
       list_workloads.py -n <ns>    (single namespace)
Requires: kubectl (authenticated), python3 (>=3.8, stdlib only).

Emits one JSON document on stdout:
  - namespaces: name, cloudManaged flag, vdr.fedramp.io/* labels
  - workloads: namespace, kind, name, vdr.fedramp.io/* labels, images,
    cloudManagedNamespace flag
  - summary counts (total / already labeled / needing attestation / cloud-managed)

Only `kubectl get` is executed — never exec/apply/label/patch/delete.
"""
import fnmatch
import json
import subprocess
import sys

# Namespaces owned by the cloud provider or cluster tooling under shared
# responsibility. Workloads here usually cannot carry customer labels and are
# classified by nameRules/namespaceRules in the ConfigMap instead.
CLOUD_MANAGED_NS_PATTERNS = [
    "kube-system",
    "kube-public",
    "kube-node-lease",
    "gke-managed-*",
    "gke-gmp-system",
    "gmp-system",
    "gmp-public",
    "gatekeeper-system",
    "calico-system",
    "tigera-operator",
    "amazon-cloudwatch",
    "amazon-guardduty",
    "aws-observability",
    "azure-*",
    "aks-*",
]

VDR_LABEL_PREFIX = "vdr.fedramp.io/"
ARCHETYPE_LABEL = "vdr.fedramp.io/asset-archetype"

# Controller kinds that own pods and can carry the archetype label. Bare Pods
# and Jobs are included only when ownerless (otherwise the controller is the
# thing to label).
CONTROLLER_KINDS = ["deployments", "statefulsets", "daemonsets", "cronjobs"]
OWNERLESS_KINDS = ["jobs", "pods"]


def parse_args(argv):
    ns_args = ["--all-namespaces"]
    scope = "all"
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "-n":
            if i + 1 >= len(argv):
                sys.stderr.write("error: -n requires a namespace argument\n")
                sys.exit(2)
            ns_args, scope = ["-n", argv[i + 1]], argv[i + 1]
            i += 2
        elif arg in ("-h", "--help"):
            sys.stderr.write(__doc__)
            sys.exit(0)
        else:
            sys.stderr.write(f"unknown arg: {arg}\n")
            sys.exit(2)
    return ns_args, scope


def kubectl(args):
    """Run kubectl and return CompletedProcess; never raises on non-zero exit."""
    return subprocess.run(
        ["kubectl", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def preflight():
    """Fail loudly if kubectl can't reach the cluster."""
    res = kubectl(["get", "--raw=/version"])
    if res.returncode != 0:
        sys.stderr.write("ERROR: kubectl cannot reach the cluster.\n")
        sys.stderr.write("  Check 'kubectl config current-context' and authentication.\n")
        sys.exit(1)


def get_json(args):
    """kubectl get ... -o json -> parsed items list ([] if kind absent/forbidden)."""
    res = kubectl(["get", *args, "-o", "json"])
    if res.returncode != 0 or not res.stdout.strip():
        return []
    try:
        doc = json.loads(res.stdout, strict=False)
    except json.JSONDecodeError:
        return []
    return doc.get("items", [])


def is_cloud_managed(namespace):
    return any(fnmatch.fnmatch(namespace, p) for p in CLOUD_MANAGED_NS_PATTERNS)


def vdr_labels(meta):
    labels = meta.get("labels") or {}
    return {k: v for k, v in labels.items() if k.startswith(VDR_LABEL_PREFIX)}


def pod_spec_of(kind, item):
    spec = item.get("spec") or {}
    if kind == "CronJob":
        return (((spec.get("jobTemplate") or {}).get("spec") or {})
                .get("template") or {}).get("spec") or {}
    if kind == "Pod":
        return spec
    return (spec.get("template") or {}).get("spec") or {}


def images_of(kind, item):
    pod_spec = pod_spec_of(kind, item)
    images = []
    for field in ("initContainers", "containers"):
        for c in pod_spec.get(field) or []:
            img = c.get("image")
            if img and img not in images:
                images.append(img)
    return images


def workload_entry(kind, item):
    meta = item.get("metadata") or {}
    ns = meta.get("namespace", "")
    labels = vdr_labels(meta)
    return {
        "namespace": ns,
        "kind": kind,
        "name": meta.get("name", ""),
        "archetype": labels.get(ARCHETYPE_LABEL),
        "vdrLabels": labels,
        "images": images_of(kind, item),
        "cloudManagedNamespace": is_cloud_managed(ns),
    }


def collect_workloads(ns_args):
    workloads = []
    for kind_plural in CONTROLLER_KINDS:
        for item in get_json([kind_plural, *ns_args]):
            workloads.append(workload_entry(item.get("kind", kind_plural), item))
    for kind_plural in OWNERLESS_KINDS:
        for item in get_json([kind_plural, *ns_args]):
            meta = item.get("metadata") or {}
            if meta.get("ownerReferences"):
                continue
            workloads.append(workload_entry(item.get("kind", kind_plural), item))
    workloads.sort(key=lambda w: (w["namespace"], w["kind"], w["name"]))
    return workloads


def collect_namespaces(scope):
    entries = []
    for item in get_json(["namespaces"]):
        meta = item.get("metadata") or {}
        name = meta.get("name", "")
        if scope != "all" and name != scope:
            continue
        entries.append({
            "name": name,
            "cloudManaged": is_cloud_managed(name),
            "vdrLabels": vdr_labels(meta),
        })
    return entries


def main():
    ns_args, scope = parse_args(sys.argv[1:])
    preflight()

    ctx = kubectl(["config", "current-context"]).stdout.strip()
    namespaces = collect_namespaces(scope)
    workloads = collect_workloads(ns_args)

    labeled = sum(1 for w in workloads if w["archetype"])
    managed = sum(1 for w in workloads if w["cloudManagedNamespace"])
    doc = {
        "context": ctx,
        "scope": scope,
        "namespaces": namespaces,
        "workloads": workloads,
        "summary": {
            "workloads": len(workloads),
            "alreadyLabeled": labeled,
            "needingAttestation": len(workloads) - labeled,
            "inCloudManagedNamespaces": managed,
        },
    }
    json.dump(doc, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
