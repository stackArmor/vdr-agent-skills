#!/usr/bin/env python3
"""Read-only inventory of cluster workloads for vdr-fedramp ConfigMap generation.

Usage: list_workloads.py --context <reviewed-context>            (all namespaces)
       list_workloads.py --context <reviewed-context> -n <ns>    (single namespace)
Requires: kubectl (authenticated), python3 (>=3.8, stdlib only).

Emits one JSON document on stdout:
  - namespaces: name, cloudManaged flag, vdr.fedramp.io/* labels
  - workloads: namespace, kind, name, effective workload vdr.fedramp.io/*
    labels, images,
    service account, non-secret privilege/data-reference evidence, and a
    managedNamespaceHint (namespace alone does not decide ownership)
  - summary counts (total / effective workload-label presence / managed-
    namespace hint); namespace labels are reported separately as fallbacks

Only `kubectl get` and `kubectl config` are executed — never
exec/apply/label/patch/delete.
"""
import fnmatch
import json
import subprocess
import sys

# Namespace patterns that often contain provider-managed or shared-responsibility
# components. This is an ownership hint only: customer-installed components can
# live in these namespaces, and every confirmed workload still receives a
# central ConfigMap assignment rule.
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
SECURITY_IMPACT_PROFILE_LABEL = "vdr.fedramp.io/security-impact-profile"

# Controller kinds that own pods and can carry a security-impact-profile label. Standalone
# and custom-owned Jobs are included; Jobs whose controller owner is a CronJob
# are represented by that CronJob.
CONTROLLER_KINDS = ["deployments", "statefulsets", "daemonsets", "cronjobs"]

# Match the plugin collector: these pod owner kinds are already represented by
# a collected workload template. Pods owned by other controllers remain visible.
COLLECTED_POD_OWNER_KINDS = {"ReplicaSet", "StatefulSet", "DaemonSet", "Job"}


def parse_args(argv):
    ns_args = ["--all-namespaces"]
    scope = "all"
    context = None
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "-n":
            if i + 1 >= len(argv):
                sys.stderr.write("error: -n requires a namespace argument\n")
                sys.exit(2)
            ns_args, scope = ["-n", argv[i + 1]], argv[i + 1]
            i += 2
        elif arg == "--context":
            if i + 1 >= len(argv):
                sys.stderr.write("error: --context requires a context name\n")
                sys.exit(2)
            context = argv[i + 1]
            i += 2
        elif arg in ("-h", "--help"):
            sys.stderr.write(__doc__)
            sys.exit(0)
        else:
            sys.stderr.write(f"unknown arg: {arg}\n")
            sys.exit(2)
    if not context:
        sys.stderr.write("error: --context <reviewed-context> is required\n")
        sys.exit(2)
    return ns_args, scope, context


def kubectl(args, context=None):
    """Run kubectl and return CompletedProcess; never raises on non-zero exit."""
    command = ["kubectl"]
    if context:
        command.extend(["--context", context])
    command.extend(args)
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def preflight(context):
    """Fail loudly if kubectl can't reach the cluster."""
    res = kubectl(["get", "--raw=/version"], context)
    if res.returncode != 0:
        sys.stderr.write("ERROR: kubectl cannot reach the cluster.\n")
        sys.stderr.write("  Check the reviewed context name and authentication.\n")
        sys.exit(1)


def get_json(args, context):
    """Run a required kubectl get and return a list; never hide partial inventory."""
    res = kubectl(["get", *args, "-o", "json"], context)
    request = " ".join(args)
    if res.returncode != 0:
        sys.stderr.write(f"ERROR: kubectl get {request} failed; inventory is incomplete.\n")
        sys.exit(1)
    if not res.stdout.strip():
        sys.stderr.write(f"ERROR: kubectl get {request} returned no JSON.\n")
        sys.exit(1)
    try:
        doc = json.loads(res.stdout, strict=False)
    except json.JSONDecodeError:
        sys.stderr.write(f"ERROR: kubectl get {request} returned malformed JSON.\n")
        sys.exit(1)
    if isinstance(doc, dict) and isinstance(doc.get("items"), list):
        return doc["items"]
    if isinstance(doc, dict) and doc.get("kind"):
        return [doc]
    sys.stderr.write(f"ERROR: kubectl get {request} returned an unexpected document.\n")
    sys.exit(1)


def is_cloud_managed(namespace):
    return any(fnmatch.fnmatch(namespace, p) for p in CLOUD_MANAGED_NS_PATTERNS)


def vdr_labels(meta):
    labels = meta.get("labels") or {}
    return dict(sorted(
        (k, v) for k, v in labels.items() if k.startswith(VDR_LABEL_PREFIX)
    ))


def pod_template_meta_of(kind, item):
    """Return pod-template metadata, or an empty mapping when none exists."""
    spec = item.get("spec") or {}
    if kind == "CronJob":
        return (((spec.get("jobTemplate") or {}).get("spec") or {})
                .get("template") or {}).get("metadata") or {}
    if kind == "Pod":
        return {}
    return (spec.get("template") or {}).get("metadata") or {}


def effective_vdr_labels(kind, item):
    """Match plugin semantics: pod-template labels win over object labels."""
    object_labels = vdr_labels(item.get("metadata") or {})
    template_labels = vdr_labels(pod_template_meta_of(kind, item))
    effective = dict(object_labels)
    effective.update(template_labels)
    return object_labels, template_labels, dict(sorted(effective.items()))


def controller_owner(meta):
    for owner in meta.get("ownerReferences") or []:
        if owner.get("controller") is True:
            return {
                "apiVersion": owner.get("apiVersion", ""),
                "kind": owner.get("kind", ""),
                "name": owner.get("name", ""),
                "uid": owner.get("uid", ""),
            }
    return None


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
    for field in ("initContainers", "containers", "ephemeralContainers"):
        for c in pod_spec.get(field) or []:
            img = c.get("image")
            if img and img not in images:
                images.append(img)
    return sorted(images)


def append_unique(values, value):
    if value and value not in values:
        values.append(value)


def workload_evidence(kind, item):
    """Extract names and privilege indicators only; never resolve referenced data."""
    pod_spec = pod_spec_of(kind, item)
    secrets = []
    config_maps = []
    pvcs = []
    host_paths = []
    capabilities = []
    privileged_containers = []
    host_process_containers = []
    ports = []
    block_devices = []

    volumes = pod_spec.get("volumes") or []
    host_path_volumes = {}
    for volume in volumes:
        volume_name = volume.get("name", "")
        secret = volume.get("secret") or {}
        config_map = volume.get("configMap") or {}
        pvc = volume.get("persistentVolumeClaim") or {}
        host_path = volume.get("hostPath") or {}
        append_unique(secrets, secret.get("secretName"))
        append_unique(config_maps, config_map.get("name"))
        append_unique(pvcs, pvc.get("claimName"))
        if host_path.get("path"):
            append_unique(host_paths, host_path.get("path"))
            host_path_volumes[volume_name] = host_path.get("path")
        for source in (volume.get("projected") or {}).get("sources") or []:
            append_unique(secrets, (source.get("secret") or {}).get("name"))
            append_unique(config_maps, (source.get("configMap") or {}).get("name"))
        secret_paths = [
            ("azureFile", "secretName"),
            ("cephfs", "secretRef", "name"),
            ("cinder", "secretRef", "name"),
            ("csi", "nodePublishSecretRef", "name"),
            ("flexVolume", "secretRef", "name"),
            ("iscsi", "secretRef", "name"),
            ("rbd", "secretRef", "name"),
            ("scaleIO", "secretRef", "name"),
            ("storageos", "secretRef", "name"),
        ]
        for path in secret_paths:
            value = volume
            for part in path:
                value = value.get(part) if isinstance(value, dict) else None
            append_unique(secrets, value)
    for image_pull_secret in pod_spec.get("imagePullSecrets") or []:
        append_unique(secrets, image_pull_secret.get("name"))

    host_path_mounts = []
    for field in ("initContainers", "containers", "ephemeralContainers"):
        for container in pod_spec.get(field) or []:
            name = container.get("name", "")
            security = container.get("securityContext") or {}
            if security.get("privileged") is True:
                append_unique(privileged_containers, name)
            if (security.get("windowsOptions") or {}).get("hostProcess") is True:
                append_unique(host_process_containers, name)
            for capability in (security.get("capabilities") or {}).get("add") or []:
                append_unique(capabilities, capability)
            for env in container.get("env") or []:
                value_from = env.get("valueFrom") or {}
                append_unique(secrets, (value_from.get("secretKeyRef") or {}).get("name"))
                append_unique(config_maps, (value_from.get("configMapKeyRef") or {}).get("name"))
            for env_from in container.get("envFrom") or []:
                append_unique(secrets, (env_from.get("secretRef") or {}).get("name"))
                append_unique(config_maps, (env_from.get("configMapRef") or {}).get("name"))
            for port in container.get("ports") or []:
                value = port.get("containerPort")
                if value is not None:
                    append_unique(ports, value)
            for mount in container.get("volumeMounts") or []:
                host_path = host_path_volumes.get(mount.get("name"))
                if host_path:
                    descriptor = {
                        "container": name,
                        "hostPath": host_path,
                        "mountPath": mount.get("mountPath", ""),
                        "readOnly": bool(mount.get("readOnly", False)),
                        "mountPropagation": mount.get("mountPropagation", ""),
                    }
                    if descriptor not in host_path_mounts:
                        host_path_mounts.append(descriptor)
            for device in container.get("volumeDevices") or []:
                descriptor = {
                    "container": name,
                    "name": device.get("name", ""),
                    "devicePath": device.get("devicePath", ""),
                }
                if descriptor not in block_devices:
                    block_devices.append(descriptor)

    host_path_mounts.sort(key=lambda d: (
        d["container"], d["hostPath"], d["mountPath"], d["readOnly"]
    ))
    block_devices.sort(key=lambda d: (d["container"], d["name"], d["devicePath"]))

    return {
        "serviceAccount": pod_spec.get("serviceAccountName", "default"),
        "automountServiceAccountToken": pod_spec.get("automountServiceAccountToken"),
        "hostNetwork": bool(pod_spec.get("hostNetwork", False)),
        "hostPID": bool(pod_spec.get("hostPID", False)),
        "hostIPC": bool(pod_spec.get("hostIPC", False)),
        "hostProcess": bool(
            ((pod_spec.get("securityContext") or {}).get("windowsOptions") or {})
            .get("hostProcess", False)
        ),
        "privilegedContainers": sorted(privileged_containers),
        "hostProcessContainers": sorted(host_process_containers),
        "addedCapabilities": sorted(capabilities),
        "hostPaths": sorted(host_paths),
        "hostPathMounts": host_path_mounts,
        "blockDevices": block_devices,
        "secretRefs": sorted(secrets),
        "configMapRefs": sorted(config_maps),
        "pvcRefs": sorted(pvcs),
        "containerPorts": sorted(ports),
        "nodeSelector": dict(sorted((pod_spec.get("nodeSelector") or {}).items())),
    }


def workload_entry(kind, item):
    meta = item.get("metadata") or {}
    ns = meta.get("namespace", "")
    object_labels, template_labels, labels = effective_vdr_labels(kind, item)
    managed_hint = is_cloud_managed(ns)
    profile = labels.get(SECURITY_IMPACT_PROFILE_LABEL)
    return {
        "namespace": ns,
        "kind": kind,
        "name": meta.get("name", ""),
        "securityImpactProfile": profile,
        "vdrLabels": labels,
        "workloadObjectVdrLabels": object_labels,
        "podTemplateVdrLabels": template_labels,
        "images": images_of(kind, item),
        "controllerOwner": controller_owner(meta),
        "managedNamespaceHint": managed_hint,
        # Retained for consumers of the v0.1 inventory schema. Treat as a hint.
        "cloudManagedNamespace": managed_hint,
        "evidence": workload_evidence(kind, item),
    }


def collect_workloads(ns_args, context):
    workloads = []
    for kind_plural in CONTROLLER_KINDS:
        for item in get_json([kind_plural, *ns_args], context):
            workloads.append(workload_entry(item.get("kind", kind_plural), item))

    for item in get_json(["jobs", *ns_args], context):
        meta = item.get("metadata") or {}
        owner = controller_owner(meta)
        # Match plugin behavior: every controller-owned CronJob execution is
        # represented by the CronJob template, even if its owner is now absent.
        if owner and owner["kind"] == "CronJob":
            continue
        workloads.append(workload_entry(item.get("kind", "Job"), item))

    for item in get_json(["pods", *ns_args], context):
        meta = item.get("metadata") or {}
        owner = controller_owner(meta)
        if owner and owner["kind"] in COLLECTED_POD_OWNER_KINDS:
            continue
        workloads.append(workload_entry(item.get("kind", "Pod"), item))
    workloads.sort(key=lambda w: (w["namespace"], w["kind"], w["name"]))
    return workloads


def collect_namespaces(scope, context):
    entries = []
    args = ["namespaces"] if scope == "all" else ["namespace", scope]
    for item in get_json(args, context):
        meta = item.get("metadata") or {}
        name = meta.get("name", "")
        if scope != "all" and name != scope:
            continue
        entries.append({
            "name": name,
            "managedNamespaceHint": is_cloud_managed(name),
            # Retained for consumers of the v0.1 inventory schema.
            "cloudManaged": is_cloud_managed(name),
            "vdrLabels": vdr_labels(meta),
        })
    entries.sort(key=lambda entry: entry["name"])
    return entries


def main():
    ns_args, scope, context = parse_args(sys.argv[1:])
    preflight(context)
    namespaces = collect_namespaces(scope, context)
    workloads = collect_workloads(ns_args, context)

    labeled = sum(
        1 for w in workloads if SECURITY_IMPACT_PROFILE_LABEL in w["vdrLabels"]
    )
    object_labeled = sum(
        1 for w in workloads
        if SECURITY_IMPACT_PROFILE_LABEL in w["workloadObjectVdrLabels"]
    )
    template_labeled = sum(
        1 for w in workloads
        if SECURITY_IMPACT_PROFILE_LABEL in w["podTemplateVdrLabels"]
    )
    managed = sum(1 for w in workloads if w["managedNamespaceHint"])
    doc = {
        "context": context,
        "scope": scope,
        "namespaces": namespaces,
        "workloads": workloads,
        "summary": {
            "workloads": len(workloads),
            "withEffectiveWorkloadSecurityImpactProfileLabel": labeled,
            "withoutEffectiveWorkloadSecurityImpactProfileLabel": len(workloads) - labeled,
            "withWorkloadObjectSecurityImpactProfileLabel": object_labeled,
            "withPodTemplateSecurityImpactProfileLabel": template_labeled,
            "alreadyLabeled": labeled,
            "needingAttestation": len(workloads) - labeled,
            "inManagedNamespacePatterns": managed,
            # Retained for consumers of the v0.1 inventory schema.
            "inCloudManagedNamespaces": managed,
        },
    }
    json.dump(doc, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
