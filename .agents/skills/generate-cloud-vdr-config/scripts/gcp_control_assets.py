"""Read-only GCP control-asset identifiers and metadata allowlists.

Kept byte-identical in the VDR skill and TSW; no credentials/payload extraction.
IAM allow bindings are synthetic, NOT IAM v3 PolicyBinding resources.
"""

import hashlib
import json

BINDING_TYPE = "vdr.fedramp.io/IAMBinding"
CONTROL_TYPES = {
    "compute.googleapis.com/Image": "compute.image",
    "artifactregistry.googleapis.com/Repository": "artifact.repository",
    "artifactregistry.googleapis.com/DockerImage": "artifact.container_image",
    "cloudfunctions.googleapis.com/Function": "cloud_function.function",
    "bigquery.googleapis.com/Dataset": "bigquery.dataset",
    "secretmanager.googleapis.com/Secret": "secret.secret",
    "cloudkms.googleapis.com/CryptoKey": "kms.crypto_key",
    "cloudkms.googleapis.com/KeyRing": "kms.key_ring",
    "iam.googleapis.com/ServiceAccount": "iam.service_account",
    "iam.googleapis.com/ServiceAccountKey": "iam.service_account_key",
    "iam.googleapis.com/Role": "iam.role",
    "cloudresourcemanager.googleapis.com/Project": "resource_manager.project",
    BINDING_TYPE: "iam.binding",
}


def service_account_owner(identifier):
    """Return exact (project, principal ID/email) from an IAM account/key path."""
    value = str(identifier or "")
    if value.startswith("//"):
        if not value.startswith("//iam.googleapis.com/"):
            return None
        value = value[len("//iam.googleapis.com/") :]
    parts = value.split("/")
    if len(parts) not in (4, 6) or parts[0] != "projects" or parts[2] != "serviceAccounts":
        return None
    if not parts[1] or not parts[3] or (len(parts) == 6 and (parts[4] != "keys" or not parts[5])):
        return None
    return parts[1], parts[3]


def service_account_parents(identifier, resources, project_ids):
    """Exact, scope-local parent candidates. Never join on a short SA name."""
    owner = service_account_owner(identifier)
    key_path = str(identifier or "").split(".googleapis.com/", 1)[-1]
    allowed = {str(value) for value in project_ids if value}
    if owner is None or owner[0] not in allowed or len(key_path.split("/")) != 6:
        return []
    matches = []
    for resource in resources:
        if resource.get("type") != "iam.googleapis.com/ServiceAccount":
            continue
        metadata = resource.get("metadata") or {}
        uri_owner = service_account_owner(resource.get("providerUri"))
        if uri_owner is not None and uri_owner[0] not in allowed:
            continue
        identifiers = {
            str(resource.get("identifier") or ""),
            str(metadata.get("uniqueId") or ""),
            str(metadata.get("email") or ""),
        }
        if uri_owner:
            identifiers.add(uri_owner[1])
        if owner[1] in identifiers:
            matches.append(resource)
    return matches


def kms_key_ring_parents(identifier, resources, project_ids):
    """Match the exact ring path within verified project ID/number aliases."""

    def path(value):
        value = str(value or "")
        if value.startswith("//"):
            prefix = "//cloudkms.googleapis.com/"
            if not value.startswith(prefix):
                return None
            value = value[len(prefix) :]
        parts = value.split("/")
        if (
            len(parts) not in (6, 8)
            or parts[0] != "projects"
            or parts[2] != "locations"
            or parts[4] != "keyRings"
            or not all(parts)
            or (len(parts) == 8 and parts[6] != "cryptoKeys")
        ):
            return None
        return parts

    allowed = {str(value) for value in project_ids if value}
    key = path(identifier)
    if key is None or len(key) != 8 or key[1] not in allowed:
        return []
    matches = []
    for resource in resources:
        if resource.get("type") != "cloudkms.googleapis.com/KeyRing":
            continue
        ring = path(resource.get("providerUri") or resource.get("identifier"))
        if ring and len(ring) == 6 and ring[1] in allowed and ring[2:] == key[2:6]:
            matches.append(resource)
    return matches


def primary_identifier(asset, project_id):
    """Stable scoring name; KMS/key paths prevent short-name collisions."""
    kind = asset["assetType"]
    full_name = str(asset.get("name") or "")
    data = (asset.get("resource") or {}).get("data") or {}
    if kind == BINDING_TYPE:
        return str(data["name"])
    if kind == "cloudresourcemanager.googleapis.com/Project":
        return str(data.get("projectId") or project_id)
    if kind == "iam.googleapis.com/ServiceAccount":
        email = data.get("email")
        if not email:
            raise ValueError("service account email is missing")
        return str(email)
    if kind in {
        "artifactregistry.googleapis.com/Repository",
        "artifactregistry.googleapis.com/DockerImage",
        "cloudkms.googleapis.com/CryptoKey",
        "cloudkms.googleapis.com/KeyRing",
        "iam.googleapis.com/ServiceAccountKey",
        "iam.googleapis.com/Role",
    }:
        return full_name.split(".googleapis.com/", 1)[-1]
    return full_name.rstrip("/").rsplit("/", 1)[-1]


def safe_metadata(asset):
    """Never propagate provider data wholesale, even if currently innocuous."""
    kind = asset["assetType"]
    data = (asset.get("resource") or {}).get("data") or {}
    result = {"provider_asset_type": kind}
    fields = {
        "artifactregistry.googleapis.com/Repository": ("kmsKeyName", "format", "mode"),
        "secretmanager.googleapis.com/Secret": ("expireTime",),
        "cloudkms.googleapis.com/CryptoKey": ("purpose", "rotationPeriod", "nextRotationTime"),
        "iam.googleapis.com/ServiceAccount": ("email", "uniqueId", "disabled"),
        "iam.googleapis.com/ServiceAccountKey": (
            "keyType",
            "keyOrigin",
            "keyAlgorithm",
            "validAfterTime",
            "validBeforeTime",
            "disabled",
        ),
        "iam.googleapis.com/Role": ("stage", "deleted", "includedPermissions"),
        "cloudresourcemanager.googleapis.com/Project": ("projectId", "projectNumber", "lifecycleState"),
    }
    for key in fields.get(kind, ()):
        if key in data:
            result[key] = data[key]
    if kind == "cloudkms.googleapis.com/CryptoKey":
        primary = data.get("primary") or {}
        result["primary"] = {key: primary[key] for key in ("name", "state", "protectionLevel") if key in primary}
    if kind == "secretmanager.googleapis.com/Secret":
        replication = data.get("replication") or {}
        automatic = replication.get("automatic") or {}
        if "automatic" in replication:
            result["replication"] = {"mode": "automatic", "kmsKeys": _kms_keys(automatic)}
        else:
            replicas = (replication.get("userManaged") or {}).get("replicas") or []
            result["replication"] = {
                "mode": "user-managed" if "userManaged" in replication else "unknown",
                "replicas": [{"location": replica.get("location"), "kmsKeys": _kms_keys(replica)} for replica in replicas],
            }
    return result


def _kms_keys(value):
    key = (value.get("customerManagedEncryption") or {}).get("kmsKeyName")
    return [str(key)] if key else []


def binding_assets(asset):
    """One assignment unit per (attached resource, principal, role, condition).

    Condition text is preserved, not evaluated. Member order, descriptions and
    policy etags do not change identity; changing the expression does.
    """
    scope = str(asset.get("name") or "")
    if not scope.startswith("//"):
        raise ValueError("IAM binding requires an attached full resource name")
    records = {}
    for binding in (asset.get("iamPolicy") or {}).get("bindings") or []:
        role = str(binding.get("role") or "")
        expression = str((binding.get("condition") or {}).get("expression") or "")
        if not role:
            raise ValueError("IAM binding role is missing")
        for member in binding.get("members") or []:
            member = str(member)
            identity = [scope, member, role, expression]
            digest = hashlib.sha256(json.dumps(identity, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
            name = "binding-" + digest
            records[name] = {
                "assetType": BINDING_TYPE,
                "name": scope + "#iam-binding=" + digest,
                "resource": {
                    "data": {
                        "name": name,
                        "labels": {"iam-role": role, "iam-member": member, "iam-scope": scope},
                    }
                },
                "bindingMetadata": {
                    "provider_asset_type": BINDING_TYPE,
                    "attached_resource": scope,
                    "attached_resource_type": asset.get("assetType"),
                    "principal": member,
                    "role": role,
                    "condition_expression": expression,
                    "grant_source": "attached-policy",
                    "effective_permissions_complete": False,
                },
            }
    return [records[key] for key in sorted(records)]
