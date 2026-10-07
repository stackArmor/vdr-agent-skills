#!/usr/bin/env python3
"""Offline coverage delta and additive-only guard; never reassess impact.

Both update skills ship this identical helper. Inventory and policy are inputs,
not provider credentials. PyYAML is needed for YAML input; the existing cloud
generator supplies matching and governed profile validation.
"""

import argparse
import fnmatch
import importlib.util
import json
import sys
from collections import Counter
from pathlib import Path

SKILLS = Path(__file__).resolve().parents[2]
FAMILIES = ("nameRules", "tagRules", "networkRules", "typeRules")
K8S_FAMILIES = ("nameRules", "kindRules", "namespaceRules")
SIP = "vdr.fedramp.io/security-impact-profile"
ATTRIBUTES = (
    "securityImpactProfile",
    "class",
    "multiAgency",
    "internetReachable",
    "internetReachableJustification",
)
EMBEDDED_KEYS = ("scoring.yaml", "scoring", "config.yaml", "config")


def load_validator():
    path = SKILLS / "generate-cloud-vdr-config/scripts/validate_cloud_config.py"
    spec = importlib.util.spec_from_file_location("vdr_coverage_validator", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def yaml_documents(text):
    try:
        import yaml
    except ImportError as exc:
        raise ValueError("YAML input needs PyYAML; use an existing Python environment with it") from exc

    class UniqueLoader(yaml.SafeLoader):
        pass

    def mapping(loader, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if key in result:
                raise ValueError(f"duplicate YAML key: {key}")
            result[key] = loader.construct_object(value_node, deep=deep)
        return result

    UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
    try:
        return list(yaml.load_all(text, Loader=UniqueLoader))
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid YAML input: {exc}") from exc


def read_policy(path, mode):
    docs = yaml_documents(Path(path).read_text(encoding="utf-8"))
    kind = "ConfigMap" if mode == "k8s" else "CloudResourceScoringConfig"
    policies = [doc for doc in docs if isinstance(doc, dict) and doc.get("kind") == kind]
    if len(policies) != 1:
        raise ValueError(f"expected exactly one {kind}; select the baseline explicitly")
    return policies[0]


def scoring(configmap):
    data = configmap.get("data") or {}
    for key in EMBEDDED_KEYS:
        if str(data.get(key) or "").strip():
            docs = yaml_documents(data[key])
            if len(docs) != 1 or not isinstance(docs[0], dict):
                raise ValueError(f"embedded {key} must be one mapping")
            return key, docs[0]
    return "scoring.yaml", {}


def scope_key(scope):
    provider = scope.get("provider")
    identity = scope.get("account") if provider == "aws" else scope.get("project")
    if provider not in ("gcp", "aws") or not identity:
        raise ValueError("invalid scope identity")
    return f"{provider}/{identity}"


def cloud_scopes(policy):
    result = {}
    for scope in policy.get("scopes") or []:
        key = scope_key(scope)
        if key in result:
            raise ValueError(f"duplicate policy scope: {key}")
        result[key] = scope
    return result


def inventory_rows(inventory, mode):
    rows = []
    if mode == "cloud":
        seen_scopes = set()
        for scope in inventory["scopes"]:
            key = scope_key(scope)
            if key in seen_scopes:
                raise ValueError(f"duplicate inventory scope: {key}")
            seen_scopes.add(key)
            for resource in scope["resources"]:
                identity = (key, resource["type"], resource["identifier"])
                rows.append((identity, resource, scope))
    else:
        context = inventory.get("context")
        if not context:
            raise ValueError("Kubernetes inventory must pin its context")
        namespaces = {entry["name"]: entry for entry in inventory["namespaces"]}
        for resource in inventory["workloads"]:
            namespace = resource["namespace"]
            if namespace not in namespaces:
                raise ValueError(f"missing namespace evidence: {namespace}")
            identity = (context, namespace, resource["kind"], resource["name"])
            rows.append((identity, resource, namespaces[namespace]))
    identities = [row[0] for row in rows]
    if len(set(identities)) != len(identities):
        raise ValueError("duplicate resource identities; do not collapse ambiguous resources")
    return rows


def profile_error(value, policy, validator):
    if not isinstance(value, str) or not value.strip():
        return "empty profile"
    value = value.strip()
    custom = (policy.get("archetypes") or {}).get(value)
    if custom is not None:
        if not isinstance(custom, dict) or any(custom.get(key) not in ("L", "M", "H") for key in ("cr", "ir", "ar")):
            return "invalid custom profile"
        return None
    try:
        validator.resolve_profile(value)
    except (ValueError, RuntimeError) as exc:
        return str(exc)
    return None


def scalar(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    return value


def resolve_cloud(resource, policy, scope, validator, resources=()):
    out = {}
    tags = resource.get("vdrTags") or {}
    for attribute in ATTRIBUTES:
        tag = "vdr.fedramp.io/" + {
            "securityImpactProfile": "security-impact-profile",
            "multiAgency": "multi-agency",
            "internetReachable": "internet-reachable",
            "internetReachableJustification": "internet-reachable-justification",
        }.get(attribute, attribute)
        if tag in tags:
            out[attribute] = (scalar(tags[tag]), "tag-override")
            continue
        for family in FAMILIES:
            for index, rule in enumerate(scope.get(family) or []):
                if attribute in rule and rule[attribute] is not None and validator.rule_matches(rule, resource, family):
                    out[attribute] = (
                        scalar(rule[attribute]),
                        f"{family}[{index}]",
                    )
                    break
            if attribute in out:
                break
        if (
            attribute == "securityImpactProfile"
            and attribute not in out
            and resource.get("type") == "iam.googleapis.com/ServiceAccountKey"
        ):
            parent = validator.key_parent(resource, scope, resources)
            inherited = resolve_cloud(parent, policy, scope, validator, resources) if parent else {}
            profile, parent_source = inherited.get(attribute, (None, "unresolved"))
            # Invalid parents remain blockers; missing owners must not be hidden by defaults.
            if parent and (
                inherited["class"][0] not in ("A", "B", "C", "D") or inherited["multiAgency"][0] not in ("true", "false")
            ):
                profile = None
            out[attribute] = (
                profile,
                f"service-account:{parent['identifier']}:{parent_source}" if profile else "unresolved",
            )
        if (
            attribute in ("securityImpactProfile", "multiAgency")
            and attribute not in out
            and resource.get("type") == "cloudkms.googleapis.com/CryptoKey"
        ):
            parent = validator.key_parent(resource, scope, resources, kms=True)
            inherited = resolve_cloud(parent, policy, scope, validator, resources) if parent else {}
            value, parent_source = inherited.get(attribute, (None, "unresolved"))
            if parent and (
                inherited["class"][0] not in ("A", "B", "C", "D")
                or inherited["multiAgency"][0] not in ("true", "false")
                or profile_error(inherited["securityImpactProfile"][0], policy, validator)
            ):
                value = None
            out[attribute] = (
                value,
                f"key-ring:{parent['identifier']}:{parent_source}" if value is not None else "unresolved",
            )
        if attribute not in out:
            if attribute in scope:
                out[attribute] = (scalar(scope[attribute]), "scope-default")
            elif attribute in (policy.get("defaults") or {}):
                out[attribute] = (
                    scalar(policy["defaults"][attribute]),
                    "global-default",
                )
            else:
                out[attribute] = (None, "unresolved")
    return out


def path_match(pattern, value):
    # Kubernetes names/namespaces contain no slash. Preserve Go's [^...] syntax;
    # reject escape syntax we cannot replay rather than quietly approximating it.
    if "\\" in pattern or "[!" in pattern or "/" in pattern:
        raise ValueError(f"unsupported Kubernetes glob; verify with the plugin: {pattern}")
    return fnmatch.fnmatchcase(value, pattern.replace("[^", "[!"))


def k8s_matches(rule, resource, family):
    if family == "namespaceRules":
        return path_match(rule["match"], resource["namespace"])
    if rule.get("namespace") and not path_match(rule["namespace"], resource["namespace"]):
        return False
    if family == "kindRules":
        if not rule.get("kind") or not path_match(rule["kind"], resource["kind"]):
            return False
        return not rule.get("match") or path_match(rule["match"], resource["name"])
    return path_match(rule["match"], resource["name"])


def resolve_k8s(resource, namespace, configmap, validator):
    _, policy = scoring(configmap)
    label_key = (policy.get("labelKeys") or {}).get("securityImpactProfile", SIP)
    if not label_key.startswith("vdr.fedramp.io/"):
        raise ValueError("custom label key is not captured by the sanitized inventory; obtain effective label evidence")
    for labels, source in (
        (resource.get("vdrLabels") or {}, "workload-label"),
        (namespace.get("vdrLabels") or {}, "namespace-label"),
    ):
        if label_key in labels:
            return {"securityImpactProfile": (labels[label_key], source)}
    for family in K8S_FAMILIES:
        for index, rule in enumerate(policy.get(family) or []):
            value = rule.get("securityImpactProfile")
            if k8s_matches(rule, resource, family) and not profile_error(value, policy, validator):
                return {"securityImpactProfile": (value, f"{family}[{index}]")}
    value = (policy.get("defaults") or {}).get("securityImpactProfile")
    return {"securityImpactProfile": (value, "default" if value else "failsafe")}


def list_guard(old, new, families, where, errors):
    if {key: value for key, value in old.items() if key not in families} != {
        key: value for key, value in new.items() if key not in families
    }:
        errors.append(f"{where} changed existing non-rule fields/defaults/catalog")
    additions = []
    for family in families:
        before, after = old.get(family) or [], new.get(family) or []
        if after[: len(before)] != before:
            errors.append(f"{where} {family} rewrote, reordered or removed existing rules")
        additions.extend((family, rule) for rule in after[len(before) :])
    return additions


def additions_guard(baseline, candidate, mode, errors):
    additions = {}
    if mode == "cloud":
        before, after = cloud_scopes(baseline), cloud_scopes(candidate)
        if {k: v for k, v in baseline.items() if k != "scopes"} != {k: v for k, v in candidate.items() if k != "scopes"}:
            errors.append("changed cloud defaults/catalog/document fields")
        if list(after)[: len(before)] != list(before):
            errors.append("removed/reordered an existing cloud scope")
        for key, scope in before.items():
            if key not in after:
                errors.append(f"removed scope: {key}")
                continue
            additions[key] = list_guard(scope, after[key], FAMILIES, key, errors)
        for key in set(after) - set(before):
            if after[key].get("securityImpactProfile"):
                errors.append(f"{key} new scope introduces a broad SIP default")
            additions[key] = [(family, rule) for family in FAMILIES for rule in after[key].get(family) or []]
    else:
        old_key, old = scoring(baseline)
        new_key, new = scoring(candidate)
        if old_key != new_key:
            errors.append("changed embedded scoring key")
        for key in ("name", "namespace"):
            if baseline.get("metadata", {}).get(key) != candidate.get("metadata", {}).get(key):
                errors.append(f"changed ConfigMap target {key}")
        if {k: v for k, v in baseline.get("data", {}).items() if k != old_key} != {
            k: v for k, v in candidate.get("data", {}).items() if k != new_key
        }:
            errors.append("changed ConfigMap scalars/ceiling/reachability/other data")
        if baseline.get("binaryData") != candidate.get("binaryData"):
            errors.append("changed ConfigMap binaryData")
        additions["k8s"] = list_guard(old, new, K8S_FAMILIES, "scoring", errors)
    return additions


def analyze(baseline, inventory, mode, candidate=None, previous=None):
    validator = load_validator()
    rows = inventory_rows(inventory, mode)
    prior = None
    if previous is not None:
        if mode == "k8s" and (previous.get("context"), previous.get("scope")) != (
            inventory.get("context"),
            inventory.get("scope"),
        ):
            raise ValueError("previous Kubernetes inventory has a different context/scope")
        prior = {row[0] for row in inventory_rows(previous, mode)}
    errors, entries = [], []
    if mode == "cloud":
        for label, policy in (("baseline", baseline), ("candidate", candidate)):
            if policy is None:
                continue
            for key, scope in cloud_scopes(policy).items():
                for family in FAMILIES:
                    for index, rule in enumerate(scope.get(family) or []):
                        defects = validator.selector_errors(rule, family)
                        if defects and label == "baseline":
                            raise ValueError(f"{label} {key} {family}[{index}]: {'; '.join(defects)}")
                        errors.extend(f"{label} {key} {family}[{index}]: {defect}" for defect in defects)
    additions = additions_guard(baseline, candidate, mode, errors) if candidate is not None else {}
    scopes = cloud_scopes(baseline) if mode == "cloud" else {}
    updated_scopes = cloud_scopes(candidate) if candidate is not None and mode == "cloud" else {}
    for identity, resource, context in rows:
        key = identity[0] if mode == "cloud" else "k8s"
        scope = scopes.get(key, {})
        if mode == "cloud":
            resolved = resolve_cloud(resource, baseline, scope, validator, context["resources"])
            profile_policy = baseline
        else:
            resolved = resolve_k8s(resource, context, baseline, validator)
            profile_policy = scoring(baseline)[1]
        value, source = resolved["securityImpactProfile"]
        problem = profile_error(value, profile_policy, validator) if value else None
        missing = not value or value == "unclassified"
        blocked = bool(problem) and not missing
        status = "blocked-existing-profile" if blocked else "missing-assignment" if missing else "covered-unchanged"
        if mode == "cloud" and key not in scopes and not blocked:
            status = "missing-scope"
        if (
            status == "covered-unchanged"
            and mode == "cloud"
            and (resolved["class"][0] not in ("A", "B", "C", "D") or resolved["multiAgency"][0] not in ("true", "false"))
        ):
            status = "blocked-existing-metadata"
        entry = {
            "identity": list(identity),
            "status": status,
            "profile": value,
            "resolutionSource": source,
            "newResource": None if prior is None else identity not in prior,
        }
        if problem:
            entry["problem"] = problem
        if candidate is not None:
            next_scope = updated_scopes.get(key, {})
            after = (
                resolve_cloud(resource, candidate, next_scope, validator, context["resources"])
                if mode == "cloud"
                else resolve_k8s(resource, context, candidate, validator)
            )
            next_value = after["securityImpactProfile"][0]
            next_policy = candidate if mode == "cloud" else scoring(candidate)[1]
            entry["proposedProfile"] = next_value
            if status.startswith("blocked-"):
                errors.append(f"{identity} blocked existing assignment; do not repair/re-score it in this update")
            elif status == "covered-unchanged":
                if {attr: pair[0] for attr, pair in resolved.items()} != {attr: pair[0] for attr, pair in after.items()}:
                    errors.append(f"{identity} changed an existing effective assignment")
            elif not next_value or next_value == "unclassified" or profile_error(next_value, next_policy, validator):
                errors.append(f"{identity} remains without a usable assignment")
            if mode == "cloud" and key not in updated_scopes:
                errors.append(f"{key} remains without a policy scope")
            if (
                mode == "cloud"
                and status.startswith("missing-")
                and (after["class"][0] not in ("A", "B", "C", "D") or after["multiAgency"][0] not in ("true", "false"))
            ):
                errors.append(f"{identity} has missing/invalid Class or agency scope")
            for family, rule in additions.get(key, []):
                matches = (
                    validator.rule_matches(rule, resource, family) if mode == "cloud" else k8s_matches(rule, resource, family)
                )
                if matches and status == "covered-unchanged":
                    errors.append(f"{identity} new rule touches an already-covered resource")
        entries.append(entry)
    current = {row[0] for row in rows}
    if candidate is not None:
        for key, rules in additions.items():
            for family, rule in rules:
                profile = rule.get("securityImpactProfile")
                policy = candidate if mode == "cloud" else scoring(candidate)[1]
                if mode == "cloud":
                    if rule.get("internetReachable") is not None or rule.get("internetReachableJustification") is not None:
                        errors.append(f"{key} new rule adds a reachability attestation outside coverage-only scope")
                    if not rule.get("type"):
                        errors.append(f"{key} new rule must pin its resource type")
                    if rule.get("multiAgency") not in (None, "true", "false"):
                        errors.append(f"{key} new rule has invalid agency scope")
                elif family in ("nameRules", "kindRules") and not rule.get("namespace"):
                    errors.append("new Kubernetes name/kind rule must pin its namespace")
                if not profile or profile == "unclassified" or profile_error(profile, policy, validator):
                    errors.append(f"{key} new {family} rule lacks a valid non-failsafe profile")
                matches = [
                    row
                    for row in rows
                    if (row[0][0] if mode == "cloud" else "k8s") == key
                    and (validator.rule_matches(rule, row[1], family) if mode == "cloud" else k8s_matches(rule, row[1], family))
                ]
                if not matches:
                    errors.append(f"{key} new {family} rule matches no discovered resource")
    warnings = []
    if mode == "cloud":
        for scope in inventory["scopes"]:
            warnings.extend(f"{scope_key(scope)}: {warning}" for warning in scope.get("warnings") or [])
        unseen = set(scopes) - {scope_key(scope) for scope in inventory["scopes"]}
        warnings.extend(f"scope not inventoried; retained without coverage claim: {key}" for key in sorted(unseen))
    return {
        "mode": mode,
        "inventoryTotal": len(entries),
        "assignments": entries,
        "summary": dict(Counter(entry["status"] for entry in entries)),
        "notObserved": [] if prior is None else [list(key) for key in sorted(prior - current)],
        "warnings": warnings,
        "errors": sorted(set(errors)),
        "candidateChecked": candidate is not None,
        "existingScoresReevaluated": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("cloud", "k8s"), required=True)
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--inventory", required=True)
    parser.add_argument("--previous-inventory")
    parser.add_argument("--candidate")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        baseline = read_policy(args.baseline, args.mode)
        candidate = read_policy(args.candidate, args.mode) if args.candidate else None
        inventory = json.loads(Path(args.inventory).read_text(encoding="utf-8"))
        previous = json.loads(Path(args.previous_inventory).read_text(encoding="utf-8")) if args.previous_inventory else None
        report = analyze(baseline, inventory, args.mode, candidate, previous)
        Path(args.output).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(
            json.dumps(
                {
                    key: report[key]
                    for key in (
                        "inventoryTotal",
                        "summary",
                        "warnings",
                        "errors",
                        "candidateChecked",
                    )
                },
                indent=2,
            )
        )
        return 1 if report["errors"] else 0
    except (ValueError, KeyError, TypeError, OSError) as exc:
        print(f"coverage diff failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
