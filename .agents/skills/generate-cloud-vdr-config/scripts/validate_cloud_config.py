#!/usr/bin/env python3
"""No-cloud-access validator for the cloud-resource assignment plan.

Given the assignment-plan JSON, the read-only inventory JSON, the coverage
JSON, and the rendered ``vdr-cloud.yaml`` text, this script re-derives every
assignment from first principles and reports discrepancies as plain error
strings. It never contacts a cloud provider; the plan, inventory, and coverage
files are the only inputs.

Nine checks are enforced:
  1. every rule's securityImpactProfile value is a resolvable direct vector,
     governed decision trace, or named archetype;
  2. rule shape: required family field, at least one assigned attribute, valid
     confidence, and a manual-review entry for non-high confidence;
  3. networkRules never constrain a non-network-attachable (global) type;
  4. resolution replay: every inventory resource resolves to a profile, and
     the plan and inventory agree on which scopes exist;
  5. zero-match rules (a rule no inventory resource matches) are errors;
  6. shadowed rules (a later rule fully covered by an earlier one that assigns
     the same attribute) are errors;
  7. the inventory equation balances across inventory, coverage total, and the
     assignment list, with each resource assigned exactly once;
  8. each coverage assignment matches the replayed resolution and vector;
  9. rendered drift: re-rendering the plan must reproduce the supplied text.

Standard library only (Python >= 3.8).
"""

import argparse
import fnmatch
import importlib.util
import json
import re
import sys
from pathlib import Path

FAMILIES = ("nameRules", "tagRules", "networkRules", "typeRules")
SIP_TAG = "vdr.fedramp.io/security-impact-profile"
MA_TAG = "vdr.fedramp.io/multi-agency"
CLASS_TAG = "vdr.fedramp.io/class"

VALID_CONFIDENCE = ("high", "medium", "low")

# Non-network-attachable types: a networkRule constrained to one of these can
# never match a resource, because these resources carry no network attachment.
GLOBAL_TYPES = (
    "storage.googleapis.com/Bucket",
    "AWS::S3::Bucket",
    "bigquery.googleapis.com/Dataset",
)

_HERE = Path(__file__).resolve().parent
_SKILLS = _HERE.parent.parent
_REASON_CODES = _SKILLS / "generate-vdr-configmap" / "scripts" / "reason_codes.py"
_PROFILE_GUIDE = (
    _SKILLS / "generate-vdr-configmap" / "references" / "archetype-guide.md"
)
_RENDER_PATH = _HERE / "render_cloud_config.py"

_DIRECT_VECTOR = re.compile(r"(?i)cr-([lmh])_ir-([lmh])_ar-([lmh])")

_classify = None
_named_profiles = None
_render = None


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_classifier():
    """Import ``classify`` from the governed reason-code helper, once."""
    global _classify
    if _classify is None:
        if not _REASON_CODES.is_file():
            raise RuntimeError(
                "governed reason-code helper not found: %s" % _REASON_CODES)
        _classify = _load_module("vdr_reason_codes", _REASON_CODES).classify
    return _classify


def load_named_profiles():
    """Parse the archetype-guide catalog table into name -> (CR, IR, AR)."""
    global _named_profiles
    if _named_profiles is None:
        if not _PROFILE_GUIDE.is_file():
            raise RuntimeError("profile guide not found: %s" % _PROFILE_GUIDE)
        profiles = {}
        pattern = re.compile(
            r"^\| `([^`]+)` \| [^|]+ \| ([LMH]) \| ([LMH]) \| ([LMH]) \|")
        for line in _PROFILE_GUIDE.read_text(encoding="utf-8").splitlines():
            match = pattern.match(line)
            if match:
                name, cr, ir, ar = match.groups()
                profiles[name] = (cr, ir, ar)
        if not profiles:
            raise RuntimeError(
                "named profile catalog not found in: %s" % _PROFILE_GUIDE)
        _named_profiles = profiles
    return _named_profiles


def load_render():
    """Import the sibling deterministic renderer's ``render`` function, once."""
    global _render
    if _render is None:
        _render = _load_module("render_cloud_config", _RENDER_PATH).render
    return _render


def resolve_profile(profile):
    """Resolve a SIP value to its (CR, IR, AR) vector or raise ValueError.

    Accepts a direct ``cr-x_ir-y_ar-z`` vector, a governed dotted decision
    trace, or a named archetype from the guide's catalog.
    """
    direct = _DIRECT_VECTOR.fullmatch(profile)
    if direct:
        return tuple(value.upper() for value in direct.groups())
    if "." in profile:
        return load_classifier()(profile)
    named = load_named_profiles()
    if profile not in named:
        raise ValueError("unknown named security-impact profile %r" % profile)
    return named[profile]


def _vector_string(profile):
    return "/".join(resolve_profile(profile))


def rule_matches(rule, res, family):
    """Return True when ``rule`` matches inventory resource ``res``.

    Mirrors the plugin's per-family predicate. Missing required fields make the
    rule match nothing (shape validation reports the defect separately).
    """
    if rule.get("type") and rule["type"] != res["type"]:
        return False
    if rule.get("region") and not fnmatch.fnmatchcase(res.get("region") or "",
                                                      rule["region"]):
        return False
    if family == "nameRules":
        match = rule.get("match")
        if not match or not fnmatch.fnmatchcase(res["identifier"], match):
            return False
    if rule.get("matchTags"):
        tags = res.get("tags") or {}
        if not all(key in tags and fnmatch.fnmatchcase(str(tags[key]), str(val))
                   for key, val in rule["matchTags"].items()):
            return False
    if family == "networkRules":
        if not res.get("network"):
            return False
        if not rule.get("network") or not fnmatch.fnmatchcase(res["network"],
                                                              rule["network"]):
            return False
        if rule.get("subnet") and not fnmatch.fnmatchcase(res.get("subnet") or "",
                                                          rule["subnet"]):
            return False
    if family == "tagRules" and not rule.get("matchTags"):
        return False
    if family == "typeRules" and not rule.get("type"):
        return False
    return True


def resolve(res, scope_plan, defaults):
    """Independently resolve securityImpactProfile, multiAgency, and class.

    Each attribute resolves down its own chain: tag-override, then rules in
    family then document order (first rule that SETS the attribute wins),
    then the scope default, the global default, and finally ``unresolved``
    for securityImpactProfile.
    """
    out = {}
    vdr = res.get("vdrTags") or {}
    sip = (vdr[SIP_TAG], "tag-override") if SIP_TAG in vdr else None
    ma = (vdr[MA_TAG], "tag-override") if MA_TAG in vdr else None
    cls = (vdr[CLASS_TAG], "tag-override") if CLASS_TAG in vdr else None
    for family in FAMILIES:
        for index, rule in enumerate(scope_plan.get(family) or []):
            if (sip and ma) or not rule_matches(rule, res, family):
                continue
            source = "%s[%d]" % (family, index)
            if sip is None and rule.get("securityImpactProfile"):
                sip = (rule["securityImpactProfile"], source)
            if ma is None and rule.get("multiAgency") is not None:
                ma = (rule["multiAgency"], source)
    if sip is None and scope_plan.get("securityImpactProfile"):
        sip = (scope_plan["securityImpactProfile"], "scope-default")
    if sip is None and defaults.get("securityImpactProfile"):
        sip = (defaults["securityImpactProfile"], "global-default")
    if ma is None:
        ma = (scope_plan["multiAgency"]["value"], "scope-default") \
            if scope_plan.get("multiAgency") else \
            (defaults["multiAgency"]["value"], "global-default")
    if cls is None:
        cls = (scope_plan["class"]["value"], "scope-default") \
            if scope_plan.get("class") else \
            (defaults["class"]["value"], "global-default")
    out["securityImpactProfile"] = sip or (None, "unresolved")
    out["multiAgency"] = ma
    out["class"] = cls
    return out


def scope_key(scope):
    """Canonical ``provider/identity`` key for a plan or inventory scope."""
    provider = scope.get("provider")
    identity = scope.get("account") if provider == "aws" else scope.get("project")
    return "%s/%s" % (provider, identity)


def _required_field(family):
    return {"nameRules": "match", "tagRules": "matchTags",
            "networkRules": "network", "typeRules": "type"}[family]


def _rule_assigns(rule):
    """Attributes this rule sets: subset of {'securityImpactProfile',
    'multiAgency'}."""
    assigned = set()
    if rule.get("securityImpactProfile"):
        assigned.add("securityImpactProfile")
    if rule.get("multiAgency") is not None:
        assigned.add("multiAgency")
    return assigned


def _validate_sip_value(value, where, errors):
    try:
        resolve_profile(value)
    except (ValueError, RuntimeError) as exc:
        errors.append("%s invalid securityImpactProfile %r: %s"
                      % (where, value, exc))


def _validate_scope_shape(scope, key, errors):
    """Checks 1, 2, and 3 for a single plan scope."""
    if scope.get("securityImpactProfile"):
        _validate_sip_value(scope["securityImpactProfile"],
                            "%s scope default" % key, errors)
    for family in FAMILIES:
        for i, rule in enumerate(scope.get(family) or []):
            where = "%s %s[%d]" % (key, family, i)
            required = _required_field(family)
            if not rule.get(required):
                errors.append("%s missing required %s field" % (where, required))
            if not _rule_assigns(rule):
                errors.append("%s assigns neither securityImpactProfile nor "
                              "multiAgency" % where)
            confidence = rule.get("confidence")
            if confidence not in VALID_CONFIDENCE:
                errors.append("%s has invalid confidence %r" % (where, confidence))
            elif confidence != "high" and not rule.get("manualReview"):
                errors.append("%s is %s confidence but has no manual-review "
                              "entry" % (where, confidence))
            if rule.get("securityImpactProfile"):
                _validate_sip_value(rule["securityImpactProfile"], where, errors)
            if family == "networkRules" and rule.get("type") in GLOBAL_TYPES:
                errors.append("%s constrains non-network-attachable type %s"
                              % (where, rule["type"]))


def _matched_sets(scope, resources):
    """For each family, list the set of resource keys each rule matches."""
    matched = {}
    for family in FAMILIES:
        family_sets = []
        for rule in scope.get(family) or []:
            hits = {res["identifier"] for res in resources
                    if rule_matches(rule, res, family)}
            family_sets.append(hits)
        matched[family] = family_sets
    return matched


def _check_zero_match_and_shadow(scope, key, matched, errors):
    """Checks 5 and 6 for a single scope's rules."""
    rules_by_family = {family: (scope.get(family) or []) for family in FAMILIES}
    for family in FAMILIES:
        sets = matched[family]
        rules = rules_by_family[family]
        for j, hits in enumerate(sets):
            if not hits:
                errors.append("%s %s[%d] matches no inventoried resource"
                              % (key, family, j))
                continue
            for i in range(j):
                earlier = sets[i]
                if not earlier:
                    continue
                shared = _rule_assigns(rules[j]) & _rule_assigns(rules[i])
                if shared and hits <= earlier:
                    errors.append("%s %s[%d] is shadowed by %s[%d] (same %s, "
                                  "no unique match)"
                                  % (key, family, j, family, i,
                                     "/".join(sorted(shared))))
                    break


def _check_resolution_replay(scope, key, resources, defaults, errors):
    """Check 4: every resource resolves to a securityImpactProfile."""
    for res in resources:
        resolved = resolve(res, scope, defaults)
        if resolved["securityImpactProfile"][1] == "unresolved":
            errors.append("%s %s unresolved: no rule, scope default, or global "
                          "default assigns a securityImpactProfile"
                          % (key, res["identifier"]))


def _check_inventory_equation(inventory, coverage, errors):
    """Check 7: inventory count == coverage total == assignments, one each."""
    resource_count = inventory.get("summary", {}).get("resourceCount")
    inventory_total = coverage.get("inventoryTotal")
    assignments = coverage.get("assignments") or []
    if not (resource_count == inventory_total == len(assignments)):
        errors.append(
            "inventory equation does not balance: inventory resourceCount=%r, "
            "coverage inventoryTotal=%r, assignments=%d"
            % (resource_count, inventory_total, len(assignments)))

    assignment_keys = {}
    for assignment in assignments:
        akey = (assignment.get("scope"), assignment.get("type"),
                assignment.get("identifier"))
        assignment_keys[akey] = assignment_keys.get(akey, 0) + 1
    for akey, count in assignment_keys.items():
        if count != 1:
            errors.append("inventory equation violated: %s appears %d times in "
                          "assignments" % ("/".join(str(p) for p in akey), count))

    inventory_keys = set()
    for scope in inventory.get("scopes", []):
        key = scope_key(scope)
        for res in scope.get("resources", []):
            rkey = (key, res["type"], res["identifier"])
            inventory_keys.add(rkey)
            if rkey not in assignment_keys:
                errors.append("inventory equation violated: %s/%s/%s has no "
                              "assignment" % rkey)
    for akey in assignment_keys:
        if akey not in inventory_keys:
            errors.append("inventory equation violated: assignment %s/%s/%s "
                          "matches no inventoried resource" % akey)


def _check_assignments(coverage, resolved_by_key, errors):
    """Check 8: coverage entries agree with the replayed resolution."""
    for assignment in coverage.get("assignments") or []:
        akey = (assignment.get("scope"), assignment.get("type"),
                assignment.get("identifier"))
        label = "/".join(str(p) for p in akey)
        resolved = resolved_by_key.get(akey)
        if resolved is None:
            continue  # equation check already reports the orphaned assignment
        want_sip, want_src = resolved["securityImpactProfile"]
        if assignment.get("securityImpactProfile") != want_sip:
            errors.append("%s securityImpactProfile %r disagrees with replayed "
                          "%r" % (label, assignment.get("securityImpactProfile"),
                                  want_sip))
        if assignment.get("resolutionSource") != want_src:
            errors.append("%s resolutionSource %r disagrees with replayed %r"
                          % (label, assignment.get("resolutionSource"), want_src))
        want_ma, want_ma_src = resolved["multiAgency"]
        if assignment.get("multiAgency") != want_ma:
            errors.append("%s multiAgency %r disagrees with replayed %r"
                          % (label, assignment.get("multiAgency"), want_ma))
        if "multiAgencySource" in assignment \
                and assignment.get("multiAgencySource") != want_ma_src:
            errors.append("%s multiAgencySource %r disagrees with replayed %r"
                          % (label, assignment.get("multiAgencySource"),
                             want_ma_src))
        if want_sip is not None:
            try:
                want_vector = _vector_string(want_sip)
            except (ValueError, RuntimeError):
                continue  # invalid SIP already reported by check 1
            if assignment.get("vector") != want_vector:
                errors.append("%s vector %r disagrees with mechanically derived "
                              "%r" % (label, assignment.get("vector"),
                                      want_vector))
        entry_confidence = assignment.get("confidence")
        if entry_confidence in ("medium", "low") \
                and not assignment.get("manualReview"):
            errors.append("%s is %s confidence but lists no manual-review item"
                          % (label, entry_confidence))


def validate(plan, inventory, coverage, rendered_text):
    """Return a list of error strings; an empty list means the plan is valid."""
    errors = []
    defaults = plan.get("defaults") or {}

    if defaults.get("securityImpactProfile"):
        _validate_sip_value(defaults["securityImpactProfile"], "defaults", errors)

    plan_scopes = {scope_key(scope): scope for scope in plan.get("scopes", [])}
    inventory_scopes = {scope_key(scope): scope
                        for scope in inventory.get("scopes", [])}

    # Check 4 (scope agreement): a scope on one side but not the other.
    for key in sorted(set(plan_scopes) - set(inventory_scopes)):
        errors.append("plan scope %s has no matching inventory scope" % key)
    for key in sorted(set(inventory_scopes) - set(plan_scopes)):
        errors.append("inventory scope %s has no matching plan scope" % key)

    # Checks 1, 2, 3 (shape) over every plan scope.
    for key, scope in plan_scopes.items():
        _validate_scope_shape(scope, key, errors)

    # Checks 4, 5, 6 over scopes present on both sides.
    resolved_by_key = {}
    for key in sorted(set(plan_scopes) & set(inventory_scopes)):
        scope = plan_scopes[key]
        resources = inventory_scopes[key].get("resources", [])
        matched = _matched_sets(scope, resources)
        _check_zero_match_and_shadow(scope, key, matched, errors)
        _check_resolution_replay(scope, key, resources, defaults, errors)
        for res in resources:
            resolved_by_key[(key, res["type"], res["identifier"])] = \
                resolve(res, scope, defaults)

    # Check 7 (inventory equation).
    _check_inventory_equation(inventory, coverage, errors)

    # Check 8 (per-assignment cross-check).
    _check_assignments(coverage, resolved_by_key, errors)

    # Check 9 (rendered drift).
    if load_render()(plan) != rendered_text:
        errors.append("rendered vdr-cloud.yaml does not match the plan")

    return errors


def _format_manual_review(items):
    return "; ".join(items) if items else "(none listed)"


def confidence_report(plan, coverage):
    """Human-readable report of every item needing operator review.

    Lists every medium/low assignment, every configuration assumption, and
    every tag-override resolution (as override provenance). When nothing needs
    review, prints ``manual-review items: none``.
    """
    lines = ["Confidence report", "================="]

    overrides = [a for a in (coverage.get("assignments") or [])
                 if a.get("resolutionSource") == "tag-override"]
    lines.append("")
    lines.append("Override provenance (workload tag beats every rule):")
    if overrides:
        for a in overrides:
            lines.append(
                "  - %s %s/%s: securityImpactProfile=%s via tag-override"
                % (a.get("scope"), a.get("type"), a.get("identifier"),
                   a.get("securityImpactProfile")))
    else:
        lines.append("  none")

    review = [a for a in (coverage.get("assignments") or [])
              if a.get("confidence") in ("medium", "low")]
    assumptions = coverage.get("configurationAssumptions") or []
    attestations = _plan_attestations_needing_review(plan)

    lines.append("")
    if not review and not assumptions and not attestations:
        lines.append("manual-review items: none")
        return "\n".join(lines) + "\n"

    lines.append("Manual-review items:")
    for a in review:
        lines.append("  - [%s] %s %s/%s securityImpactProfile=%s"
                     % (a.get("confidence"), a.get("scope"), a.get("type"),
                        a.get("identifier"), a.get("securityImpactProfile")))
        lines.append("      evidence: %s" % a.get("evidence"))
        lines.append("      manual-review: %s"
                     % _format_manual_review(a.get("manualReview")))
    for where, att in attestations:
        lines.append("  - [%s] %s %s=%s"
                     % (att.get("confidence"), where, att.get("_field"),
                        att.get("value")))
        lines.append("      evidence: %s" % att.get("evidence"))
        lines.append("      manual-review: %s"
                     % _format_manual_review(att.get("manualReview")))
    for assumption in assumptions:
        value = assumption.get("value", assumption)
        lines.append("  - [assumption] %s" % value)
        if isinstance(assumption, dict):
            if assumption.get("evidence"):
                lines.append("      evidence: %s" % assumption["evidence"])
            actions = assumption.get("manualReview") or assumption.get("actions")
            if actions:
                lines.append("      manual-review: %s"
                             % _format_manual_review(actions))
    return "\n".join(lines) + "\n"


def _plan_attestations_needing_review(plan):
    """Medium/low class or multiAgency attestations from defaults and scopes."""
    found = []
    defaults = plan.get("defaults") or {}
    for field in ("class", "multiAgency"):
        att = defaults.get(field)
        if isinstance(att, dict) and att.get("confidence") in ("medium", "low"):
            entry = dict(att)
            entry["_field"] = field
            found.append(("defaults", entry))
    for scope in plan.get("scopes", []):
        key = scope_key(scope)
        for field in ("class", "multiAgency"):
            att = scope.get(field)
            if isinstance(att, dict) \
                    and att.get("confidence") in ("medium", "low"):
                entry = dict(att)
                entry["_field"] = field
                found.append((key, entry))
    return found


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Validate a cloud-resource assignment plan against its "
                    "inventory, coverage, and rendered document.")
    parser.add_argument("--plan", required=True, help="assignment-plan JSON")
    parser.add_argument("--inventory", required=True, help="inventory JSON")
    parser.add_argument("--coverage", required=True, help="coverage JSON")
    parser.add_argument("--rendered", required=True,
                        help="rendered vdr-cloud.yaml to byte-compare")
    args = parser.parse_args(argv)

    with open(args.plan, encoding="utf-8") as handle:
        plan = json.load(handle)
    with open(args.inventory, encoding="utf-8") as handle:
        inventory = json.load(handle)
    with open(args.coverage, encoding="utf-8") as handle:
        coverage = json.load(handle)
    with open(args.rendered, encoding="utf-8") as handle:
        rendered_text = handle.read()

    sys.stdout.write(confidence_report(plan, coverage))

    errors = validate(plan, inventory, coverage, rendered_text)
    if errors:
        for error in errors:
            print("error: %s" % error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
