#!/usr/bin/env python3
"""Deterministic renderer: assignment-plan JSON -> commented vdr-cloud.yaml.

No YAML library is used or available. The document is assembled as plain text
and never parsed back; ``render(plan)`` is a pure function of the plan JSON so a
validator can re-render and byte-compare.
"""
import argparse
import json
import sys

HEADER = [
    "# Central cloud-resource scoring assignment surface for trivy-plugin-vdr.",
    "# PROPOSED INTEGRATION CONTRACT: no current scanner consumes this document.",
    "apiVersion: vdr.fedramp.io/v1alpha1",
    "kind: CloudResourceScoringConfig",
]

# Fixed key order for a rule's single-line flow map.
RULE_KEY_ORDER = [
    "type", "match", "matchTags", "network", "subnet", "region",
    "securityImpactProfile", "multiAgency",
    "internetReachable", "internetReachableJustification",
]

VALID_CONFIDENCE = ("high", "medium", "low")


def _check_confidence(confidence, manual_review, where):
    """Enforce the confidence/manual-review invariant, raising ValueError."""
    if confidence not in VALID_CONFIDENCE:
        raise ValueError(
            "%s: confidence must be one of %s, got %r"
            % (where, "|".join(VALID_CONFIDENCE), confidence))
    if confidence != "high" and not manual_review:
        raise ValueError(
            "%s: non-high confidence (%s) requires at least one manual-review "
            "entry" % (where, confidence))


def _quote(value, force=False):
    """Quote a scalar when it holds YAML-significant characters or when forced.

    Dotted traces and provider types contain no YAML-special characters and are
    left bare; values with ``*`` or spaces (globs, prose) are quoted.
    """
    text = str(value)
    if force or "*" in text or " " in text:
        return '"%s"' % text
    return text


def _render_match_tags(match_tags):
    """Inline flow map for matchTags, keys sorted, values always quoted."""
    inner = ", ".join(
        "%s: %s" % (key, _quote(match_tags[key], force=True))
        for key in sorted(match_tags))
    return "{%s}" % inner


def _render_rule_map(rule):
    """One rule as a single-line flow map in the fixed key order."""
    parts = []
    for key in RULE_KEY_ORDER:
        value = rule.get(key)
        if value is None:
            continue
        if key == "matchTags":
            parts.append("matchTags: %s" % _render_match_tags(value))
        elif key in ("multiAgency", "internetReachable",
                     "internetReachableJustification"):
            parts.append("%s: %s" % (key, _quote(value, force=True)))
        else:
            parts.append("%s: %s" % (key, _quote(value)))
    return "- {%s}" % ", ".join(parts)


def _check_reachability(rule, where):
    """Enforce the reachability attestation contract, raising ValueError.

    ``internetReachable: "false"`` retracts a verdict TSW derived from firewall,
    route, and load-balancer evidence, so it is the one assignable attribute
    that cannot be emitted without prose an assessor can read. See
    ``references/cloud-config-schema.md`` for why WAF and DDoS protections do
    not qualify as justification.
    """
    value = rule.get("internetReachable")
    justification = (rule.get("internetReachableJustification") or "").strip()
    if value not in (None, "true", "false"):
        raise ValueError(
            '%s: internetReachable must be the quoted string "true" or '
            '"false", got %r' % (where, value))
    if value == "false" and not justification:
        raise ValueError(
            "%s: internetReachable \"false\" requires a non-empty "
            "internetReachableJustification naming the allowlist that "
            "restricts access and where it is enforced" % where)
    if justification and value != "false":
        raise ValueError(
            '%s: internetReachableJustification is only meaningful with '
            'internetReachable "false"' % where)


def _reject_broad_reachability(container, where):
    """Refuse a reachability attestation outside a rule.

    A defaults- or scope-level value is the broad fail-open the schema's
    fail-loud stance exists to prevent, and the generator has no reason to emit
    the redundant ``"true"`` form either.
    """
    if container.get("internetReachable") is not None:
        raise ValueError(
            "%s: internetReachable may only be set on a rule that names the "
            "assets it covers" % where)


def _attestation_lines(key, attestation, indent, where):
    """Comment(s) + ``key: "value"`` for a class/multiAgency attestation."""
    confidence = attestation["confidence"]
    manual_review = attestation.get("manualReview", [])
    _check_confidence(confidence, manual_review, where)
    lines = ["%s# confidence: %s | %s"
             % (indent, confidence, attestation["evidence"])]
    for item in manual_review:
        lines.append("%s# manual-review: %s" % (indent, item))
    lines.append('%s%s: "%s"' % (indent, key, attestation["value"]))
    return lines


def _rule_lines(rule, indent, where):
    """Comment(s) + flow-map line for one rule."""
    confidence = rule["confidence"]
    manual_review = rule.get("manualReview", [])
    _check_confidence(confidence, manual_review, where)
    _check_reachability(rule, where)
    lines = []
    if rule.get("builtinPattern"):
        lines.append("%s# builtin-pattern: %s" % (indent, rule["builtinPattern"]))
    lines.append("%s# confidence: %s | %s"
                 % (indent, confidence, rule["evidence"]))
    for item in manual_review:
        lines.append("%s# manual-review: %s" % (indent, item))
    lines.append("%s%s" % (indent, _render_rule_map(rule)))
    return lines


def _rule_family_lines(scope, family, indent, scope_key):
    """Lines for one rule family, or [] when the family is empty/absent."""
    rules = scope.get(family) or []
    if not rules:
        return []
    lines = ["%s%s:" % (indent, family)]
    rule_indent = indent + "  "
    for i, rule in enumerate(rules):
        where = "%s %s[%d]" % (scope_key, family, i)
        lines.extend(_rule_lines(rule, rule_indent, where))
    return lines


def _archetype_lines(archetypes):
    """Optional archetype catalog, matching the scoring.yaml archetype shape."""
    if not archetypes:
        return []
    lines = ["archetypes:"]
    for name in sorted(archetypes):
        entry = archetypes[name]
        parts = []
        if entry.get("description") is not None:
            parts.append("description: %s" % _quote(entry["description"], force=True))
        for axis in ("cr", "ir", "ar"):
            if entry.get(axis) is not None:
                parts.append("%s: %s" % (axis, entry[axis]))
        lines.append("  %s: {%s}" % (name, ", ".join(parts)))
    return lines


def render(plan):
    """Render the assignment plan to the commented vdr-cloud.yaml document."""
    lines = list(HEADER)

    defaults = plan["defaults"]
    _reject_broad_reachability(defaults, "defaults")
    lines.append("defaults:")
    lines.extend(_attestation_lines("class", defaults["class"], "  ",
                                    "defaults class"))
    lines.extend(_attestation_lines("multiAgency", defaults["multiAgency"], "  ",
                                    "defaults multiAgency"))
    if defaults.get("securityImpactProfile") is not None:
        lines.append("  securityImpactProfile: %s"
                     % _quote(defaults["securityImpactProfile"]))

    lines.extend(_archetype_lines(plan.get("archetypes") or {}))

    lines.append("scopes:")
    for scope in plan["scopes"]:
        provider = scope["provider"]
        if provider == "aws":
            scope_id = scope["account"]
            id_line = '    account: "%s"' % scope_id
        else:
            scope_id = scope["project"]
            id_line = "    project: %s" % scope_id
        scope_key = "%s/%s" % (provider, scope_id)
        _reject_broad_reachability(scope, scope_key)
        # First list-item line carries provider; identity is a continuation key.
        lines.append("  - provider: %s" % provider)
        lines.append(id_line)
        lines.extend(_attestation_lines("class", scope["class"], "    ",
                                        "%s class" % scope_key))
        lines.extend(_attestation_lines("multiAgency", scope["multiAgency"],
                                        "    ", "%s multiAgency" % scope_key))
        if scope.get("securityImpactProfile") is not None:
            lines.append("    securityImpactProfile: %s"
                         % _quote(scope["securityImpactProfile"]))
        for family in ("nameRules", "tagRules", "networkRules", "typeRules"):
            lines.extend(_rule_family_lines(scope, family, "    ", scope_key))

    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Render an assignment-plan JSON to vdr-cloud.yaml.")
    parser.add_argument("--plan", required=True, help="assignment-plan JSON file")
    parser.add_argument("--output", help="output file (default: stdout)")
    args = parser.parse_args(argv)

    with open(args.plan, encoding="utf-8") as handle:
        plan = json.load(handle)
    text = render(plan)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
