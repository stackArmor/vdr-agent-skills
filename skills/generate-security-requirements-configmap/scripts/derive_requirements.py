#!/usr/bin/env python3
"""Derive final security-requirements vectors and the scoring catalog.

Per objective o in {c, i, a} with L < M < H:
  envelope(o) = min(sso(o), aso(o))
  final(o)    = min(cso(o), envelope(o))
A declared breakout restores final(o) = cso(o) for that objective. A breakout
is valid only when cso(o) exceeds the envelope and its category is one of the
closed list; a no-op breakout is an input error, not a silent pass.

Usage:
  derive_requirements.py --emit-catalog
  derive_requirements.py --derive <input.json>

Derive input document:
{
  "sso": {"c": "M", "i": "M", "a": "M"},
  "aso": {"c": "M", "i": "M", "a": "L"},
  "components": [
    {"id": "namespace/Kind/name",
     "cso": {"c": "H", "i": "H", "a": "M"},
     "breakouts": [{"objective": "i",
                    "category": "agency-endpoint-delivery",
                    "justification": "controls the endpoint agent update channel"}]}
  ]
}

Exit codes: 0 success, 2 validation error (message on stderr).
Requires python3 >= 3.8, standard library only.
"""
import argparse
import json
import re
import sys

RANK = {"L": 0, "M": 1, "H": 2}
LEVELS = ("L", "M", "H")
OBJECTIVES = ("c", "i", "a")
LABEL_RE = re.compile(r"^cr-([lmh])_ir-([lmh])_ar-([lmh])$")
BREAKOUT_CATEGORIES = (
    "agency-endpoint-delivery",
    "cross-system-trust-anchor",
    "shared-csp-infrastructure",
)


class DerivationError(ValueError):
    """Raised when derivation input is invalid."""


def normalize_level(value, location):
    if isinstance(value, str) and value.strip().upper() in RANK:
        return value.strip().upper()
    raise DerivationError(f"{location} must be one of L, M, H")


def normalize_vector(mapping, location):
    if not isinstance(mapping, dict):
        raise DerivationError(f"{location} must be an object with c, i, a")
    unknown = sorted(set(mapping) - set(OBJECTIVES))
    if unknown:
        raise DerivationError(
            f"{location} has unknown objectives: {', '.join(unknown)}"
        )
    return {o: normalize_level(mapping.get(o), f"{location}.{o}") for o in OBJECTIVES}


def minimum(left, right):
    return {
        o: left[o] if RANK[left[o]] <= RANK[right[o]] else right[o]
        for o in OBJECTIVES
    }


def label_for(vector):
    return "cr-{}_ir-{}_ar-{}".format(
        vector["c"].lower(), vector["i"].lower(), vector["a"].lower()
    )


def vector_for_label(label):
    match = LABEL_RE.match(label if isinstance(label, str) else "")
    if not match:
        raise DerivationError(
            f"label {label!r} must match cr-[lmh]_ir-[lmh]_ar-[lmh]"
        )
    return {o: match.group(index + 1).upper() for index, o in enumerate(OBJECTIVES)}


def catalog_yaml():
    lines = ["archetypes:"]
    for c in LEVELS:
        for i in LEVELS:
            for a in LEVELS:
                vector = {"c": c, "i": i, "a": a}
                lines.append(f'  "{label_for(vector)}":')
                lines.append(f"    {{lens: requirements, cr: {c}, ir: {i}, ar: {a}}}")
    return "\n".join(lines) + "\n"


def normalize_breakouts(component, location):
    raw = component.get("breakouts", [])
    if not isinstance(raw, list):
        raise DerivationError(f"{location}.breakouts must be a list")
    breakouts = []
    seen = set()
    for index, entry in enumerate(raw):
        entry_location = f"{location}.breakouts[{index}]"
        if not isinstance(entry, dict):
            raise DerivationError(f"{entry_location} must be an object")
        objective = entry.get("objective")
        if objective not in OBJECTIVES:
            raise DerivationError(f"{entry_location}.objective must be c, i, or a")
        if objective in seen:
            raise DerivationError(f"{entry_location} duplicates objective {objective!r}")
        seen.add(objective)
        category = entry.get("category")
        if category not in BREAKOUT_CATEGORIES:
            raise DerivationError(
                f"{entry_location}.category must be one of: "
                + ", ".join(BREAKOUT_CATEGORIES)
            )
        justification = entry.get("justification")
        if not isinstance(justification, str) or not justification.strip():
            raise DerivationError(
                f"{entry_location}.justification must be a non-empty string"
            )
        breakouts.append({
            "objective": objective,
            "category": category,
            "justification": justification.strip(),
        })
    return breakouts


def derive_component(component, envelope, index):
    location = f"components[{index}]"
    if not isinstance(component, dict):
        raise DerivationError(f"{location} must be an object")
    identity = component.get("id")
    if not isinstance(identity, str) or not identity.strip():
        raise DerivationError(f"{location}.id must be a non-empty string")
    cso = normalize_vector(component.get("cso"), f"{location}.cso")
    breakouts = normalize_breakouts(component, location)
    breakout_objectives = {entry["objective"] for entry in breakouts}
    final = {}
    capped = {}
    for objective in OBJECTIVES:
        if objective in breakout_objectives:
            if RANK[cso[objective]] <= RANK[envelope[objective]]:
                raise DerivationError(
                    f"{location} declares a breakout on {objective!r} but the "
                    f"component objective does not exceed the envelope"
                )
            final[objective] = cso[objective]
        elif RANK[cso[objective]] <= RANK[envelope[objective]]:
            final[objective] = cso[objective]
        else:
            final[objective] = envelope[objective]
        capped[objective] = RANK[final[objective]] < RANK[cso[objective]]
    return {
        "id": identity.strip(),
        "cso": cso,
        "final": final,
        "capped": capped,
        "breakouts": breakouts,
        "securityRequirements": label_for(final),
    }


def derive(document):
    if not isinstance(document, dict):
        raise DerivationError("derive input must be a JSON object")
    sso = normalize_vector(document.get("sso"), "sso")
    aso = normalize_vector(document.get("aso"), "aso")
    envelope = minimum(sso, aso)
    raw_components = document.get("components", [])
    if not isinstance(raw_components, list):
        raise DerivationError("components must be a list")
    components = [
        derive_component(component, envelope, index)
        for index, component in enumerate(raw_components)
    ]
    identities = [component["id"] for component in components]
    if len(identities) != len(set(identities)):
        raise DerivationError("components contains duplicate ids")
    return {
        "sso": sso,
        "aso": aso,
        "envelope": envelope,
        "components": components,
        "labelValuesUsed": sorted({c["securityRequirements"] for c in components}),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Derive security-requirements vectors and the scoring catalog."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--emit-catalog", action="store_true",
                       help="print the 27-entry archetypes catalog YAML")
    group.add_argument("--derive", metavar="INPUT_JSON",
                       help="derive final vectors from an input document")
    args = parser.parse_args()
    if args.emit_catalog:
        sys.stdout.write(catalog_yaml())
        return 0
    try:
        with open(args.derive, "r", encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read derive input: {exc}", file=sys.stderr)
        return 2
    try:
        result = derive(document)
    except DerivationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    json.dump(result, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
