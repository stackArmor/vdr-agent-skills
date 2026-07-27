#!/usr/bin/env python3
"""Derive the optional security-requirements ceiling from SSO and ASO.

Usage:
  derive_ceiling.py security-objectives.json

The input must contain top-level ``sso`` and ``aso`` objects. The derived
``securityRequirementsCeiling`` object is printed to stdout.
"""

import argparse
import json
import sys

OBJECTIVES = ("c", "i", "a")
RANK = {"L": 0, "M": 1, "H": 2}


class DerivationError(ValueError):
    """Raised when objective input is invalid."""


def normalize_level(value, location):
    if isinstance(value, str) and value.strip().upper() in RANK:
        return value.strip().upper()
    raise DerivationError(f"{location} must be one of L, M, H")


def normalize_vector(value, location):
    if not isinstance(value, dict):
        raise DerivationError(f"{location} must be an object with c, i, a")
    unknown = sorted(set(value) - set(OBJECTIVES))
    if unknown:
        raise DerivationError(
            f"{location} has unknown objectives: {', '.join(unknown)}"
        )
    return {
        objective: normalize_level(
            value.get(objective), f"{location}.{objective}"
        )
        for objective in OBJECTIVES
    }


def minimum(left, right):
    return {
        objective: (
            left[objective]
            if RANK[left[objective]] <= RANK[right[objective]]
            else right[objective]
        )
        for objective in OBJECTIVES
    }


def wire_value(vector):
    return "cr-{}_ir-{}_ar-{}".format(
        vector["c"].lower(), vector["i"].lower(), vector["a"].lower()
    )


def display_value(vector):
    return "CR:{}/IR:{}/AR:{}".format(
        vector["c"], vector["i"], vector["a"]
    )


def derive_ceiling(sso, aso):
    normalized_sso = normalize_vector(sso, "sso")
    normalized_aso = normalize_vector(aso, "aso")
    ceiling = minimum(normalized_sso, normalized_aso)
    return {
        **ceiling,
        "wire": wire_value(ceiling),
        "display": display_value(ceiling),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Derive min(SSO, ASO) as a security-requirements ceiling."
    )
    parser.add_argument("objectives_json", help="draft security-objectives JSON")
    args = parser.parse_args()

    try:
        with open(args.objectives_json, "r", encoding="utf-8") as handle:
            document = json.load(handle)
        if not isinstance(document, dict):
            raise DerivationError("input must be a JSON object")
        result = derive_ceiling(document.get("sso"), document.get("aso"))
    except (OSError, json.JSONDecodeError, DerivationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    json.dump(result, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
