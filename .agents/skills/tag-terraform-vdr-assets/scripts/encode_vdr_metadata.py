#!/usr/bin/env python3
"""Validate canonical VDR metadata and encode provider-native key/value pairs."""

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path


REASON_CODES = (
    Path(__file__).resolve().parent.parent.parent
    / "generate-vdr-configmap"
    / "scripts"
    / "reason_codes.py"
)
CANONICAL_KEYS = {
    "archetype": "vdr.fedramp.io/asset-archetype",
    "asset_value": "vdr.fedramp.io/asset-value",
    "class": "vdr.fedramp.io/class",
    "multi_agency": "vdr.fedramp.io/multi-agency",
}
GCP_LABEL = re.compile(r"^[a-z][a-z0-9_-]{0,62}$")


def load_classifier():
    if not REASON_CODES.is_file():
        raise RuntimeError(f"governed reason-code helper not found: {REASON_CODES}")
    spec = importlib.util.spec_from_file_location("vdr_reason_codes", REASON_CODES)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.classify


def provider_key(provider, canonical):
    if provider == "aws":
        return canonical
    if provider == "azure":
        return canonical.replace("/", ".")
    return re.sub(r"[./-]", "_", canonical)


def encode_value(provider, field, value):
    if provider != "gcp":
        return value
    if field == "archetype":
        return value.replace(".", "__")
    return value.lower()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", choices=("aws", "azure", "gcp"), required=True)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("--archetype", help="canonical three-part dotted decision trace")
    choice.add_argument("--asset-value", choices=("High", "Medium", "Low"))
    parser.add_argument("--class", dest="certification_class", choices=tuple("ABCD"))
    parser.add_argument("--multi-agency", choices=("true", "false"))
    args = parser.parse_args(argv)

    canonical = {}
    vector = None
    try:
        if args.archetype:
            cr, ir, ar = load_classifier()(args.archetype)
            canonical[CANONICAL_KEYS["archetype"]] = args.archetype
            vector = {"cr": cr, "ir": ir, "ar": ar}
        else:
            canonical[CANONICAL_KEYS["asset_value"]] = args.asset_value
        if args.certification_class:
            canonical[CANONICAL_KEYS["class"]] = args.certification_class
        if args.multi_agency:
            canonical[CANONICAL_KEYS["multi_agency"]] = args.multi_agency

        encoded = {}
        for canonical_key, value in canonical.items():
            field = next(name for name, key in CANONICAL_KEYS.items() if key == canonical_key)
            key = provider_key(args.provider, canonical_key)
            encoded_value = encode_value(args.provider, field, value)
            if args.provider == "gcp":
                if not GCP_LABEL.fullmatch(key):
                    raise ValueError(f"encoded GCP label key is invalid: {key!r}")
                if encoded_value and not GCP_LABEL.fullmatch(encoded_value):
                    raise ValueError(f"encoded GCP label value is invalid: {encoded_value!r}")
            encoded[key] = encoded_value
    except (RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(json.dumps({
        "provider": args.provider,
        "canonical": canonical,
        "metadata": encoded,
        "vector": vector,
        "normalization_required": args.provider in {"azure", "gcp"},
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
