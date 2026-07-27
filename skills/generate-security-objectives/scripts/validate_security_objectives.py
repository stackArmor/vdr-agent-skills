#!/usr/bin/env python3
"""Validate the focused security-objectives.json contract."""

import argparse
import json
import sys
from pathlib import Path

SCRIPT_DIR = str(Path(__file__).resolve().parent)
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from derive_ceiling import (  # noqa: E402
    DerivationError,
    OBJECTIVES,
    derive_ceiling,
    normalize_level,
    normalize_vector,
)

CONFIDENCE = {"low", "medium", "high"}
STATUS = {"operator-confirmed", "agent-inferred"}
RELATIONSHIPS = {"definite", "target"}
CLASSES = {"A", "B", "C", "D", "unknown"}
FORBIDDEN_TOP_LEVEL = {
    "assignments",
    "ceilingMode",
    "components",
    "configMap",
    "envelope",
    "inventoryTotal",
    "multiAgencyDetermination",
}


class ValidationError(ValueError):
    """Raised when the objectives artifact violates its contract."""


def require_object(value, location):
    if not isinstance(value, dict):
        raise ValidationError(f"{location} must be an object")
    return value


def require_string(value, location, allow_empty=False):
    if not isinstance(value, str) or (not allow_empty and not value.strip()):
        raise ValidationError(f"{location} must be a non-empty string")
    return value.strip()


def require_string_list(value, location):
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item.strip() for item in value
    ):
        raise ValidationError(f"{location} must be a list of non-empty strings")


def validate_evidence_record(record, location):
    status = require_string(record.get("status"), f"{location}.status")
    if status not in STATUS:
        raise ValidationError(
            f"{location}.status must be operator-confirmed or agent-inferred"
        )
    confidence = require_string(
        record.get("confidence"), f"{location}.confidence"
    )
    if confidence not in CONFIDENCE:
        raise ValidationError(f"{location}.confidence must be low, medium, or high")
    require_string_list(record.get("assumptions"), f"{location}.assumptions")
    require_string_list(record.get("manualReview"), f"{location}.manualReview")


def detail_vector(value, location):
    value = require_object(value, location)
    normalized = {}
    for objective in OBJECTIVES:
        detail = require_object(value.get(objective), f"{location}.{objective}")
        try:
            normalized[objective] = normalize_level(
                detail.get("level"), f"{location}.{objective}.level"
            )
        except DerivationError as exc:
            raise ValidationError(str(exc)) from exc
        require_string(detail.get("rationale"), f"{location}.{objective}.rationale")
    return normalized


def maximum(vectors):
    rank = {"L": 0, "M": 1, "H": 2}
    return {
        objective: max(
            (vector[objective] for vector in vectors),
            key=lambda level: rank[level],
        )
        for objective in OBJECTIVES
    }


def validate(document):
    document = require_object(document, "document")
    forbidden = sorted(FORBIDDEN_TOP_LEVEL.intersection(document))
    if forbidden:
        raise ValidationError(
            "focused objectives artifact must not contain: " + ", ".join(forbidden)
        )
    if document.get("schemaVersion") != 1:
        raise ValidationError("schemaVersion must be 1")

    system = require_object(document.get("systemProfile"), "systemProfile")
    require_string(system.get("product"), "systemProfile.product")
    require_string(
        system.get("confirmedDescription"),
        "systemProfile.confirmedDescription",
    )
    validate_evidence_record(system, "systemProfile")
    system_detail = detail_vector(system.get("sso"), "systemProfile.sso")

    try:
        sso = normalize_vector(document.get("sso"), "sso")
        aso = normalize_vector(document.get("aso"), "aso")
    except DerivationError as exc:
        raise ValidationError(str(exc)) from exc
    if system_detail != sso:
        raise ValidationError("systemProfile.sso levels must equal top-level sso")

    profiles = document.get("agencyProfiles")
    if not isinstance(profiles, list):
        raise ValidationError("agencyProfiles must be a list")
    definite = []
    for index, profile in enumerate(profiles):
        location = f"agencyProfiles[{index}]"
        profile = require_object(profile, location)
        require_string(profile.get("agency"), f"{location}.agency")
        relationship = require_string(
            profile.get("relationship"), f"{location}.relationship"
        )
        if relationship not in RELATIONSHIPS:
            raise ValidationError(
                f"{location}.relationship must be definite or target"
            )
        validate_evidence_record(profile, location)
        profile_aso = detail_vector(profile.get("aso"), f"{location}.aso")
        if relationship == "definite":
            definite.append(profile_aso)

    expected_aso = maximum(definite) if definite else sso
    if aso != expected_aso:
        rule = (
            "per-objective maximum of definite agency profiles"
            if definite
            else "sso when no definite agency exists"
        )
        raise ValidationError(f"top-level aso must equal {rule}")

    agency_summary = require_object(
        document.get("agencyUseSummary"), "agencyUseSummary"
    )
    validate_evidence_record(agency_summary, "agencyUseSummary")
    require_string(agency_summary.get("rationale"), "agencyUseSummary.rationale")
    expected_basis = "definite-agencies" if definite else "sso-fallback"
    if agency_summary.get("basis") != expected_basis:
        raise ValidationError(
            f"agencyUseSummary.basis must be {expected_basis}"
        )
    if not definite:
        if agency_summary.get("confidence") != "low":
            raise ValidationError(
                "agencyUseSummary.confidence must be low for sso-fallback"
            )
        if not agency_summary.get("manualReview"):
            raise ValidationError(
                "agencyUseSummary.manualReview must be non-empty for sso-fallback"
            )

    class_prior = require_object(document.get("classPrior"), "classPrior")
    class_value = class_prior.get("class")
    if class_value not in CLASSES:
        raise ValidationError("classPrior.class must be A, B, C, D, or unknown")
    require_string(
        class_prior.get("authorization"),
        "classPrior.authorization",
    )
    if not isinstance(class_prior.get("divergences"), list):
        raise ValidationError("classPrior.divergences must be a list")

    expected_ceiling = derive_ceiling(sso, aso)
    actual_ceiling = require_object(
        document.get("securityRequirementsCeiling"),
        "securityRequirementsCeiling",
    )
    if actual_ceiling != expected_ceiling:
        raise ValidationError(
            "securityRequirementsCeiling must equal min(sso, aso) with matching "
            "wire and display values"
        )
    return document


def main():
    parser = argparse.ArgumentParser(
        description="Validate a focused security-objectives.json artifact."
    )
    parser.add_argument("objectives_json", help="security-objectives JSON")
    args = parser.parse_args()
    try:
        with open(args.objectives_json, "r", encoding="utf-8") as handle:
            document = json.load(handle)
        validate(document)
    except (
        OSError,
        json.JSONDecodeError,
        DerivationError,
        ValidationError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print("security-objectives.json: valid")
    return 0


if __name__ == "__main__":
    sys.exit(main())
