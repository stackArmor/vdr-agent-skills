#!/usr/bin/env python3
"""Validate security-requirements coverage artifacts and print the review report.

Usage: report_confidence.py <assignment-coverage.json> <security-objectives.json>

Checks the confidence contract, the envelope math
(final = min(component objective, envelope) unless a recorded breakout
applies), breakout legitimacy, capped-flag accuracy, and label/vector
consistency. Prints every medium/low-confidence decision, every capped
component, and every breakout. Exit 0 when valid, 2 when invalid.

This gate never reads the generated ConfigMap and never prints the
humanReviewCompleted attestation marker.
"""

import argparse
import json
import re
import sys

CONFIDENCE = {"high", "medium", "low"}
STATUS = {"operator-confirmed", "agent-inferred"}
RANK = {"L": 0, "M": 1, "H": 2}
OBJECTIVES = ("c", "i", "a")
OBJECTIVE_NAMES = {"c": "CR", "i": "IR", "a": "AR"}
LABEL_RE = re.compile(r"^cr-([lmh])_ir-([lmh])_ar-([lmh])$")
BREAKOUT_CATEGORIES = {
    "agency-endpoint-delivery",
    "cross-system-trust-anchor",
    "shared-csp-infrastructure",
}
CLASSES = {"A", "B", "C", "D"}
SCOPES = {"cluster", "namespace"}
RELATIONSHIPS = {"definite", "target"}


class CoverageError(ValueError):
    """Raised when an artifact document is incomplete or inconsistent."""


def require_string(record, field, location):
    value = record.get(field)
    if not isinstance(value, str) or not value.strip():
        raise CoverageError(f"{location}.{field} must be a non-empty string")
    return value.strip()


def require_string_list(record, field, location):
    value = record.get(field)
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item.strip() for item in value
    ):
        raise CoverageError(f"{location}.{field} must be a list of non-empty strings")
    return [item.strip() for item in value]


def require_confidence(record, location):
    confidence = require_string(record, "confidence", location).lower()
    if confidence not in CONFIDENCE:
        raise CoverageError(f"{location}.confidence must be high, medium, or low")
    reviews = require_string_list(record, "manualReview", location)
    if confidence == "high" and reviews:
        raise CoverageError(
            f"{location}.manualReview must be empty when confidence is high"
        )
    if confidence != "high" and not reviews:
        raise CoverageError(
            f"{location}.manualReview needs at least one item when confidence "
            f"is {confidence}"
        )
    return confidence, reviews


def require_status(record, location):
    status = require_string(record, "status", location)
    if status not in STATUS:
        raise CoverageError(
            f"{location}.status must be operator-confirmed or agent-inferred"
        )
    return status


def require_level(value, location):
    if isinstance(value, str) and value.strip().upper() in RANK:
        return value.strip().upper()
    raise CoverageError(f"{location} must be H, M, or L")


def require_vector(mapping, location):
    if not isinstance(mapping, dict):
        raise CoverageError(f"{location} must be an object with c, i, a")
    return {o: require_level(mapping.get(o), f"{location}.{o}") for o in OBJECTIVES}


def require_objective_details(mapping, location, text_field):
    if not isinstance(mapping, dict):
        raise CoverageError(f"{location} must be an object with c, i, a")
    details = {}
    for objective in OBJECTIVES:
        entry = mapping.get(objective)
        if not isinstance(entry, dict):
            raise CoverageError(f"{location}.{objective} must be an object")
        details[objective] = {
            "level": require_level(entry.get("level"), f"{location}.{objective}.level"),
            text_field: require_string(entry, text_field, f"{location}.{objective}"),
        }
    return details


def vector_text(value, location):
    if isinstance(value, str) and value.strip():
        result = value.strip().upper()
        if len(result) == 5 and result[1] == result[3] == "/":
            if all(result[index] in RANK for index in (0, 2, 4)):
                return result
        raise CoverageError(f"{location}.vector string must look like H/M/L")
    if isinstance(value, dict):
        try:
            values = [str(value[key]).upper() for key in ("cr", "ir", "ar")]
        except KeyError as exc:
            raise CoverageError(
                f"{location}.vector object must contain cr, ir, and ar"
            ) from exc
        if any(item not in RANK for item in values):
            raise CoverageError(f"{location}.vector values must be H, M, or L")
        return "/".join(values)
    raise CoverageError(f"{location}.vector must be an H/M/L string or cr/ir/ar object")


def vector_from_text(text):
    return {"c": text[0], "i": text[2], "a": text[4]}


def normalize_breakouts(record, location):
    raw = record.get("breakouts", [])
    if not isinstance(raw, list):
        raise CoverageError(f"{location}.breakouts must be a list")
    breakouts = []
    seen = set()
    for index, entry in enumerate(raw):
        entry_location = f"{location}.breakouts[{index}]"
        if not isinstance(entry, dict):
            raise CoverageError(f"{entry_location} must be an object")
        objective = entry.get("objective")
        if objective not in OBJECTIVES:
            raise CoverageError(f"{entry_location}.objective must be c, i, or a")
        if objective in seen:
            raise CoverageError(f"{entry_location} duplicates objective {objective!r}")
        seen.add(objective)
        category = entry.get("category")
        if category not in BREAKOUT_CATEGORIES:
            raise CoverageError(
                f"{entry_location}.category must be one of: "
                + ", ".join(sorted(BREAKOUT_CATEGORIES))
            )
        justification = require_string(entry, "justification", entry_location)
        breakouts.append({
            "objective": objective,
            "category": category,
            "justification": justification,
        })
    return breakouts


def normalize_assignment(record, index, envelope):
    location = f"assignments[{index}]"
    if not isinstance(record, dict):
        raise CoverageError(f"{location} must be an object")
    namespace = require_string(record, "namespace", location)
    kind = require_string(record, "kind", location)
    name = require_string(record, "name", location)
    details = require_objective_details(
        record.get("componentObjectives"), f"{location}.componentObjectives", "reason"
    )
    cso = {objective: details[objective]["level"] for objective in OBJECTIVES}
    final_text = vector_text(record.get("vector"), location)
    final = vector_from_text(final_text)
    label = require_string(record, "securityRequirements", location)
    match = LABEL_RE.match(label)
    if not match:
        raise CoverageError(
            f"{location}.securityRequirements must match cr-[lmh]_ir-[lmh]_ar-[lmh]"
        )
    encoded = {
        objective: match.group(position + 1).upper()
        for position, objective in enumerate(OBJECTIVES)
    }
    if encoded != final:
        raise CoverageError(
            f"{location}.securityRequirements does not encode vector {final_text}"
        )
    breakouts = normalize_breakouts(record, location)
    breakout_objectives = {entry["objective"] for entry in breakouts}
    capped = record.get("capped")
    if not isinstance(capped, dict) or any(
        not isinstance(capped.get(objective), bool) for objective in OBJECTIVES
    ):
        raise CoverageError(f"{location}.capped must map c, i, a to booleans")
    require_string(record, "resolutionSource", location)
    status = require_status(record, location)
    evidence = require_string(record, "evidence", location)
    assumptions = require_string_list(record, "assumptions", location)
    confidence, reviews = require_confidence(record, location)
    if breakouts and confidence == "high":
        raise CoverageError(
            f"{location} declares a breakout and must not be high confidence"
        )
    for objective in OBJECTIVES:
        if objective in breakout_objectives:
            if RANK[cso[objective]] <= RANK[envelope[objective]]:
                raise CoverageError(
                    f"{location} declares a breakout on {objective!r} but the "
                    f"component objective does not exceed the envelope"
                )
            expected = cso[objective]
        elif RANK[cso[objective]] <= RANK[envelope[objective]]:
            expected = cso[objective]
        else:
            expected = envelope[objective]
        if final[objective] != expected:
            raise CoverageError(
                f"{location}.vector {OBJECTIVE_NAMES[objective]} must be "
                f"{expected}: min(component objective, envelope) unless a "
                f"recorded breakout applies"
            )
        expected_capped = RANK[final[objective]] < RANK[cso[objective]]
        if capped[objective] != expected_capped:
            raise CoverageError(
                f"{location}.capped.{objective} must be "
                f"{str(expected_capped).lower()}"
            )
    caps = [
        f"{OBJECTIVE_NAMES[objective]} {cso[objective]}->{final[objective]}"
        for objective in OBJECTIVES
        if capped[objective]
    ]
    return {
        "identity": f"{namespace}/{kind}/{name}",
        "selected": f"{label} -> {final_text}",
        "status": status,
        "confidence": confidence,
        "evidence": evidence,
        "assumptions": assumptions,
        "reviews": reviews,
        "caps": caps,
        "breakouts": breakouts,
        "key": (namespace, kind, name),
    }


def normalize_configuration(record, index):
    location = f"configurationAssumptions[{index}]"
    if not isinstance(record, dict):
        raise CoverageError(f"{location} must be an object")
    field = require_string(record, "field", location)
    if "value" not in record:
        raise CoverageError(f"{location}.value is required")
    value = json.dumps(record["value"], sort_keys=True)
    evidence = require_string(record, "evidence", location)
    assumptions = require_string_list(record, "assumptions", location)
    confidence, reviews = require_confidence(record, location)
    return {
        "identity": f"configuration/{field}",
        "selected": value,
        "status": "agent-inferred",
        "confidence": confidence,
        "evidence": evidence,
        "assumptions": assumptions,
        "reviews": reviews,
    }


def profile_record(record, identity, selected, location):
    status = require_status(record, location)
    confidence, reviews = require_confidence(record, location)
    assumptions = require_string_list(record, "assumptions", location)
    return {
        "identity": identity,
        "selected": selected,
        "status": status,
        "confidence": confidence,
        "evidence": require_string(record, "confirmedDescription", location)
        if "confirmedDescription" in record
        else require_string(record, "justification", location)
        if "justification" in record
        else "recorded profile",
        "assumptions": assumptions,
        "reviews": reviews,
    }


def load_objectives(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise CoverageError(f"cannot read objectives JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise CoverageError("objectives document must be a JSON object")

    sso = require_vector(document.get("sso"), "objectives.sso")
    aso = require_vector(document.get("aso"), "objectives.aso")
    envelope = require_vector(document.get("envelope"), "objectives.envelope")
    for objective in OBJECTIVES:
        expected = (
            sso[objective]
            if RANK[sso[objective]] <= RANK[aso[objective]]
            else aso[objective]
        )
        if envelope[objective] != expected:
            raise CoverageError(
                f"objectives.envelope.{objective} must be min(sso, aso) = {expected}"
            )
    if document.get("ceilingMode") != "semi-hard":
        raise CoverageError('objectives.ceilingMode must be "semi-hard"')

    records = []

    system_profile = document.get("systemProfile")
    if not isinstance(system_profile, dict):
        raise CoverageError("objectives.systemProfile must be an object")
    product = require_string(system_profile, "product", "objectives.systemProfile")
    require_string(system_profile, "confirmedDescription", "objectives.systemProfile")
    system_details = require_objective_details(
        system_profile.get("sso"), "objectives.systemProfile.sso", "rationale"
    )
    for objective in OBJECTIVES:
        if system_details[objective]["level"] != sso[objective]:
            raise CoverageError(
                f"objectives.systemProfile.sso.{objective} must match "
                f"objectives.sso ({sso[objective]})"
            )
    records.append(profile_record(
        system_profile, f"system-profile/{product}",
        "SSO " + "/".join(sso[o] for o in OBJECTIVES),
        "objectives.systemProfile",
    ))

    raw_profiles = document.get("agencyProfiles", [])
    if not isinstance(raw_profiles, list):
        raise CoverageError("objectives.agencyProfiles must be a list")
    definite_levels = {objective: [] for objective in OBJECTIVES}
    for index, profile in enumerate(raw_profiles):
        location = f"objectives.agencyProfiles[{index}]"
        if not isinstance(profile, dict):
            raise CoverageError(f"{location} must be an object")
        agency = require_string(profile, "agency", location)
        relationship = require_string(profile, "relationship", location)
        if relationship not in RELATIONSHIPS:
            raise CoverageError(f"{location}.relationship must be definite or target")
        details = require_objective_details(
            profile.get("aso"), f"{location}.aso", "rationale"
        )
        if relationship == "definite":
            for objective in OBJECTIVES:
                definite_levels[objective].append(details[objective]["level"])
        overlays = profile.get("overlays", [])
        if not isinstance(overlays, list):
            raise CoverageError(f"{location}.overlays must be a list")
        for overlay_index, overlay in enumerate(overlays):
            overlay_location = f"{location}.overlays[{overlay_index}]"
            if not isinstance(overlay, dict):
                raise CoverageError(f"{overlay_location} must be an object")
            require_string(overlay, "name", overlay_location)
            if not isinstance(overlay.get("statuteGrounded"), bool):
                raise CoverageError(
                    f"{overlay_location}.statuteGrounded must be a boolean"
                )
        profile.setdefault("justification", "recorded agency profile")
        records.append(profile_record(
            profile, f"agency-profile/{agency}",
            "ASO " + "/".join(details[o]["level"] for o in OBJECTIVES)
            + f" ({relationship})",
            location,
        ))
    if any(definite_levels[objective] for objective in OBJECTIVES):
        for objective in OBJECTIVES:
            expected = max(definite_levels[objective], key=lambda level: RANK[level])
            if aso[objective] != expected:
                raise CoverageError(
                    f"objectives.aso.{objective} must equal the per-objective max "
                    f"over definite agency profiles ({expected})"
                )

    class_prior = document.get("classPrior")
    if not isinstance(class_prior, dict):
        raise CoverageError("objectives.classPrior must be an object")
    prior_class = require_string(class_prior, "class", "objectives.classPrior").upper()
    if prior_class not in CLASSES:
        raise CoverageError("objectives.classPrior.class must be A, B, C, or D")
    divergences = class_prior.get("divergences", [])
    if not isinstance(divergences, list):
        raise CoverageError("objectives.classPrior.divergences must be a list")
    for index, divergence in enumerate(divergences):
        location = f"objectives.classPrior.divergences[{index}]"
        if not isinstance(divergence, dict):
            raise CoverageError(f"{location} must be an object")
        if divergence.get("objective") not in OBJECTIVES:
            raise CoverageError(f"{location}.objective must be c, i, or a")
        require_level(divergence.get("estimate"), f"{location}.estimate")
        require_level(divergence.get("prior"), f"{location}.prior")
        require_string(divergence, "resolution", location)
        require_string(divergence, "detail", location)

    determination = document.get("multiAgencyDetermination")
    if not isinstance(determination, dict):
        raise CoverageError("objectives.multiAgencyDetermination must be an object")
    scope = require_string(determination, "scope", "objectives.multiAgencyDetermination")
    if scope not in SCOPES:
        raise CoverageError(
            "objectives.multiAgencyDetermination.scope must be cluster or namespace"
        )
    if not isinstance(determination.get("clusterDefault"), bool):
        raise CoverageError(
            "objectives.multiAgencyDetermination.clusterDefault must be a boolean"
        )
    require_string(determination, "justification", "objectives.multiAgencyDetermination")
    if scope == "namespace":
        namespaces = determination.get("multiAgencyNamespaces")
        if (
            not isinstance(namespaces, list)
            or not namespaces
            or any(not isinstance(item, str) or not item.strip() for item in namespaces)
        ):
            raise CoverageError(
                "objectives.multiAgencyDetermination.multiAgencyNamespaces must "
                "be a non-empty list of non-empty strings when scope is namespace"
            )
    records.append(profile_record(
        determination, "configuration/multiAgency",
        f"scope={scope} clusterDefault={determination['clusterDefault']}",
        "objectives.multiAgencyDetermination",
    ))

    return envelope, records


def load_coverage(path, envelope):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise CoverageError(f"cannot read coverage JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise CoverageError("coverage document must be a JSON object")

    require_string(document, "context", "coverage")
    inventory_total = document.get("inventoryTotal")
    if not isinstance(inventory_total, int) or inventory_total < 0:
        raise CoverageError("inventoryTotal must be a non-negative integer")

    raw_assignments = document.get("assignments")
    if not isinstance(raw_assignments, list):
        raise CoverageError("assignments must be a list")
    assignments = [
        normalize_assignment(record, index, envelope)
        for index, record in enumerate(raw_assignments)
    ]
    if len(assignments) != inventory_total:
        raise CoverageError(
            f"inventoryTotal is {inventory_total}, but assignments has "
            f"{len(assignments)} entries"
        )
    keys = [record["key"] for record in assignments]
    if len(keys) != len(set(keys)):
        raise CoverageError("assignments contains duplicate namespace/kind/name entries")

    raw_configuration = document.get("configurationAssumptions", [])
    if not isinstance(raw_configuration, list):
        raise CoverageError("configurationAssumptions must be a list")
    configuration = [
        normalize_configuration(record, index)
        for index, record in enumerate(raw_configuration)
    ]
    return assignments, configuration


def print_review(records):
    review = [record for record in records if record["confidence"] != "high"]
    order = {"low": 0, "medium": 1}
    review.sort(key=lambda record: (order[record["confidence"]], record["identity"]))
    print(f"NON-HIGH-CONFIDENCE MANUAL REVIEW ({len(review)})")
    if not review:
        print("- none")
        return
    for record in review:
        print(
            f"- [{record['confidence'].upper()}] {record['identity']} "
            f"({record['status']})"
        )
        print(f"  Selected: {record['selected']}")
        print(f"  Evidence: {record['evidence']}")
        if record["assumptions"]:
            print(f"  Assumptions: {'; '.join(record['assumptions'])}")
        for item in record["reviews"]:
            print(f"  Review: {item}")


def print_caps(assignments):
    capped = [record for record in assignments if record["caps"]]
    print(f"CAPPED COMPONENTS ({len(capped)})")
    if not capped:
        print("- none")
        return
    for record in capped:
        print(f"- {record['identity']}: {', '.join(record['caps'])}")


def print_breakouts(assignments):
    with_breakouts = [record for record in assignments if record["breakouts"]]
    total = sum(len(record["breakouts"]) for record in with_breakouts)
    print(f"BREAKOUTS ({total})")
    if not with_breakouts:
        print("- none")
        return
    for record in with_breakouts:
        for entry in record["breakouts"]:
            print(
                f"- {record['identity']} [{OBJECTIVE_NAMES[entry['objective']]}] "
                f"{entry['category']}: {entry['justification']}"
            )


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Validate security-requirements coverage artifacts and print the "
            "manual-review, capped-component, and breakout report."
        )
    )
    parser.add_argument("coverage", help="path to assignment-coverage.json")
    parser.add_argument("objectives", help="path to security-objectives.json")
    args = parser.parse_args()
    try:
        envelope, objective_records = load_objectives(args.objectives)
        assignments, configuration = load_coverage(args.coverage, envelope)
        print_review(assignments + configuration + objective_records)
        print_caps(assignments)
        print_breakouts(assignments)
    except CoverageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
