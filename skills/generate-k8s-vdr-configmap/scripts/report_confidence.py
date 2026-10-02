#!/usr/bin/env python3
"""Validate assignment confidence metadata and print manual-review items."""

import argparse
import json
import sys


CONFIDENCE = {"high", "medium", "low"}
STATUS = {"operator-confirmed", "agent-inferred"}


class CoverageError(ValueError):
    """Raised when the assignment coverage document is incomplete."""


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
        raise CoverageError(
            f"{location}.confidence must be high, medium, or low"
        )
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


def vector_text(value, location):
    if isinstance(value, str) and value.strip():
        result = value.strip().upper()
        if len(result) == 5 and result[1] == result[3] == "/":
            if all(result[index] in {"H", "M", "L"} for index in (0, 2, 4)):
                return result
        raise CoverageError(f"{location}.vector string must look like H/M/L")
    if isinstance(value, dict):
        try:
            values = [str(value[key]).upper() for key in ("cr", "ir", "ar")]
        except KeyError as exc:
            raise CoverageError(
                f"{location}.vector object must contain cr, ir, and ar"
            ) from exc
        if any(value not in {"H", "M", "L"} for value in values):
            raise CoverageError(f"{location}.vector values must be H, M, or L")
        return "/".join(values)
    raise CoverageError(
        f"{location}.vector must be an H/M/L string or cr/ir/ar object"
    )


def normalize_assignment(record, index):
    location = f"assignments[{index}]"
    if not isinstance(record, dict):
        raise CoverageError(f"{location} must be an object")
    namespace = require_string(record, "namespace", location)
    kind = require_string(record, "kind", location)
    name = require_string(record, "name", location)
    trace = require_string(record, "trace", location)
    vector = vector_text(record.get("vector"), location)
    require_string(record, "resolutionSource", location)
    status = require_string(record, "status", location)
    if status not in STATUS:
        raise CoverageError(
            f"{location}.status must be operator-confirmed or agent-inferred"
        )
    evidence = require_string(record, "evidence", location)
    assumptions = require_string_list(record, "assumptions", location)
    confidence, reviews = require_confidence(record, location)
    return {
        "identity": f"{namespace}/{kind}/{name}",
        "selected": f"{trace} -> {vector}",
        "status": status,
        "confidence": confidence,
        "evidence": evidence,
        "assumptions": assumptions,
        "reviews": reviews,
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


def load_coverage(path):
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
        normalize_assignment(record, index)
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


def print_report(records):
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


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Validate assignment-coverage confidence metadata and print every "
            "medium- or low-confidence manual-review item."
        )
    )
    parser.add_argument("coverage", help="path to assignment-coverage.json")
    args = parser.parse_args()
    try:
        assignments, configuration = load_coverage(args.coverage)
        print_report(assignments + configuration)
    except CoverageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
