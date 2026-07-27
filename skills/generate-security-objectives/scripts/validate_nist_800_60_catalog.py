#!/usr/bin/env python3
"""Validate the bundled NIST SP 800-60 Volume II Rev. 1 JSON catalog."""

import argparse
import json
import re
import sys
from pathlib import Path

EXPECTED_SHA256 = (
    "0b4c5128b39a90f1bb1c1004f22bfe1fa34110222da740011f86c050983dc8de"
)
OBJECTIVES = ("confidentiality", "integrity", "availability")
IMPACTS = {"L", "M", "H", "N/A"}
EXPECTED_SAMPLES = {
    "C.2.1.1": ("Corrective Action", "C:L/I:L/A:L"),
    "C.2.4.1": ("Contingency Planning", "C:M/I:M/A:M"),
    "C.3.5.9": ("Information Sharing", "C:N/A/I:N/A/A:N/A"),
    "D.3": (
        "Intelligence Operations (Unclassified Domestic Intelligence)",
        "C:H/I:H/A:H",
    ),
    "D.5.3": ("Global Trade", "C:H/I:H/A:H"),
    "D.14.4": ("Health Care Delivery Services", "C:L/I:H/A:L"),
    "D.26.1": ("Military Operations", None),
    "D.26.2": ("Civilian Operations", None),
}


class CatalogError(ValueError):
    """Raised when the catalog violates its source contract."""


def require(condition, message):
    if not condition:
        raise CatalogError(message)


def validate(catalog):
    require(isinstance(catalog, dict), "catalog must be an object")
    require(catalog.get("schemaVersion") == 1, "schemaVersion must be 1")
    publication = catalog.get("publication")
    require(isinstance(publication, dict), "publication must be an object")
    require(
        publication.get("sha256") == EXPECTED_SHA256,
        "publication SHA-256 does not match the pinned official PDF",
    )
    require(publication.get("pageCount") == 304, "publication pageCount must be 304")
    authority = catalog.get("authority")
    require(
        isinstance(authority, dict) and authority.get("role") == "informative",
        "catalog authority must be informative",
    )
    require(
        isinstance(authority.get("caveats"), list) and authority["caveats"],
        "authority caveats must be non-empty",
    )

    records = catalog.get("informationTypes")
    require(isinstance(records, list), "informationTypes must be a list")
    require(len(records) == 170, "informationTypes must contain 170 records")
    seen_ids = set()
    categorized = 0
    appendix_counts = {"C": 0, "D": 0}
    by_id = {}
    for index, record in enumerate(records):
        location = f"informationTypes[{index}]"
        require(isinstance(record, dict), f"{location} must be an object")
        identifier = record.get("id")
        require(
            isinstance(identifier, str)
            and re.fullmatch(r"(?:C\.\d+\.\d+\.\d+|D\.\d+(?:\.\d+)?)", identifier),
            f"{location}.id is invalid",
        )
        require(identifier not in seen_ids, f"duplicate information type {identifier}")
        seen_ids.add(identifier)
        by_id[identifier] = record
        for key in ("slug", "name", "description"):
            require(
                isinstance(record.get(key), str) and record[key].strip(),
                f"{identifier}.{key} must be non-empty",
            )
        appendix = record.get("appendix")
        require(appendix in appendix_counts, f"{identifier}.appendix must be C or D")
        require(identifier.startswith(appendix + "."), f"{identifier}.appendix mismatch")
        appendix_counts[appendix] += 1
        source = record.get("source")
        require(isinstance(source, dict), f"{identifier}.source must be an object")
        require(source.get("section") == identifier, f"{identifier}.source.section mismatch")
        start = source.get("pdfPageStart")
        end = source.get("pdfPageEnd")
        require(
            isinstance(start, int) and isinstance(end, int) and 1 <= start <= end <= 304,
            f"{identifier} has invalid PDF pages",
        )
        require(
            source.get("documentPageStart") == start - 25
            and source.get("documentPageEnd") == end - 25,
            f"{identifier} document pages do not map to PDF pages",
        )

        vector = record.get("provisionalImpact")
        if vector is None:
            require(
                identifier in {"D.26.1", "D.26.2"},
                f"{identifier} unexpectedly lacks an impact profile",
            )
            require(record.get("impactVector") is None, f"{identifier} vector must be null")
            require(record.get("objectives") is None, f"{identifier} objectives must be null")
            continue
        categorized += 1
        require(
            isinstance(vector, dict) and set(vector) == set(OBJECTIVES),
            f"{identifier}.provisionalImpact must contain C, I, A",
        )
        require(
            all(value in IMPACTS for value in vector.values()),
            f"{identifier} has an invalid impact",
        )
        expected_display = "C:{}/I:{}/A:{}".format(
            vector["confidentiality"],
            vector["integrity"],
            vector["availability"],
        )
        require(
            record.get("impactVector") == expected_display,
            f"{identifier}.impactVector mismatch",
        )
        if set(vector.values()) == {"N/A"}:
            require(identifier == "C.3.5.9", "only Information Sharing may be N/A")
            require(record.get("objectives") is None, f"{identifier} objectives must be null")
        else:
            objectives = record.get("objectives")
            require(
                isinstance(objectives, dict) and set(objectives) == set(OBJECTIVES),
                f"{identifier}.objectives must contain C, I, A",
            )
            for objective, detail in objectives.items():
                require(
                    detail.get("recommendedImpact") == vector[objective],
                    f"{identifier}.{objective} recommendation mismatch",
                )
                require(
                    isinstance(detail.get("rationale"), str)
                    and detail["rationale"].strip(),
                    f"{identifier}.{objective}.rationale must be non-empty",
                )
                require(
                    isinstance(detail.get("recommendation"), str)
                    and detail["recommendation"].strip(),
                    f"{identifier}.{objective}.recommendation must be non-empty",
                )

    require(categorized == 168, "catalog must contain 168 categorized records")
    require(appendix_counts == {"C": 77, "D": 93}, "appendix counts are incorrect")
    statistics = catalog.get("statistics")
    require(
        statistics
        == {
            "recordCount": 170,
            "categorizedRecordCount": 168,
            "notAssignedRecordCount": 2,
            "managementAndSupportRecordCount": 77,
            "missionBasedRecordCount": 93,
        },
        "statistics do not match catalog contents",
    )
    for identifier, (name, vector) in EXPECTED_SAMPLES.items():
        require(identifier in by_id, f"missing sample record {identifier}")
        require(by_id[identifier]["name"] == name, f"{identifier} name mismatch")
        require(by_id[identifier]["impactVector"] == vector, f"{identifier} impact mismatch")
    return catalog


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("catalog_json")
    args = parser.parse_args()
    try:
        catalog = json.loads(Path(args.catalog_json).read_text(encoding="utf-8"))
        validate(catalog)
    except (OSError, json.JSONDecodeError, CatalogError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print("NIST SP 800-60 catalog: valid (170 records; 168 categorized)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
