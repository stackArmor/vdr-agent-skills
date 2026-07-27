#!/usr/bin/env python3
"""Query the bundled NIST SP 800-60 Volume II Rev. 1 information catalog."""

import argparse
import json
import re
import sys
from pathlib import Path

DEFAULT_CATALOG = (
    Path(__file__).resolve().parent.parent
    / "references"
    / "nist-sp-800-60-v2r1-information-types.json"
)


def searchable_text(record):
    parts = [
        record["id"],
        record["name"],
        record["description"],
        json.dumps(record["taxonomy"]),
    ]
    for detail in (record.get("objectives") or {}).values():
        parts.extend(
            [
                detail.get("rationale") or "",
                detail.get("specialFactors") or "",
                detail.get("recommendation") or "",
            ]
        )
    return " ".join(parts).lower()


def search_score(record, query):
    phrase = query.strip().lower()
    terms = re.findall(r"[a-z0-9]+", phrase)
    if not terms:
        return 0
    name = record["name"].lower()
    description = record["description"].lower()
    haystack = searchable_text(record)
    if not all(term in haystack for term in terms):
        return 0
    score = sum(haystack.count(term) for term in terms)
    score += sum(8 for term in terms if term in name)
    score += sum(3 for term in terms if term in description)
    if phrase in name:
        score += 25
    elif phrase in haystack:
        score += 10
    return score


def select_records(catalog, args):
    records = catalog["informationTypes"]
    if args.identifier:
        wanted = {value.upper() for value in args.identifier}
        records = [record for record in records if record["id"].upper() in wanted]
    if args.appendix:
        records = [record for record in records if record["appendix"] == args.appendix]
    if args.impact:
        impact = [value.strip() for value in args.impact.upper().split(",")]
        if len(impact) != 3 or any(value not in {"L", "M", "H", "N/A", "-"} for value in impact):
            raise ValueError("--impact must be C,I,A using L, M, H, N/A, or -")
        records = [
            record
            for record in records
            if record["provisionalImpact"]
            and all(
                expected == "-"
                or record["provisionalImpact"][objective] == expected
                for objective, expected in zip(
                    ("confidentiality", "integrity", "availability"), impact
                )
            )
        ]
    if args.search:
        scored = [
            (search_score(record, args.search), record)
            for record in records
        ]
        records = [
            record
            for score, record in sorted(
                scored, key=lambda item: (-item[0], item[1]["id"])
            )
            if score
        ]
    else:
        records = sorted(records, key=lambda record: record["id"])
    return records[: args.limit]


def summarize(value, limit=240):
    value = re.sub(r"\s+", " ", value or "").strip()
    if len(value) <= limit:
        return value
    return value[: limit - 1].rstrip() + "…"


def render_text(records):
    for index, record in enumerate(records):
        if index:
            print()
        source = record["source"]
        print(
            f"{record['id']}  {record['name']}  "
            f"{record['impactVector'] or 'no standalone impact profile'}"
        )
        print(
            f"  source: PDF pp. {source['pdfPageStart']}-"
            f"{source['pdfPageEnd']} (document pp. "
            f"{source['documentPageStart']}-{source['documentPageEnd']})"
        )
        print(f"  description: {summarize(record['description'])}")
        factors = [
            f"{objective[0].upper()}: {summarize(detail['specialFactors'])}"
            for objective, detail in (record.get("objectives") or {}).items()
            if detail.get("specialFactors")
        ]
        if factors:
            print("  special factors:")
            for factor in factors:
                print(f"    - {factor}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", default=str(DEFAULT_CATALOG))
    parser.add_argument("--id", dest="identifier", action="append")
    parser.add_argument("--search", help="all search terms must match")
    parser.add_argument("--appendix", choices=("C", "D"))
    parser.add_argument(
        "--impact",
        help="exact C,I,A profile; use - as a wildcard (example: L,H,-)",
    )
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args()
    if not any((args.identifier, args.search, args.appendix, args.impact)):
        parser.error("provide --id, --search, --appendix, or --impact")
    if args.limit < 1:
        parser.error("--limit must be positive")
    try:
        catalog = json.loads(Path(args.catalog).read_text(encoding="utf-8"))
        records = select_records(catalog, args)
    except (OSError, json.JSONDecodeError, KeyError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if not records:
        print("no matching NIST SP 800-60 information types", file=sys.stderr)
        return 1
    if args.as_json:
        json.dump(records, sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write("\n")
    else:
        render_text(records)
    return 0


if __name__ == "__main__":
    sys.exit(main())
