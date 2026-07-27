#!/usr/bin/env python3
"""Convert NIST SP 800-60 Volume II Revision 1 text into a JSON catalog.

The input text must be produced from the official PDF with:

    pdftotext -layout nistspecialpublication800-60v2r1.pdf source.txt

This extractor intentionally targets that publication and fails closed when
the expected record and categorization counts change.
"""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

SOURCE_URL = (
    "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/"
    "nistspecialpublication800-60v2r1.pdf"
)
EXPECTED_SHA256 = (
    "0b4c5128b39a90f1bb1c1004f22bfe1fa34110222da740011f86c050983dc8de"
)
OBJECTIVES = ("confidentiality", "integrity", "availability")
IMPACT_CODES = {"low": "L", "moderate": "M", "high": "H", "n/a": "N/A"}

BUSINESS_AREAS = {
    "C.2": "Services Delivery Support Information",
    "C.3": "Government Resource Management Information",
}
LINES_OF_BUSINESS = {
    "C.2.1": "Controls and Oversight",
    "C.2.2": "Regulatory Development",
    "C.2.3": "Planning and Budgeting",
    "C.2.4": "Internal Risk Management and Mitigation",
    "C.2.5": "Revenue Collection",
    "C.2.6": "Public Affairs",
    "C.2.7": "Legislative Relations",
    "C.2.8": "General Government",
    "C.3.1": "Administrative Management",
    "C.3.2": "Financial Management",
    "C.3.3": "Human Resource Management",
    "C.3.4": "Supply Chain Management",
    "C.3.5": "Information and Technology Management",
}
MISSION_AREAS = {
    "D.1": "Defense and National Security",
    "D.2": "Homeland Security",
    "D.3": "Intelligence Operations",
    "D.4": "Disaster Management",
    "D.5": "International Affairs and Commerce",
    "D.6": "Natural Resources",
    "D.7": "Energy",
    "D.8": "Environmental Management",
    "D.9": "Economic Development",
    "D.10": "Community and Social Services",
    "D.11": "Transportation",
    "D.12": "Education",
    "D.13": "Workforce Management",
    "D.14": "Health",
    "D.15": "Income Security",
    "D.16": "Law Enforcement",
    "D.17": "Litigation and Judicial Activities",
    "D.18": "Federal Correctional Activities",
    "D.19": "General Sciences and Innovation",
    "D.20": "Knowledge Creation and Management",
    "D.21": "Regulatory Compliance and Enforcement",
    "D.22": "Public Goods Creation and Management",
    "D.23": "Federal Financial Assistance",
    "D.24": "Credit and Insurance",
    "D.25": "Transfers to State/Local Governments",
    "D.26": "Direct Services for Citizens",
}


class ExtractionError(ValueError):
    """Raised when the source no longer matches the expected publication."""


def normalize_space(value):
    value = value.replace("\u2019", "'").replace("\u201c", '"').replace("\u201d", '"')
    value = re.sub(r"(?<=\w)-\s*\n\s*(?=\w)", "", value)
    value = re.sub(r"\s+", " ", value)
    return value.strip()


def slugify(value):
    value = value.lower().replace("&", " and ")
    value = re.sub(r"[^a-z0-9]+", "-", value)
    return value.strip("-")


def strip_page_material(value):
    """Remove page numbers and extracted footnotes without changing prose."""

    # Footnotes in this publication begin with a standalone marker and end at
    # a page break. Page numbers alone are removed by the second expression.
    value = re.sub(
        r"(?ms)^[ \t]*(?:1[0-9]|[2-9])[ \t]*\n"
        r"(?=[ \t]*[A-Za-z(\[]).*?\f",
        "\f",
        value,
    )
    value = re.sub(r"(?m)^[ \t]*\d{1,3}[ \t]*$", "", value)
    value = re.sub(
        r"(?is)\[\s*This Page Intentionally Left Blank\s*\]",
        "",
        value,
    )
    return value


def record_headings(text):
    """Return detailed Appendix C/D headings plus the special D.3 record."""

    candidates = []
    pattern = re.compile(
        r"(?m)^\f?(?P<id>C\.\d+\.\d+\.\d+|D\.\d+\.\d+)"
        r"[ \t]+(?P<title>[^\n]+)"
    )
    for match in pattern.finditer(text):
        identifier = match.group("id")
        title_parts = [match.group("title").strip()]
        end = match.end()
        while "Information Type" not in " ".join(title_parts):
            next_line_end = text.find("\n", end + 1)
            if next_line_end < 0:
                break
            next_line = text[end + 1 : next_line_end].strip()
            if not next_line:
                break
            title_parts.append(next_line)
            end = next_line_end
        while "(".join(title_parts).count("(") > ")".join(title_parts).count(")"):
            next_line_end = text.find("\n", end + 1)
            if next_line_end < 0:
                break
            next_line = text[end + 1 : next_line_end].strip()
            if not next_line:
                break
            title_parts.append(next_line)
            end = next_line_end
        title = normalize_space(" ".join(title_parts))
        if "Information Type" not in title:
            continue
        candidates.append(
            {
                "id": identifier,
                "title": title,
                "start": match.start(),
                "bodyStart": end,
            }
        )

    # The unclassified domestic-intelligence recommendation is attached to
    # the D.3 mission-area heading rather than a D.x.y information-type ID.
    d3_matches = list(
        re.finditer(r"(?m)^\f?D\.3 Intelligence Operations[ \t]*$", text)
    )
    if not d3_matches:
        raise ExtractionError("could not locate detailed D.3 section")
    d3 = d3_matches[-1]
    candidates.append(
        {
            "id": "D.3",
            "title": "Intelligence Operations (Unclassified Domestic Intelligence)",
            "start": d3.start(),
            "bodyStart": d3.end(),
        }
    )

    # Exclude table-of-contents matches by retaining only headings in the
    # detailed appendices, where a section body or delivery-mechanism text
    # follows. The final occurrence wins if a title appeared earlier.
    by_id = {}
    for candidate in candidates:
        if candidate["start"] > text.rfind("APPENDIX C:") - 1:
            by_id[candidate["id"]] = candidate
    result = sorted(by_id.values(), key=lambda item: item["start"])
    appendix_d = text.rfind("APPENDIX D:")
    appendix_e = text.rfind("APPENDIX E:")
    for index, item in enumerate(result):
        item["end"] = (
            result[index + 1]["start"] if index + 1 < len(result) else len(text)
        )
        if item["id"].startswith("C.") and appendix_d > item["bodyStart"]:
            item["end"] = min(item["end"], appendix_d)
        if item["id"].startswith("D.") and appendix_e > item["bodyStart"]:
            item["end"] = min(item["end"], appendix_e)

        # End the previous information type before a new business/mission-area
        # introduction. Otherwise that introduction becomes part of the final
        # objective recommendation in the preceding record.
        boundary = re.search(
            r"(?m)^\f?(?:C\.\d+(?:\.\d+)?|D\.\d+)[ \t]+[A-Z][^\n]*$",
            text[item["bodyStart"] : item["end"]],
        )
        if boundary:
            item["end"] = item["bodyStart"] + boundary.start()
    return result


def clean_name(title):
    title = re.sub(r"\s+Information(?: Information)? Type\b", "", title)
    return normalize_space(title)


def security_category(chunk):
    match = re.search(
        r"Security Category\s*=\s*\{.*?\}", chunk, flags=re.IGNORECASE | re.DOTALL
    )
    if not match:
        return None, None, None
    statement = normalize_space(match.group(0))
    vector = {}
    for objective in OBJECTIVES:
        impact_match = re.search(
            rf"\({objective},\s*(Low|Moderate|High|N/A)",
            statement,
            flags=re.IGNORECASE,
        )
        if not impact_match:
            raise ExtractionError(f"malformed {objective} category: {statement}")
        vector[objective] = IMPACT_CODES[impact_match.group(1).lower()]
    return vector, statement, match


def objective_details(chunk, category_match, vector):
    if not category_match or not vector:
        return None
    if set(vector.values()) == {"N/A"}:
        return None
    section = strip_page_material(chunk[category_match.end() :])
    headings = []
    for objective in OBJECTIVES:
        match = re.search(
            rf"(?m)^[ \t\f]*{objective.title()}[ \t]*$", section,
        )
        if not match:
            raise ExtractionError(f"missing {objective} discussion")
        headings.append((objective, match))

    result = {}
    for index, (objective, heading) in enumerate(headings):
        end = headings[index + 1][1].start() if index + 1 < len(headings) else len(section)
        body = section[heading.end() : end]
        special_matches = list(re.finditer(
            r"Special Factors Affecting "
            r"(?:Confidentiality|Integrity|Availability) Impact Determination:",
            body,
            flags=re.IGNORECASE,
        ))
        special_match = special_matches[0] if special_matches else None
        recommendation_match = re.search(
            r"Recommended (?:Confidentiality|Integrity|Availability)"
            r"(?: Impact)? Level:",
            body,
            flags=re.IGNORECASE,
        )
        # Two source sections accidentally label the recommendation as
        # "Special Factors." Recover it from the formulaic recommendation
        # prose while preserving the publication's wording.
        if recommendation_match is None and special_matches:
            candidate = special_matches[-1]
            candidate_text = normalize_space(body[candidate.end() :])
            if re.search(
                r"(?i)\bprovisional\b.*\bimpact\b.*\brecommended\b",
                candidate_text,
            ):
                recommendation_match = candidate
                special_matches = special_matches[:-1]
                special_match = special_matches[0] if special_matches else None
        rationale_end = min(
            (
                match.start()
                for match in (special_match, recommendation_match)
                if match is not None
            ),
            default=len(body),
        )
        rationale = normalize_space(body[:rationale_end])
        special = None
        if special_match:
            special_end = (
                recommendation_match.start()
                if recommendation_match and recommendation_match.start() > special_match.end()
                else len(body)
            )
            special = normalize_space(body[special_match.end() : special_end]) or None
        recommendation = None
        if recommendation_match:
            recommendation = normalize_space(body[recommendation_match.end() :]) or None
        result[objective] = {
            "recommendedImpact": vector[objective],
            "rationale": rationale,
            "specialFactors": special,
            "recommendation": recommendation,
        }
    return result


def description_for(chunk, category_match):
    end = category_match.start() if category_match else len(chunk)
    value = normalize_space(strip_page_material(chunk[:end]))
    # Remove the publication's formulaic lead-in to the category statement.
    value = re.sub(
        r"(?i)\b(?:the\s+|a\s+)?(?:general\s+)?recommended(?:\s+provisional)?"
        r"\s+(?:security\s+)?categori[sz]ation\b.*$",
        "",
        value,
    )
    return value.strip()


def taxonomy(identifier):
    parts = identifier.split(".")
    if parts[0] == "C":
        business_id = ".".join(parts[:2])
        line_id = ".".join(parts[:3])
        return {
            "businessArea": {
                "id": business_id,
                "name": BUSINESS_AREAS[business_id],
            },
            "lineOfBusiness": {
                "id": line_id,
                "name": LINES_OF_BUSINESS[line_id],
            },
        }
    mission_id = ".".join(parts[:2])
    return {
        "missionArea": {
            "id": mission_id,
            "name": MISSION_AREAS[mission_id],
        }
    }


def make_record(text, heading):
    chunk = text[heading["bodyStart"] : heading["end"]]
    vector, statement, category_match = security_category(chunk)
    name = clean_name(heading["title"])
    page_start = text[: heading["start"]].count("\f") + 1
    page_end = text[: max(heading["start"], heading["end"] - 1)].count("\f") + 1
    if vector:
        impact_vector = "C:{}/I:{}/A:{}".format(
            vector["confidentiality"],
            vector["integrity"],
            vector["availability"],
        )
        status = (
            "not-applicable"
            if set(vector.values()) == {"N/A"}
            else "provisional"
        )
    else:
        impact_vector = None
        status = "not-assigned"
    return {
        "id": heading["id"],
        "slug": slugify(name),
        "name": name,
        "appendix": heading["id"][0],
        "category": (
            "management-and-support"
            if heading["id"][0] == "C"
            else "mission-based"
        ),
        "taxonomy": taxonomy(heading["id"]),
        "description": description_for(chunk, category_match),
        "categorizationStatus": status,
        "provisionalImpact": vector,
        "impactVector": impact_vector,
        "securityCategoryStatement": statement,
        "objectives": objective_details(chunk, category_match, vector),
        "source": {
            "section": heading["id"],
            "pdfPageStart": page_start,
            "pdfPageEnd": page_end,
            "documentPageStart": page_start - 25,
            "documentPageEnd": page_end - 25,
        },
    }


def build_catalog(text, pdf_bytes):
    digest = hashlib.sha256(pdf_bytes).hexdigest()
    if digest != EXPECTED_SHA256:
        raise ExtractionError(
            f"unexpected source PDF SHA-256 {digest}; expected {EXPECTED_SHA256}"
        )
    headings = record_headings(text)
    records = [make_record(text, heading) for heading in headings]
    categorized = [record for record in records if record["provisionalImpact"]]
    if len(records) != 170 or len(categorized) != 168:
        raise ExtractionError(
            "unexpected extraction counts: "
            f"{len(records)} records, {len(categorized)} categorized"
        )
    ids = [record["id"] for record in records]
    if len(ids) != len(set(ids)):
        raise ExtractionError("duplicate information-type IDs")
    return {
        "schemaVersion": 1,
        "catalogId": "nist-sp-800-60-v2r1-information-types",
        "title": (
            "NIST SP 800-60 Volume II Revision 1 Information Types and "
            "Provisional Impact Levels"
        ),
        "publication": {
            "series": "NIST Special Publication",
            "number": "800-60 Volume II Revision 1",
            "date": "2008-08",
            "url": SOURCE_URL,
            "sha256": digest,
            "pageCount": 304,
            "textExtraction": "pdftotext -layout",
            "copyrightNotice": (
                "This publication is not subject to copyright in the United "
                "States; attribution is appreciated."
            ),
        },
        "authority": {
            "role": "informative",
            "scope": (
                "Provisional FIPS 199 impact recommendations for federal "
                "management/support and mission-based information types."
            ),
            "caveats": [
                (
                    "Recommendations are starting points subject to agency "
                    "review and modification, not a definitive auditor checklist."
                ),
                (
                    "Actual use, aggregation, system context, connectivity, "
                    "governing requirements, and each record's special factors "
                    "can change an objective."
                ),
                (
                    "National-security information and national-security systems "
                    "are outside the publication's scope."
                ),
            ],
        },
        "impactScale": {
            "L": "low",
            "M": "moderate",
            "H": "high",
            "N/A": "not assigned by the publication",
        },
        "statistics": {
            "recordCount": len(records),
            "categorizedRecordCount": len(categorized),
            "notAssignedRecordCount": len(records) - len(categorized),
            "managementAndSupportRecordCount": sum(
                record["appendix"] == "C" for record in records
            ),
            "missionBasedRecordCount": sum(
                record["appendix"] == "D" for record in records
            ),
        },
        "informationTypes": records,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--text", required=True, help="pdftotext -layout output")
    parser.add_argument("--pdf", required=True, help="official source PDF")
    parser.add_argument("--output", help="write JSON to this path; default stdout")
    args = parser.parse_args()
    try:
        text = Path(args.text).read_text(encoding="utf-8")
        pdf_bytes = Path(args.pdf).read_bytes()
        catalog = build_catalog(text, pdf_bytes)
        rendered = json.dumps(catalog, indent=2, ensure_ascii=False) + "\n"
        if args.output:
            Path(args.output).write_text(rendered, encoding="utf-8")
        else:
            sys.stdout.write(rendered)
    except (OSError, ExtractionError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
