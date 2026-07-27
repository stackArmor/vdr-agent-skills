import json
import subprocess
import sys
import unittest

from loader import SKILL, SCRIPTS, load_script

validator = load_script("validate_nist_800_60_catalog")
query = load_script("query_nist_800_60")
CATALOG = (
    SKILL
    / "references"
    / "nist-sp-800-60-v2r1-information-types.json"
)


def load_catalog():
    return json.loads(CATALOG.read_text(encoding="utf-8"))


class CatalogTests(unittest.TestCase):
    def test_catalog_is_valid_and_complete(self):
        catalog = load_catalog()
        self.assertIs(validator.validate(catalog), catalog)
        self.assertEqual(catalog["statistics"]["recordCount"], 170)
        self.assertEqual(catalog["statistics"]["categorizedRecordCount"], 168)

    def test_representative_information_types(self):
        records = {
            record["id"]: record
            for record in load_catalog()["informationTypes"]
        }
        self.assertEqual(records["C.2.1.1"]["impactVector"], "C:L/I:L/A:L")
        self.assertEqual(records["C.2.4.1"]["impactVector"], "C:M/I:M/A:M")
        self.assertEqual(records["D.3"]["impactVector"], "C:H/I:H/A:H")
        self.assertEqual(records["D.14.4"]["impactVector"], "C:L/I:H/A:L")
        self.assertIsNone(records["D.26.1"]["provisionalImpact"])
        self.assertIsNone(records["D.26.2"]["provisionalImpact"])

    def test_every_record_has_source_pages(self):
        for record in load_catalog()["informationTypes"]:
            source = record["source"]
            self.assertGreaterEqual(source["pdfPageStart"], 1)
            self.assertLessEqual(source["pdfPageEnd"], 304)
            self.assertEqual(
                source["documentPageStart"],
                source["pdfPageStart"] - 25,
            )


class QueryTests(unittest.TestCase):
    SCRIPT = SCRIPTS / "query_nist_800_60.py"

    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, str(self.SCRIPT), *args],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_health_care_search_prioritizes_delivery(self):
        result = self.run_cli("--search", "health care", "--limit", "1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("D.14.4", result.stdout)
        self.assertIn("C:L/I:H/A:L", result.stdout)

    def test_id_query_emits_machine_readable_record(self):
        result = self.run_cli("--id", "C.2.3.4", "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        records = json.loads(result.stdout)
        self.assertEqual(records[0]["name"], "Strategic Planning")

    def test_na_impact_query_finds_information_sharing(self):
        result = self.run_cli("--impact", "N/A,N/A,N/A", "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        records = json.loads(result.stdout)
        self.assertEqual([record["id"] for record in records], ["C.3.5.9"])

    def test_no_match_is_distinct(self):
        result = self.run_cli("--search", "zyxqvnevermatch")
        self.assertEqual(result.returncode, 1)
        self.assertIn("no matching", result.stderr)


if __name__ == "__main__":
    unittest.main()
