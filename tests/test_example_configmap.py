import itertools
import re
import unittest
from pathlib import Path

EXAMPLE = (Path(__file__).resolve().parents[1] / "skills"
           / "generate-security-requirements-configmap" / "assets"
           / "vdr-fedramp.example.yaml")


class ExampleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = EXAMPLE.read_text(encoding="utf-8")

    def test_all_27_catalog_entries_present_once(self):
        for c, i, a in itertools.product("lmh", repeat=3):
            key = f'"cr-{c}_ir-{i}_ar-{a}":'
            self.assertEqual(self.text.count(key), 1, key)
        self.assertEqual(self.text.count("lens: requirements"), 27)

    def test_label_key_rename_present(self):
        self.assertIn("archetype: vdr.fedramp.io/security-requirements", self.text)

    def test_human_review_marker_fenced_false(self):
        self.assertIn('humanReviewCompleted: "false"', self.text)
        self.assertIn("human-only attestation marker", self.text)
        self.assertIn("DO NOT read, report, summarize", self.text)

    def test_rules_use_dot_free_label_values(self):
        for match in re.finditer(r"archetype:\s*([\w.\-/]+)", self.text):
            value = match.group(1)
            if value.startswith("vdr.fedramp.io/"):
                continue  # the labelKeys rename line
            self.assertRegex(value, r"^cr-[lmh]_ir-[lmh]_ar-[lmh]$")

    def test_no_real_names(self):
        for banned in ("Clarity", "Broadcom", "Rally", "NIH", "CFTC", "USPTO",
                       "Ohio", "Patlytics", "DCEG", "DAU"):
            self.assertNotIn(banned, self.text)

    def test_scalars_quoted_with_confidence_comments(self):
        self.assertIn('class: "C"', self.text)
        self.assertIn('multiAgency: "false"', self.text)
        self.assertGreaterEqual(self.text.count("# confidence:"), 6)


if __name__ == "__main__":
    unittest.main()
