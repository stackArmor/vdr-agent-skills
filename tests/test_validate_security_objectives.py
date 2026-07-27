import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from loader import SKILL, SCRIPTS, load_script

mod = load_script("validate_security_objectives")
EXAMPLE = SKILL / "assets" / "security-objectives.example.json"


def load_example():
    return json.loads(EXAMPLE.read_text(encoding="utf-8"))


class ContractTests(unittest.TestCase):
    def test_example_is_valid(self):
        document = load_example()
        self.assertIs(mod.validate(document), document)

    def test_ceiling_must_match_math_and_encodings(self):
        document = load_example()
        document["securityRequirementsCeiling"]["wire"] = "cr-h_ir-h_ar-h"
        with self.assertRaisesRegex(mod.ValidationError, "min"):
            mod.validate(document)

    def test_system_detail_must_match_top_level_sso(self):
        document = load_example()
        document["systemProfile"]["sso"]["c"]["level"] = "H"
        with self.assertRaisesRegex(mod.ValidationError, "top-level sso"):
            mod.validate(document)

    def test_definite_agencies_aggregate_by_max(self):
        document = load_example()
        second = copy.deepcopy(document["agencyProfiles"][0])
        second["agency"] = "second generic agency"
        second["aso"]["c"]["level"] = "H"
        document["agencyProfiles"].append(second)
        document["aso"]["c"] = "H"
        document["securityRequirementsCeiling"]["c"] = "M"
        mod.validate(document)
        document["aso"]["c"] = "M"
        with self.assertRaisesRegex(mod.ValidationError, "maximum"):
            mod.validate(document)

    def test_target_only_profiles_fall_back_to_sso(self):
        document = load_example()
        document["agencyProfiles"][0]["relationship"] = "target"
        document["aso"] = copy.deepcopy(document["sso"])
        document["agencyUseSummary"] = {
            "basis": "sso-fallback",
            "rationale": "No deploying agency is definite.",
            "status": "agent-inferred",
            "confidence": "low",
            "assumptions": ["Target profile does not establish actual use."],
            "manualReview": ["Confirm the first deploying agency."],
        }
        document["securityRequirementsCeiling"] = {
            "c": "M",
            "i": "M",
            "a": "M",
            "wire": "cr-m_ir-m_ar-m",
            "display": "CR:M/IR:M/AR:M",
        }
        mod.validate(document)

    def test_fallback_requires_low_confidence_and_review(self):
        document = load_example()
        document["agencyProfiles"] = []
        document["aso"] = copy.deepcopy(document["sso"])
        document["securityRequirementsCeiling"] = {
            "c": "M",
            "i": "M",
            "a": "M",
            "wire": "cr-m_ir-m_ar-m",
            "display": "CR:M/IR:M/AR:M",
        }
        document["agencyUseSummary"]["basis"] = "sso-fallback"
        with self.assertRaisesRegex(mod.ValidationError, "confidence"):
            mod.validate(document)

    def test_configmap_era_fields_are_rejected(self):
        for field in (
            "assignments",
            "components",
            "configMap",
            "envelope",
            "multiAgencyDetermination",
        ):
            document = load_example()
            document[field] = []
            with self.assertRaisesRegex(mod.ValidationError, field):
                mod.validate(document)

    def test_nist_reference_must_match_bundled_catalog(self):
        document = load_example()
        reference = document["systemProfile"]["nistInformationTypes"][0]
        reference["provisionalImpact"]["c"] = "H"
        with self.assertRaisesRegex(mod.ValidationError, "catalog"):
            mod.validate(document)

    def test_confirmed_nist_reference_requires_applied_impact(self):
        document = load_example()
        reference = document["systemProfile"]["nistInformationTypes"][0]
        reference["appliedImpact"] = None
        with self.assertRaisesRegex(mod.ValidationError, "appliedImpact"):
            mod.validate(document)

    def test_candidate_nist_reference_cannot_be_applied(self):
        document = load_example()
        reference = document["systemProfile"]["nistInformationTypes"][0]
        reference["applicability"] = "candidate"
        with self.assertRaisesRegex(mod.ValidationError, "must be null"):
            mod.validate(document)


class CliTests(unittest.TestCase):
    SCRIPT = SCRIPTS / "validate_security_objectives.py"

    def run_cli(self, document):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "security-objectives.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(self.SCRIPT), str(path)],
                capture_output=True,
                text=True,
                check=False,
            )

    def test_cli_accepts_example(self):
        result = self.run_cli(load_example())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("valid", result.stdout)

    def test_cli_rejects_invalid_example(self):
        document = load_example()
        document["schemaVersion"] = 2
        result = self.run_cli(document)
        self.assertEqual(result.returncode, 2)
        self.assertIn("schemaVersion", result.stderr)


if __name__ == "__main__":
    unittest.main()
