import json
import importlib.util
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CATALOG = (REPO_ROOT / "skills" / "generate-cloud-vdr-config"
           / "references" / "managed-resource-patterns.json")
REASON_CODES = (REPO_ROOT / "skills" / "generate-vdr-configmap"
                / "scripts" / "reason_codes.py")


def load_reason_codes():
    spec = importlib.util.spec_from_file_location("vdr_reason_codes", REASON_CODES)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ManagedResourcePatternTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.patterns = json.loads(CATALOG.read_text(encoding="utf-8"))
        cls.reason_codes = load_reason_codes()

    def test_catalog_shape(self):
        required = {"id", "provider", "type", "nameGlobs", "markerTags",
                    "managedBy", "rationale", "defaultSecurityImpactProfile",
                    "maxConfidence", "manualReview"}
        ids = set()
        for entry in self.patterns:
            self.assertEqual(required, set(entry), entry.get("id"))
            self.assertIn(entry["provider"], ("gcp", "aws"))
            self.assertEqual(entry["maxConfidence"], "medium", entry["id"])
            self.assertTrue(entry["nameGlobs"] or entry["markerTags"], entry["id"])
            self.assertTrue(entry["manualReview"], entry["id"])
            self.assertNotIn(entry["id"], ids)
            ids.add(entry["id"])

    def test_default_traces_validate_against_governed_registry(self):
        for entry in self.patterns:
            vector = self.reason_codes.classify(entry["defaultSecurityImpactProfile"])
            self.assertEqual(("M", "L", "L"), vector, entry["id"])

    def test_expected_patterns_present(self):
        ids = {entry["id"] for entry in self.patterns}
        for expected in ("gcp-cloudfunctions-staging", "gcp-cloudbuild-artifacts",
                         "gcp-cloudrun-sources", "gcp-dataproc-staging",
                         "gcp-container-registry-artifacts", "gcp-appengine-staging",
                         "aws-cloudformation-templates", "aws-cdk-assets",
                         "aws-elasticbeanstalk-artifacts", "aws-athena-query-results",
                         "aws-cloudformation-managed"):
            self.assertIn(expected, ids)


if __name__ == "__main__":
    unittest.main()
