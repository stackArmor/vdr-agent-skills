# tests/test_render_cloud_config.py
import importlib.util
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (REPO_ROOT / "skills" / "generate-cloud-vdr-config"
          / "scripts" / "render_cloud_config.py")


def load():
    spec = importlib.util.spec_from_file_location("render_cloud_config", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def minimal_plan():
    return {
        "defaults": {
            "class": {"value": "C", "confidence": "high",
                       "evidence": "operator-confirmed", "manualReview": []},
            "multiAgency": {"value": "false", "confidence": "high",
                             "evidence": "operator-confirmed", "manualReview": []},
            "securityImpactProfile": None,
        },
        "archetypes": {},
        "scopes": [{
            "provider": "gcp", "project": "acme-prod",
            "class": {"value": "C", "confidence": "high",
                       "evidence": "operator-confirmed", "manualReview": []},
            "multiAgency": {"value": "false", "confidence": "high",
                             "evidence": "operator-confirmed", "manualReview": []},
            "securityImpactProfile": None,
            "nameRules": [{
                "type": "storage.googleapis.com/Bucket",
                "match": "gcf-sources-*",
                "securityImpactProfile":
                    "service-content.disposable-state.deferrable-work",
                "multiAgency": None, "region": None, "matchTags": None,
                "confidence": "medium",
                "builtinPattern": "gcp-cloudfunctions-staging",
                "evidence": "provider-created transient artifact store",
                "manualReview": ["verify staged contents are non-sensitive"],
            }],
            "tagRules": [], "networkRules": [], "typeRules": [],
        }],
    }


class RenderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load()

    def test_render_structure_and_comments(self):
        text = self.mod.render(minimal_plan())
        self.assertIn("apiVersion: vdr.fedramp.io/v1alpha1", text)
        self.assertIn("kind: CloudResourceScoringConfig", text)
        self.assertIn('class: "C"', text)
        self.assertIn('multiAgency: "false"', text)
        self.assertIn("# builtin-pattern: gcp-cloudfunctions-staging", text)
        self.assertIn("# confidence: medium", text)
        self.assertIn("# manual-review: verify staged contents are non-sensitive",
                      text)
        self.assertIn('match: "gcf-sources-*"', text)
        # comment lines sit immediately above the rule entry
        lines = text.splitlines()
        rule_idx = next(i for i, l in enumerate(lines) if "match:" in l and "gcf" in l)
        self.assertTrue(any("# confidence: medium" in l
                            for l in lines[rule_idx - 4:rule_idx]))

    def test_render_is_deterministic(self):
        self.assertEqual(self.mod.render(minimal_plan()),
                         self.mod.render(minimal_plan()))

    def test_high_confidence_needs_no_manual_review_but_medium_does(self):
        plan = minimal_plan()
        plan["scopes"][0]["nameRules"][0]["manualReview"] = []
        with self.assertRaises(ValueError):
            self.mod.render(plan)

    def test_omits_empty_rule_families_and_archetypes(self):
        text = self.mod.render(minimal_plan())
        self.assertNotIn("tagRules", text)
        self.assertNotIn("archetypes", text)
