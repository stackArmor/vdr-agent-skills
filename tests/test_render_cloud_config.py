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


def attested_rule(**kw):
    base = {
        "type": "compute.googleapis.com/Instance", "match": "sftp-*",
        "matchTags": None, "network": None, "subnet": None, "region": None,
        "securityImpactProfile": None, "multiAgency": None,
        "internetReachable": "false",
        "internetReachableJustification":
            "Port 22 admits only the twelve agency source CIDRs enforced on "
            "the load-balancer backend firewall.",
        "confidence": "high", "builtinPattern": None,
        "evidence": "operator-attested strict allowlist", "manualReview": [],
    }
    base.update(kw)
    return base


def plan_with_rule(rule):
    plan = minimal_plan()
    plan["scopes"][0]["nameRules"] = [rule]
    return plan


class ReachabilityAttestationRenderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load()

    def test_attestation_and_justification_are_rendered_quoted(self):
        text = self.mod.render(plan_with_rule(attested_rule()))
        self.assertIn('internetReachable: "false"', text)
        self.assertIn('internetReachableJustification: "Port 22 admits only', text)

    def test_false_without_justification_is_refused(self):
        rule = attested_rule(internetReachableJustification=None)
        with self.assertRaises(ValueError) as ctx:
            self.mod.render(plan_with_rule(rule))
        self.assertIn("requires a non-empty", str(ctx.exception))

    def test_blank_justification_is_refused(self):
        rule = attested_rule(internetReachableJustification="   ")
        with self.assertRaises(ValueError):
            self.mod.render(plan_with_rule(rule))

    def test_justification_without_a_negative_attestation_is_refused(self):
        rule = attested_rule(internetReachable="true")
        with self.assertRaises(ValueError) as ctx:
            self.mod.render(plan_with_rule(rule))
        self.assertIn("only meaningful", str(ctx.exception))

    def test_unquoted_boolean_is_refused(self):
        rule = attested_rule(internetReachable=False)
        with self.assertRaises(ValueError) as ctx:
            self.mod.render(plan_with_rule(rule))
        self.assertIn("quoted string", str(ctx.exception))

    def test_true_needs_no_justification(self):
        rule = attested_rule(internetReachable="true",
                             internetReachableJustification=None)
        self.assertIn('internetReachable: "true"',
                      self.mod.render(plan_with_rule(rule)))

    def test_defaults_may_not_attest_reachability(self):
        plan = minimal_plan()
        plan["defaults"]["internetReachable"] = "false"
        with self.assertRaises(ValueError) as ctx:
            self.mod.render(plan)
        self.assertIn("only be set on a rule", str(ctx.exception))

    def test_scope_may_not_attest_reachability(self):
        plan = minimal_plan()
        plan["scopes"][0]["internetReachable"] = "true"
        with self.assertRaises(ValueError) as ctx:
            self.mod.render(plan)
        self.assertIn("only be set on a rule", str(ctx.exception))


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
