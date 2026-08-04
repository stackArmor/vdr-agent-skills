# tests/test_validate_cloud_config.py
import importlib.util
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SKILL = REPO_ROOT / "skills" / "generate-cloud-vdr-config"


def load(stem):
    path = SKILL / "scripts" / f"{stem}.py"
    spec = importlib.util.spec_from_file_location(stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def resource(identifier="gcf-sources-42", rtype="storage.googleapis.com/Bucket",
             tags=None, vdr=None, network=None):
    return {"type": rtype, "identifier": identifier, "region": "us-central1",
            "network": network, "subnet": None, "tags": tags or {},
            "vdrTags": vdr or {}, "builtinPatterns": []}


def rule(**kw):
    base = {"type": None, "match": None, "matchTags": None, "network": None,
            "subnet": None, "region": None, "securityImpactProfile": None,
            "multiAgency": None, "confidence": "high", "builtinPattern": None,
            "evidence": "operator attested", "manualReview": []}
    base.update(kw)
    return base


def scope_plan(**families):
    plan = {"provider": "gcp", "project": "acme-prod",
            "class": {"value": "C", "confidence": "high",
                       "evidence": "e", "manualReview": []},
            "multiAgency": {"value": "false", "confidence": "high",
                             "evidence": "e", "manualReview": []},
            "securityImpactProfile": None,
            "nameRules": [], "tagRules": [], "networkRules": [], "typeRules": []}
    plan.update(families)
    return plan


DEFAULTS = {"class": {"value": "C", "confidence": "high", "evidence": "e",
                       "manualReview": []},
            "multiAgency": {"value": "false", "confidence": "high",
                             "evidence": "e", "manualReview": []},
            "securityImpactProfile": None}


class ResolveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load("validate_cloud_config")

    def test_family_precedence_name_beats_tag(self):
        sp = scope_plan(
            nameRules=[rule(type="storage.googleapis.com/Bucket",
                            match="gcf-*", securityImpactProfile="cr-l_ir-l_ar-l")],
            tagRules=[rule(matchTags={"env": "prod"},
                           securityImpactProfile="cr-h_ir-h_ar-h")])
        res = self.mod.resolve(resource(tags={"env": "prod"}), sp, DEFAULTS)
        self.assertEqual(("cr-l_ir-l_ar-l", "nameRules[0]"),
                         res["securityImpactProfile"])

    def test_tag_override_beats_rules(self):
        sp = scope_plan(nameRules=[rule(match="gcf-*",
                                        securityImpactProfile="cr-l_ir-l_ar-l")])
        res = self.mod.resolve(
            resource(vdr={"vdr.fedramp.io/security-impact-profile":
                          "cr-m_ir-m_ar-m"}), sp, DEFAULTS)
        self.assertEqual(("cr-m_ir-m_ar-m", "tag-override"),
                         res["securityImpactProfile"])

    def test_attributes_resolve_independently(self):
        sp = scope_plan(
            nameRules=[rule(match="gcf-sources-42", multiAgency="true")],
            typeRules=[rule(type="storage.googleapis.com/Bucket",
                            securityImpactProfile="cr-l_ir-l_ar-l")])
        res = self.mod.resolve(resource(), sp, DEFAULTS)
        self.assertEqual(("true", "nameRules[0]"), res["multiAgency"])
        self.assertEqual(("cr-l_ir-l_ar-l", "typeRules[0]"),
                         res["securityImpactProfile"])

    def test_network_rule_requires_network_and_unmatched_is_unresolved(self):
        sp = scope_plan(networkRules=[rule(network="prod-vpc",
                                           securityImpactProfile="cr-h_ir-h_ar-h")])
        bucket = self.mod.resolve(resource(), sp, DEFAULTS)  # no network
        self.assertEqual("unresolved", bucket["securityImpactProfile"][1])
        vm = self.mod.resolve(
            resource(identifier="web-1", rtype="compute.googleapis.com/Instance",
                     network="prod-vpc"), sp, DEFAULTS)
        self.assertEqual("networkRules[0]", vm["securityImpactProfile"][1])

    def test_multi_agency_falls_to_scope_then_global(self):
        res = self.mod.resolve(resource(), scope_plan(), DEFAULTS)
        self.assertEqual(("false", "scope-default"), res["multiAgency"])
        self.assertEqual(("C", "scope-default"), res["class"])


class ValidateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load("validate_cloud_config")
        cls.render = staticmethod(load("render_cloud_config").render)

    def build(self):
        sp = scope_plan(nameRules=[rule(
            type="storage.googleapis.com/Bucket", match="gcf-sources-*",
            securityImpactProfile="service-content.disposable-state.deferrable-work",
            confidence="medium", builtinPattern="gcp-cloudfunctions-staging",
            evidence="provider-created transient artifact store",
            manualReview=["verify contents"])])
        plan = {"defaults": DEFAULTS, "archetypes": {}, "scopes": [sp]}
        inventory = {"scopes": [{"provider": "gcp", "project": "acme-prod",
                                  "provenance": {}, "resources": [resource()],
                                  "tagSummary": {}, "warnings": []}],
                     "summary": {"scopeCount": 1, "resourceCount": 1,
                                  "byType": {"storage.googleapis.com/Bucket": 1}}}
        coverage = {"scopes": ["gcp/acme-prod"], "inventoryTotal": 1,
                    "assignments": [{
                        "scope": "gcp/acme-prod",
                        "type": "storage.googleapis.com/Bucket",
                        "identifier": "gcf-sources-42",
                        "securityImpactProfile":
                            "service-content.disposable-state.deferrable-work",
                        "derivationMethod": "decision-trace", "vector": "M/L/L",
                        "resolutionSource": "nameRules[0]",
                        "multiAgency": "false",
                        "multiAgencySource": "scope-default",
                        "status": "builtin-pattern", "confidence": "medium",
                        "evidence": "provider-created transient artifact store",
                        "assumptions": [],
                        "manualReview": ["verify contents"]}],
                    "configurationAssumptions": [],
                    "summary": {"byScope": {"gcp/acme-prod": 1},
                                 "byFamily": {"nameRules": 1},
                                 "byStatus": {"builtin-pattern": 1},
                                 "byConfidence": {"medium": 1}}}
        return plan, inventory, coverage

    def test_clean_document_passes(self):
        plan, inventory, coverage = self.build()
        errors = self.mod.validate(plan, inventory, coverage, self.render(plan))
        self.assertEqual([], errors)

    def test_invalid_trace_fails(self):
        plan, inventory, coverage = self.build()
        plan["scopes"][0]["nameRules"][0]["securityImpactProfile"] = \
            "made-up.reasons.here"
        errors = self.mod.validate(plan, inventory, coverage, self.render(plan))
        self.assertTrue(any("made-up" in e for e in errors))

    def test_unresolved_resource_fails(self):
        plan, inventory, coverage = self.build()
        inventory["scopes"][0]["resources"].append(
            resource(identifier="mystery-bucket"))
        inventory["summary"]["resourceCount"] = 2
        errors = self.mod.validate(plan, inventory, coverage, self.render(plan))
        self.assertTrue(any("mystery-bucket" in e and "unresolved" in e
                            for e in errors))

    def test_zero_match_rule_fails(self):
        plan, inventory, coverage = self.build()
        plan["scopes"][0]["typeRules"].append(rule(
            type="sqladmin.googleapis.com/Instance",
            securityImpactProfile="cr-m_ir-m_ar-m"))
        errors = self.mod.validate(plan, inventory, coverage, self.render(plan))
        self.assertTrue(any("matches no inventoried resource" in e
                            for e in errors))

    def test_shadowed_rule_fails(self):
        plan, inventory, coverage = self.build()
        plan["scopes"][0]["nameRules"].append(rule(
            type="storage.googleapis.com/Bucket", match="gcf-sources-42",
            securityImpactProfile="cr-l_ir-l_ar-l"))
        errors = self.mod.validate(plan, inventory, coverage, self.render(plan))
        self.assertTrue(any("shadow" in e for e in errors))

    def test_coverage_accounting_mismatch_fails(self):
        plan, inventory, coverage = self.build()
        coverage["assignments"] = []
        coverage["inventoryTotal"] = 0
        errors = self.mod.validate(plan, inventory, coverage, self.render(plan))
        self.assertTrue(any("inventory equation" in e for e in errors))

    def test_rendered_drift_fails(self):
        plan, inventory, coverage = self.build()
        errors = self.mod.validate(plan, inventory, coverage,
                                   self.render(plan) + "\n# edited\n")
        self.assertTrue(any("rendered" in e for e in errors))

    def test_conflicting_tag_override_reported(self):
        plan, inventory, coverage = self.build()
        inventory["scopes"][0]["resources"][0]["vdrTags"] = {
            "vdr.fedramp.io/security-impact-profile": "cr-h_ir-h_ar-h"}
        coverage["assignments"][0]["resolutionSource"] = "tag-override"
        coverage["assignments"][0]["securityImpactProfile"] = "cr-h_ir-h_ar-h"
        coverage["assignments"][0]["derivationMethod"] = "direct-vector"
        coverage["assignments"][0]["vector"] = "H/H/H"
        errors = self.mod.validate(plan, inventory, coverage, self.render(plan))
        self.assertEqual([], errors)  # override is legal, not an error
        report = self.mod.confidence_report(plan, coverage)
        self.assertIn("tag-override", report)

    def test_global_default_invalid_sip_fails(self):
        plan, inventory, coverage = self.build()
        plan["defaults"] = {**DEFAULTS,
                            "securityImpactProfile": "made-up.bogus.trace"}
        errors = self.mod.validate(plan, inventory, coverage, self.render(plan))
        self.assertTrue(any("made-up" in e for e in errors))

    def test_confidence_report_lists_medium_and_none(self):
        plan, inventory, coverage = self.build()
        report = self.mod.confidence_report(plan, coverage)
        self.assertIn("gcf-sources-42", report)
        self.assertIn("verify contents", report)
        coverage["assignments"][0]["confidence"] = "high"
        coverage["assignments"][0]["status"] = "operator-confirmed"
        coverage["assignments"][0]["manualReview"] = []
        plan["scopes"][0]["nameRules"][0]["confidence"] = "high"
        plan["scopes"][0]["nameRules"][0]["manualReview"] = []
        report = self.mod.confidence_report(plan, coverage)
        self.assertIn("none", report.lower())


if __name__ == "__main__":
    unittest.main()
