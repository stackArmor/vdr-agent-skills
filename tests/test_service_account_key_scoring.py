"""Offline generation and coverage refresh agree on scoped key inheritance."""

import copy
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(skill, script):
    path = ROOT / "skills" / skill / "scripts" / (script + ".py")
    spec = importlib.util.spec_from_file_location(script, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class KeyInheritanceTests(unittest.TestCase):
    def setUp(self):
        self.validator = load("generate-cloud-vdr-config", "validate_cloud_config")
        self.coverage = load("update-cloud-vdr-config", "coverage_diff")
        self.helper = load("generate-cloud-vdr-config", "gcp_control_assets")
        self.parent = {
            "type": "iam.googleapis.com/ServiceAccount",
            "identifier": "runtime@example-prod.iam.gserviceaccount.com",
            "providerUri": "//iam.googleapis.com/projects/example-prod/serviceAccounts/123",
            "metadata": {"uniqueId": "123", "email": "runtime@example-prod.iam.gserviceaccount.com"},
        }
        self.key = {
            "type": "iam.googleapis.com/ServiceAccountKey",
            "identifier": "projects/example-prod/serviceAccounts/123/keys/new-key",
            "metadata": {"keyType": "SYSTEM_MANAGED"},
        }
        self.resources = [self.parent, self.key]
        self.scope = {
            "provider": "gcp", "project": "example-prod",
            "nameRules": [{"type": self.parent["type"], "match": self.parent["identifier"],
                           "securityImpactProfile": "cr-m_ir-h_ar-h"}],
        }
        self.policy = {"defaults": {"class": "D", "multiAgency": "true",
                                    "securityImpactProfile": "cr-l_ir-l_ar-l"},
                       "scopes": [self.scope]}

    def resolve(self):
        return self.coverage.resolve_cloud(self.key, self.policy, self.scope, self.validator, self.resources)

    def test_inheritance_precedes_defaults_and_tracks_parent_source(self):
        resolved = self.resolve()
        self.assertEqual(resolved["securityImpactProfile"][0], "cr-m_ir-h_ar-h")
        self.assertIn(self.parent["identifier"], resolved["securityImpactProfile"][1])
        self.assertIn("nameRules[0]", resolved["securityImpactProfile"][1])
        plan = copy.deepcopy(self.scope)
        plan.update({"class": {"value": "D"}, "multiAgency": {"value": "true"}})
        generated = self.validator.resolve(self.key, plan, {}, self.resources)
        self.assertEqual(generated["securityImpactProfile"], resolved["securityImpactProfile"])

    def test_keys_are_covered_unchanged_without_parent_reevaluation(self):
        inventory = {"scopes": [{"provider": "gcp", "project": "example-prod", "resources": self.resources}]}
        report = self.coverage.analyze(self.policy, inventory, "cloud", candidate=copy.deepcopy(self.policy))
        self.assertEqual(report["summary"], {"covered-unchanged": 2})
        self.assertFalse(report["existingScoresReevaluated"])
        self.assertFalse(report["errors"])

    def test_scoped_group_exception_and_tag_override_win(self):
        self.scope["nameRules"].append({"type": self.key["type"],
            "match": "projects/example-prod/serviceAccounts/123/keys/*", "securityImpactProfile": "cr-m_ir-h_ar-m"})
        self.assertEqual(self.resolve()["securityImpactProfile"][0], "cr-m_ir-h_ar-m")
        self.key["vdrTags"] = {"vdr.fedramp.io/security-impact-profile": "cr-h_ir-h_ar-l"}
        self.assertEqual(self.resolve()["securityImpactProfile"], ("cr-h_ir-h_ar-l", "tag-override"))

    def test_missing_or_ambiguous_owner_does_not_use_defaults(self):
        for resources in ([self.key], [self.parent, copy.deepcopy(self.parent), self.key]):
            with self.subTest(resources=len(resources)):
                self.resources = resources
                self.assertEqual(self.resolve()["securityImpactProfile"], (None, "unresolved"))

    def test_invalid_parent_remains_a_blocker_not_an_inherited_valid_default(self):
        self.scope["nameRules"][0]["securityImpactProfile"] = "not-a-profile"
        inventory = {"scopes": [{"provider": "gcp", "project": "example-prod", "resources": self.resources}]}
        report = self.coverage.analyze(self.policy, inventory, "cloud")
        self.assertEqual(report["summary"], {"blocked-existing-profile": 2})

    def test_exact_numeric_email_and_verified_project_number_aliases(self):
        for project, account in [("example-prod", "123"), ("987", self.parent["identifier"])]:
            path = f"projects/{project}/serviceAccounts/{account}/keys/rotated"
            self.assertEqual(self.helper.service_account_parents(path, self.resources, ("example-prod", "987")), [self.parent])

    def test_cross_project_and_short_names_never_join(self):
        for path in ("projects/other/serviceAccounts/123/keys/key", "runtime", "projects/example-prod/serviceAccounts/runtime/keys/key"):
            self.assertEqual(self.helper.service_account_parents(path, self.resources, ("example-prod",)), [])

    def test_key_inherits_neither_parent_multiagency_nor_reachability(self):
        self.scope["nameRules"][0].update({"multiAgency": "false", "internetReachable": "true"})
        resolved = self.resolve()
        self.assertEqual(resolved["multiAgency"][0], "true")
        self.assertIsNone(resolved["internetReachable"][0])


if __name__ == "__main__":
    unittest.main()
