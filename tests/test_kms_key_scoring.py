"""Generation and additive refresh agree on key-ring inheritance."""

import copy
import unittest

from test_service_account_key_scoring import load


class KmsInheritanceTests(unittest.TestCase):
    def setUp(self):
        self.validator = load("generate-cloud-vdr-config", "validate_cloud_config")
        self.coverage = load("update-cloud-vdr-config", "coverage_diff")
        self.helper = load("generate-cloud-vdr-config", "gcp_control_assets")
        self.ring = {"type": "cloudkms.googleapis.com/KeyRing",
                     "identifier": "projects/example-prod/locations/us-east4/keyRings/runtime"}
        self.key = {"type": "cloudkms.googleapis.com/CryptoKey",
                    "identifier": self.ring["identifier"] + "/cryptoKeys/database"}
        self.resources = [self.ring, self.key]
        self.scope = {"provider": "gcp", "project": "example-prod", "nameRules": [{
            "type": self.ring["type"], "match": self.ring["identifier"],
            "securityImpactProfile": "cr-m_ir-h_ar-h", "multiAgency": "false",
            "internetReachable": "true",
        }]}
        self.policy = {"defaults": {"class": "D", "multiAgency": "true",
                                   "securityImpactProfile": "cr-l_ir-l_ar-l"}, "scopes": [self.scope]}

    def resolve(self):
        return self.coverage.resolve_cloud(self.key, self.policy, self.scope, self.validator, self.resources)

    def generate(self):
        defaults = copy.deepcopy(self.policy["defaults"])
        for attr in ("class", "multiAgency"):
            defaults[attr] = {"value": defaults[attr]}
        return self.validator.resolve(self.key, self.scope, defaults, self.resources)

    def test_inherits_both_attributes_and_parent_sources_not_reachability(self):
        resolved = self.resolve()
        self.assertEqual(resolved["securityImpactProfile"][0], "cr-m_ir-h_ar-h")
        self.assertEqual(resolved["multiAgency"][0], "false")
        self.assertIsNone(resolved["internetReachable"][0])
        for attr in ("securityImpactProfile", "multiAgency"):
            self.assertIn("key-ring:" + self.ring["identifier"], resolved[attr][1])
            self.assertEqual(self.generate()[attr], resolved[attr])

    def test_key_overrides_win_independently_in_both_tools(self):
        for attr, value in (("securityImpactProfile", "cr-h_ir-m_ar-l"), ("multiAgency", "true")):
            with self.subTest(attribute=attr):
                self.scope["nameRules"].append({"type": self.key["type"], "match": self.key["identifier"], attr: value})
                self.assertEqual(self.resolve()[attr][0], value)
                self.assertEqual(self.generate()[attr][0], value)
                self.scope["nameRules"].pop()
        self.key["vdrTags"] = {"vdr.fedramp.io/security-impact-profile": "cr-h_ir-h_ar-l",
                              "vdr.fedramp.io/multi-agency": "true"}
        self.resources = [self.key]
        self.assertEqual(self.resolve()["multiAgency"], ("true", "tag-override"))
        self.assertEqual(self.generate()["securityImpactProfile"][0], "cr-h_ir-h_ar-l")

    def test_missing_or_ambiguous_ring_does_not_use_defaults(self):
        for resources in ([self.key], [self.ring, copy.deepcopy(self.ring), self.key]):
            self.resources = resources
            for attr in ("securityImpactProfile", "multiAgency"):
                self.assertEqual(self.resolve()[attr], (None, "unresolved"))
                self.assertEqual(self.generate()[attr], (None, "unresolved"))

    def test_exact_region_ring_and_verified_project_alias(self):
        for old, new in (("example-prod", "other"), ("us-east4", "us-west1"), ("keyRings/runtime", "keyRings/other")):
            path = self.key["identifier"].replace(old, new)
            self.assertEqual(self.helper.kms_key_ring_parents(path, self.resources, ("example-prod",)), [])
        path = self.key["identifier"].replace("example-prod", "987")
        self.assertEqual(self.helper.kms_key_ring_parents(path, self.resources, ("example-prod", "987")), [self.ring])
        self.key["identifier"] = path
        self.resources.append({"type": "cloudresourcemanager.googleapis.com/Project",
                               "identifier": "example-prod",
                               "metadata": {"projectId": "example-prod", "projectNumber": "987"}})
        self.assertEqual(self.resolve()["multiAgency"][0], "false")
        self.assertEqual(self.generate()["multiAgency"][0], "false")

    def test_new_keys_are_covered_without_rescoring_or_policy_edits(self):
        inventory = {"scopes": [{"provider": "gcp", "project": "example-prod", "resources": self.resources}]}
        report = self.coverage.analyze(self.policy, inventory, "cloud", candidate=copy.deepcopy(self.policy))
        self.assertEqual(report["summary"], {"covered-unchanged": 2})
        self.assertFalse(report["existingScoresReevaluated"])
        self.assertFalse(report["errors"])

    def test_parent_labels_are_inherited_and_invalid_parent_is_blocked(self):
        self.ring["vdrTags"] = {"vdr.fedramp.io/security-impact-profile": "cr-h_ir-h_ar-m",
                               "vdr.fedramp.io/multi-agency": "true"}
        self.assertEqual(self.resolve()["multiAgency"][0], "true")
        self.assertEqual(self.generate()["securityImpactProfile"][0], "cr-h_ir-h_ar-m")
        self.ring["vdrTags"]["vdr.fedramp.io/security-impact-profile"] = "invalid"
        for attr in ("securityImpactProfile", "multiAgency"):
            self.assertEqual(self.generate()[attr], (None, "unresolved"))
        inventory = {"scopes": [{"provider": "gcp", "project": "example-prod", "resources": self.resources}]}
        report = self.coverage.analyze(self.policy, inventory, "cloud")
        self.assertTrue(report["summary"].get("blocked-existing-profile"))


if __name__ == "__main__":
    unittest.main()
