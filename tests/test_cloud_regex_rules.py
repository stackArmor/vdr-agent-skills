"""Regex grouping preserves cloud rule ordering and incremental boundaries."""

import copy
import importlib.util
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "generate-cloud-vdr-config" / "scripts"


def load(path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def rule(**extra):
    return {
        "type": "iam.googleapis.com/ServiceAccount",
        "matchRegex": r"(deploy|bootstrap)@acme-prod\.iam\.gserviceaccount\.com",
        "securityImpactProfile": "privileged-access.release-control.change-deferred",
        "confidence": "medium",
        "evidence": "Reviewed deployment-only authority",
        "manualReview": ["Verify recovery does not depend on this identity"],
        **extra,
    }


def resource(name="deploy@acme-prod.iam.gserviceaccount.com", **extra):
    return {"identifier": name, "type": "iam.googleapis.com/ServiceAccount", **extra}


def policy(*rules):
    return {
        "defaults": {"class": "D", "multiAgency": "true"},
        "scopes": [{"provider": "gcp", "project": "acme-prod", "nameRules": list(rules)}],
    }


def inventory(*resources):
    return {"scopes": [{"provider": "gcp", "project": "acme-prod", "resources": list(resources)}]}


class RegexMatchingTests(unittest.TestCase):
    def setUp(self):
        self.helper = load(SCRIPTS / "cloud_name_matching.py")
        self.validator = load(SCRIPTS / "validate_cloud_config.py")
        self.renderer = load(SCRIPTS / "render_cloud_config.py")
        self.delta = load(ROOT / "skills" / "update-cloud-vdr-config" / "scripts" / "coverage_diff.py")

    def test_explicit_group_fullmatch_and_case(self):
        cases = {
            "deploy@acme-prod.iam.gserviceaccount.com": True,
            "bootstrap@acme-prod.iam.gserviceaccount.com": True,
            "runtime@acme-prod.iam.gserviceaccount.com": False,
            "DEPLOY@acme-prod.iam.gserviceaccount.com": False,
            "prefix-deploy@acme-prod.iam.gserviceaccount.com": False,
            "deploy@acme-prod.iam.gserviceaccount.com.extra": False,
            "deploy@acme-prodXiamXgserviceaccountXcom": False,
            "deploy@other-prod.iam.gserviceaccount.com": False,
        }
        for name, expected in cases.items():
            with self.subTest(name=name):
                self.assertEqual(self.helper.name_matches(rule(), name), expected)
                self.assertEqual(self.validator.rule_matches(rule(), resource(name), "nameRules"), expected)

    def test_globs_keep_literal_dots_and_character_classes(self):
        self.assertTrue(self.helper.name_matches({"match": "vm-[ab].*"}, "vm-a.example"))
        self.assertFalse(self.helper.name_matches({"match": "vm-[ab].*"}, "vm-aXexample"))

    def test_inline_flag_and_anchors(self):
        self.assertTrue(
            self.helper.name_matches(
                rule(matchRegex=r"(?i)^deploy@acme-prod\.iam\.gserviceaccount\.com$"), "DEPLOY@acme-prod.iam.gserviceaccount.com"
            )
        )

    def test_invalid_selectors_and_patterns(self):
        cases = [
            (rule(match="*"), "exactly one"),
            (rule(matchRegex=None), "exactly one"),
            (rule(matchRegex=""), "non-empty"),
            (rule(matchRegex=False), "non-empty"),
            (rule(matchRegex=27), "non-empty"),
            (rule(matchRegex=["deploy"]), "non-empty"),
            (rule(matchRegex="["), "invalid matchRegex"),
            (rule(matchRegex="x" * 2049), "2048"),
            (rule(type=None), "explicit"),
            (rule(type=""), "explicit"),
        ]
        for item, message in cases:
            with self.subTest(item=item):
                self.assertTrue(any(message in error for error in self.helper.selector_errors(item, "nameRules")))
                errors = []
                self.validator._validate_scope_shape(policy(item)["scopes"][0], "gcp/acme-prod", errors)
                self.assertTrue(any(message in error for error in errors), errors)

    def test_regex_rejected_outside_name_rules(self):
        for family in ("tagRules", "networkRules", "typeRules"):
            with self.subTest(family=family):
                self.assertIn("only allowed", self.helper.selector_errors(rule(), family)[0])

    def test_null_unused_selector_is_allowed(self):
        self.assertEqual(self.helper.selector_errors(rule(match=None), "nameRules"), [])
        self.assertEqual(self.helper.selector_errors({"match": "vm-*", "matchRegex": None}, "nameRules"), [])

    def test_dependency_missing_has_actionable_error_and_globs_work(self):
        self.helper._compile.cache_clear()
        with patch.dict("sys.modules", {"regex": None}):
            self.assertTrue(self.helper.name_matches({"match": "vm-*"}, "vm-a"))
            self.assertIn("requires the regex package", self.helper.selector_errors(rule(), "nameRules")[0])

    def test_timeout_raises_instead_of_no_match(self):
        compiled = Mock()
        compiled.fullmatch.side_effect = TimeoutError
        with patch.object(self.helper, "_compile", return_value=compiled):
            with self.assertRaisesRegex(ValueError, "exceeded 25 ms"):
                self.helper.name_matches(rule(), "any")
        compiled.fullmatch.assert_called_once_with("any", timeout=0.025)

    def test_cache_is_bounded(self):
        self.assertEqual(self.helper._compile.cache_info().maxsize, 256)

    def test_type_tags_and_region_are_conjunctive(self):
        item = rule(matchTags={"purpose": "deploy*"}, region="us-*")
        target = resource(tags={"purpose": "deployment"}, region="us-east4")
        self.assertTrue(self.validator.rule_matches(item, target, "nameRules"))
        for field, value in (("type", "storage.googleapis.com/Bucket"), ("tags", {}), ("region", "europe-west1")):
            with self.subTest(field=field):
                self.assertFalse(self.validator.rule_matches(item, {**target, field: value}, "nameRules"))

    def test_document_order_and_per_attribute_precedence(self):
        glob = {"type": rule()["type"], "match": "deploy@*", "multiAgency": "false"}
        group = rule()
        scope = policy(glob, group)["scopes"][0]
        target = resource()
        result = self.delta.resolve_cloud(target, policy(glob, group), scope, self.validator, [target])
        self.assertEqual(result["securityImpactProfile"], (group["securityImpactProfile"], "nameRules[1]"))
        self.assertEqual(result["multiAgency"], ("false", "nameRules[0]"))
        glob["securityImpactProfile"] = "cr-h_ir-h_ar-h"
        result = self.delta.resolve_cloud(target, policy(glob, group), scope, self.validator, [target])
        self.assertEqual(result["securityImpactProfile"], ("cr-h_ir-h_ar-h", "nameRules[0]"))

    def test_override_beats_regex(self):
        target = resource(vdrTags={"vdr.fedramp.io/security-impact-profile": "cr-h_ir-h_ar-h"})
        result = self.delta.resolve_cloud(target, policy(rule()), policy(rule())["scopes"][0], self.validator, [target])
        self.assertEqual(result["securityImpactProfile"], ("cr-h_ir-h_ar-h", "tag-override"))

    def test_renderer_round_trip_escaping(self):
        attestation = {"value": "D", "confidence": "high", "evidence": "operator confirmed", "manualReview": []}
        plan = policy(rule())
        plan["defaults"] = {"class": attestation, "multiAgency": {**attestation, "value": "true"}}
        plan["scopes"][0].update(plan["defaults"])
        rendered = self.renderer.render(plan)
        parsed = yaml.safe_load(rendered)
        self.assertEqual(parsed["scopes"][0]["nameRules"][0]["matchRegex"], rule()["matchRegex"])
        self.assertNotIn("match:", rendered)
        self.assertEqual(rendered.count("# manual-review:"), 1)

    def test_renderer_rejects_malformed_selectors(self):
        plan = policy(rule(match="*"))
        attestation = {"value": "D", "confidence": "high", "evidence": "operator confirmed", "manualReview": []}
        plan["defaults"] = {"class": attestation, "multiAgency": {**attestation, "value": "true"}}
        plan["scopes"][0].update(plan["defaults"])
        with self.assertRaisesRegex(ValueError, "exactly one"):
            self.renderer.render(plan)

    def test_shadow_and_zero_match_checks_include_regex(self):
        scope = policy(rule(matchRegex=".*"), rule())["scopes"][0]
        errors = []
        self.validator._check_zero_match_and_shadow(
            scope, "gcp/acme-prod", self.validator._matched_sets(scope, [resource()]), errors
        )
        self.assertTrue(any("shadowed" in error for error in errors))
        scope["nameRules"] = [rule(matchRegex="nothing")]
        errors = []
        self.validator._check_zero_match_and_shadow(
            scope, "gcp/acme-prod", self.validator._matched_sets(scope, [resource()]), errors
        )
        self.assertTrue(any("matches no" in error for error in errors))

    def test_coverage_update_only_fills_gaps(self):
        baseline = policy(rule(matchRegex=r"deploy@acme-prod\.iam\.gserviceaccount\.com"))
        candidate = copy.deepcopy(baseline)
        candidate["scopes"][0]["nameRules"].append(rule(matchRegex=r"bootstrap@acme-prod\.iam\.gserviceaccount\.com"))
        report = self.delta.analyze(
            baseline, inventory(resource(), resource("bootstrap@acme-prod.iam.gserviceaccount.com")), "cloud", candidate=candidate
        )
        self.assertEqual(report["summary"], {"covered-unchanged": 1, "missing-assignment": 1})
        self.assertEqual(report["errors"], [])
        self.assertFalse(report["existingScoresReevaluated"])

    def test_new_regex_cannot_touch_covered_assets_even_with_same_score(self):
        baseline = policy(rule(matchRegex=r"deploy@acme-prod\.iam\.gserviceaccount\.com"))
        candidate = copy.deepcopy(baseline)
        candidate["scopes"][0]["nameRules"].append(rule())
        report = self.delta.analyze(
            baseline, inventory(resource(), resource("bootstrap@acme-prod.iam.gserviceaccount.com")), "cloud", candidate=candidate
        )
        self.assertTrue(any("touches an already-covered" in error for error in report["errors"]))

    def test_invalid_baseline_rejected_without_inventory(self):
        with self.assertRaisesRegex(ValueError, "invalid matchRegex"):
            self.delta.analyze(policy(rule(matchRegex="[")), inventory(), "cloud")

    def test_invalid_candidate_rejected_without_inventory(self):
        candidate = policy(rule(matchRegex="["))
        report = self.delta.analyze(policy(), inventory(), "cloud", candidate=candidate)
        self.assertTrue(any("invalid matchRegex" in error for error in report["errors"]))

    def test_existing_rule_consolidation_remains_out_of_scope(self):
        baseline = policy(
            {"type": rule()["type"], "match": resource()["identifier"], "securityImpactProfile": rule()["securityImpactProfile"]}
        )
        report = self.delta.analyze(baseline, inventory(resource()), "cloud", candidate=policy(rule()))
        self.assertTrue(report["errors"])

    def test_keys_inherit_regex_selected_parent(self):
        parent = resource(metadata={"uniqueId": "123", "email": resource()["identifier"]})
        key = {
            "type": "iam.googleapis.com/ServiceAccountKey",
            "identifier": "projects/acme-prod/serviceAccounts/123/keys/rotated",
        }
        report = self.delta.analyze(policy(rule()), inventory(parent, key), "cloud")
        self.assertEqual(report["summary"], {"covered-unchanged": 2})
        self.assertEqual(report["assignments"][1]["profile"], rule()["securityImpactProfile"])


if __name__ == "__main__":
    unittest.main()
