# tests/test_inventory_cloud_resources.py
import importlib.util
import json
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SKILL = REPO_ROOT / "skills" / "generate-cloud-vdr-config"


def load_script(stem):
    path = SKILL / "scripts" / f"{stem}.py"
    spec = importlib.util.spec_from_file_location(stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fake_runner(responses):
    """responses: list of (subcommand-match, payload). Raises on no match."""
    calls = []

    def run(args):
        calls.append(args)
        joined = " ".join(args)
        for needle, payload in responses:
            if needle in joined:
                return payload if isinstance(payload, str) else json.dumps(payload)
        raise RuntimeError("unexpected command: " + joined)

    run.calls = calls
    return run


class PatternMatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_script("inventory_cloud_resources")
        cls.patterns = cls.mod.load_patterns(
            SKILL / "references" / "managed-resource-patterns.json")

    def test_name_glob_match(self):
        resource = {"type": "storage.googleapis.com/Bucket",
                    "identifier": "gcf-sources-42-us-central1", "tags": {}}
        self.assertIn("gcp-cloudfunctions-staging",
                      self.mod.match_patterns(resource, [p for p in self.patterns
                                                          if p["provider"] == "gcp"]))

    def test_marker_tag_match_any_type(self):
        resource = {"type": "AWS::EC2::Instance", "identifier": "i-0abc",
                    "tags": {"aws:cloudformation:stack-name": "web"}}
        aws = [p for p in self.patterns if p["provider"] == "aws"]
        self.assertEqual(["aws-cloudformation-managed"],
                         self.mod.match_patterns(resource, aws))

    def test_no_match(self):
        resource = {"type": "storage.googleapis.com/Bucket",
                    "identifier": "acme-prod-customer-data", "tags": {}}
        gcp = [p for p in self.patterns if p["provider"] == "gcp"]
        self.assertEqual([], self.mod.match_patterns(resource, gcp))


class DecodeVdrTagTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_script("inventory_cloud_resources")

    def test_gcp_encoded_trace_decodes(self):
        tags = {"vdr_fedramp_io_security_impact_profile":
                "service-content__disposable-state__deferrable-work",
                "env": "prod"}
        self.assertEqual(
            {"vdr.fedramp.io/security-impact-profile":
             "service-content.disposable-state.deferrable-work"},
            self.mod.decode_vdr_tags("gcp", tags))

    def test_gcp_direct_vector_and_class_decode(self):
        tags = {"vdr_fedramp_io_security_impact_profile": "cr-l_ir-l_ar-l",
                "vdr_fedramp_io_class": "c",
                "vdr_fedramp_io_multi_agency": "false"}
        decoded = self.mod.decode_vdr_tags("gcp", tags)
        self.assertEqual("cr-l_ir-l_ar-l",
                         decoded["vdr.fedramp.io/security-impact-profile"])
        self.assertEqual("C", decoded["vdr.fedramp.io/class"])
        self.assertEqual("false", decoded["vdr.fedramp.io/multi-agency"])

    def test_aws_canonical_passthrough(self):
        tags = {"vdr.fedramp.io/multi-agency": "true", "Name": "web-1"}
        self.assertEqual({"vdr.fedramp.io/multi-agency": "true"},
                         self.mod.decode_vdr_tags("aws", tags))


class GcpInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_script("inventory_cloud_resources")
        cls.patterns = cls.mod.load_patterns(
            SKILL / "references" / "managed-resource-patterns.json")

    def asset(self, asset_type, name, location="us-central1", labels=None,
              network=None):
        resource = {"data": {"labels": labels or {}}, "location": location}
        if network:
            resource["data"]["networkInterfaces"] = [
                {"network": network, "subnetwork": network + "/sub"}]
        return {"assetType": asset_type,
                "name": "//x/" + name,
                "resource": resource}

    def test_asset_api_inventory(self):
        runner = fake_runner([
            ("auth list", [{"account": "ops@acme.example", "status": "ACTIVE"}]),
            ("asset list", [
                self.asset("storage.googleapis.com/Bucket",
                           "projects/_/buckets/gcf-sources-42-uc1"),
                self.asset("compute.googleapis.com/Instance",
                           "projects/acme/zones/us-central1-a/instances/web-1",
                           labels={"env": "prod"},
                           network=".../networks/prod-vpc"),
            ]),
        ])
        scope = self.mod.inventory_gcp("acme-prod", self.patterns, runner=runner)
        self.assertEqual("gcp", scope["provider"])
        self.assertEqual("acme-prod", scope["project"])
        self.assertEqual("asset-api", scope["provenance"]["inventorySource"])
        self.assertEqual(2, len(scope["resources"]))
        bucket = scope["resources"][0]
        self.assertEqual("gcf-sources-42-uc1", bucket["identifier"])
        self.assertEqual(["gcp-cloudfunctions-staging"], bucket["builtinPatterns"])
        vm = scope["resources"][1]
        self.assertEqual("web-1", vm["identifier"])
        self.assertEqual("prod-vpc", vm["network"])
        # every gcloud call pins the reviewed project
        for call in runner.calls:
            if "asset list" in " ".join(call):
                self.assertIn("--project", call)
                self.assertIn("acme-prod", call)

    def test_fallback_records_degraded_warning(self):
        runner = fake_runner([
            ("auth list", [{"account": "ops@acme.example", "status": "ACTIVE"}]),
            ("storage buckets list", [{"name": "acme-data", "location": "US",
                                        "labels": {}}]),
            ("sql instances list", []),
            ("compute instances list", []),
            ("bq ", []),
        ])
        scope = self.mod.inventory_gcp("acme-prod", self.patterns,
                                       runner=runner, use_asset_api=False)
        self.assertEqual("per-service-fallback",
                         scope["provenance"]["inventorySource"])
        self.assertTrue(any("Asset" in w or "asset" in w
                            for w in scope["warnings"]))
        self.assertEqual(1, len(scope["resources"]))

    def test_merge_scopes_summary(self):
        scope = {"provider": "gcp", "project": "p", "provenance": {},
                 "resources": [{"type": "t", "identifier": "a", "tags": {},
                                "vdrTags": {}, "builtinPatterns": [],
                                "region": None, "network": None, "subnet": None}],
                 "tagSummary": {}, "warnings": []}
        doc = self.mod.merge_scopes([scope])
        self.assertEqual(1, doc["summary"]["scopeCount"])
        self.assertEqual(1, doc["summary"]["resourceCount"])
        self.assertEqual({"t": 1}, doc["summary"]["byType"])
