"""The assignment contract is shared with the plugin and TSW consumers."""

import copy
import json
import unittest
from pathlib import Path

import yaml

from test_inventory_cloud_resources import load_script


class CloudPolicyContractTests(unittest.TestCase):
    def test_shared_assignment_contract(self):
        fixture = json.loads(Path(__file__).with_name("fixtures").joinpath("cloud_policy_contract.json").read_text())
        inventory = load_script("inventory_cloud_resources")
        validator = load_script("validate_cloud_config")
        policy = yaml.safe_load(fixture["policy"])
        for case in fixture["cases"]:
            with self.subTest(case=case["name"]):
                scope = next(scope for scope in policy["scopes"] if scope["provider"] == case["provider"])
                defaults = copy.deepcopy(policy["defaults"])
                for key in ("class", "multiAgency"):
                    defaults[key] = {"value": defaults[key]}
                types = {"container.task_definition": "AWS::ECS::TaskDefinition", "run.job": "run.googleapis.com/Job"}
                resource = {
                    "type": types[case["resourceType"]], "identifier": case["resourceName"],
                    "region": case["region"], "tags": case["labels"],
                    "vdrTags": inventory.decode_vdr_tags(case["provider"], case["labels"]),
                }
                resolved = validator.resolve(resource, scope, defaults)
                self.assertEqual(resolved["securityImpactProfile"][0], case["profile"])
                self.assertEqual(resolved["class"][0], case["class"])
                self.assertEqual(resolved["multiAgency"][0] == "true", case["multiAgency"])
