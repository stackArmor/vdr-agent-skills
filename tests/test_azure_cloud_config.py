import copy
import contextlib
import importlib.util
import io
import json
import unittest
from pathlib import Path
from unittest.mock import patch

import jmespath
import yaml

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "skills/generate-cloud-vdr-config/scripts"
SUB = "6e3f17d6-a937-41d4-861d-ea302e369236"


def load(stem, directory=BASE):
    spec = importlib.util.spec_from_file_location(stem, directory / (stem + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def rid(kind, name, group="prod"):
    namespace, *types = kind.split("/")
    names = name.split("/")
    return "/subscriptions/%s/resourceGroups/%s/providers/%s/%s" % (
        SUB, group, namespace, "/".join(v for pair in zip(types, names) for v in pair))


def row(kind, name, group="prod", **extra):
    return {"id": rid(kind, name, group), "name": name, "type": kind,
            "location": "usgovvirginia", "resourceGroup": group, "tags": {"env": "prod"}, **extra}


class AzureRunner:
    def __init__(self, resources, details=None, cloud="AzureUSGovernment"):
        self.resources = resources
        self.details = {k.lower(): v for k, v in (details or {}).items()}
        self.cloud = cloud
        self.children = {}
        self.calls = []
        self.fail_show = set()
        self.account_calls = 0
        self.change_identity = False

    def __call__(self, args):
        self.calls.append(args)
        assert args[0] == "az"
        query = args[args.index("--query") + 1]
        if args[1:3] == ["cloud", "show"]:
            data = {"name": self.cloud}
        else:
            assert args[args.index("--subscription") + 1] == SUB
            if args[1:3] == ["account", "show"]:
                self.account_calls += 1
                data = {"id": SUB.upper(), "tenantId": "tenant",
                        "environmentName": self.cloud,
                        "user": {"name": "changed" if self.change_identity and self.account_calls > 1 else "reader"},
                        "accessToken": "DO_NOT_RECORD"}
            elif args[1:3] == ["resource", "list"]:
                data = self.resources
            elif args[1:3] == ["resource", "show"]:
                key = args[args.index("--ids") + 1].lower()
                if key in self.fail_show:
                    raise RuntimeError("read denied")
                data = self.details[key]
            else:
                prefix = tuple(args[1:args.index("--subscription")])
                data = self.children[prefix]
        # Apply the actual CLI projection, catching unsafe or invalid queries.
        return json.dumps(jmespath.search(query, data))


class AzureInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inventory = load("inventory_cloud_resources")

    def test_commercial_and_government_identity_and_metadata_redaction(self):
        for cloud in ("AzureCloud", "AzureUSGovernment"):
            raw = row("Microsoft.Storage/storageAccounts", "evidence", properties={"key": "DO_NOT_RECORD"})
            runner = AzureRunner([raw], cloud=cloud)
            scope = self.inventory.inventory_azure(SUB.upper(), [], runner)
            self.assertEqual(scope["subscription"], SUB)
            self.assertEqual(scope["provenance"]["cloudEnvironment"],
                             "azure" if cloud == "AzureCloud" else "azure-us-government")
            self.assertNotIn("DO_NOT_RECORD", json.dumps(scope))
            self.assertEqual(scope["resources"][0]["name"], "evidence")

    def test_subscription_level_objects_are_reported_as_excluded(self):
        item = {"id": "/subscriptions/" + SUB + "/providers/Microsoft.Authorization/policyAssignments/policy",
                "type": "Microsoft.Authorization/policyAssignments", "name": "policy"}
        scope = self.inventory.inventory_azure(SUB, [], AzureRunner([item]))
        self.assertEqual(scope["resources"], [])
        self.assertIn("microsoft.authorization/policyassignments", scope["provenance"]["excludedResourceTypes"])

    def test_same_names_in_two_resource_groups_keep_distinct_coverage_identities(self):
        rows = [row("Microsoft.Compute/virtualMachines", "web", group) for group in ("one", "two")]
        runner = AzureRunner(rows, {r["id"]: {"properties": {}} for r in rows})
        resources = self.inventory.inventory_azure(SUB, [], runner)["resources"]
        self.assertEqual(len(resources), 2)
        self.assertEqual(len({r["identifier"] for r in resources}), 2)
        self.assertEqual({r["name"] for r in resources}, {"web"})

    def test_embedded_subnets_listeners_and_vm_network_are_discovered(self):
        vnet = row("Microsoft.Network/virtualNetworks", "vnet")
        subnet = row("Microsoft.Network/virtualNetworks/subnets", "vnet/apps")
        appgw = row("Microsoft.Network/applicationGateways", "edge")
        listener = row("Microsoft.Network/applicationGateways/httpListeners", "edge/https")
        vm = row("Microsoft.Compute/virtualMachines", "web")
        nic = row("Microsoft.Network/networkInterfaces", "web-nic")
        details = {
            vnet["id"]: {"properties": {"subnets": [subnet]}},
            appgw["id"]: {"properties": {"httpListeners": [listener],
                             "gatewayIPConfigurations": [{"properties": {"subnet": {"id": subnet["id"]}}}],
                             "sslCertificates": [{"password": "DO_NOT_RECORD"}]}},
            vm["id"]: {"properties": {"networkProfile": {"networkInterfaces": [{"id": nic["id"]}]}, "userData": "DO_NOT_RECORD"}},
            nic["id"]: {"properties": {"ipConfigurations": [{"properties": {"subnet": {"id": subnet["id"]}}}]}},
        }
        scope = self.inventory.inventory_azure(SUB, [], AzureRunner([vnet, appgw, vm, nic], details))
        by_type = {r["type"]: r for r in scope["resources"]}
        self.assertEqual(by_type[subnet["type"]]["network"], vnet["id"].lower())
        self.assertEqual(by_type[vm["type"]]["subnet"], subnet["id"].lower())
        self.assertEqual(by_type[listener["type"]]["network"], vnet["id"].lower())
        self.assertNotIn("DO_NOT_RECORD", json.dumps(scope))
        self.assertIn("microsoft.network/networkinterfaces", scope["provenance"]["excludedResourceTypes"])

    def test_sql_and_service_bus_children_are_not_silently_omitted(self):
        server = row("Microsoft.Sql/servers", "sql")
        database = row("Microsoft.Sql/servers/databases", "sql/customer")
        namespace = row("Microsoft.ServiceBus/namespaces", "bus")
        queue = row("Microsoft.ServiceBus/namespaces/queues", "bus/jobs")
        topic = row("Microsoft.ServiceBus/namespaces/topics", "bus/events")
        subscription = row("Microsoft.ServiceBus/namespaces/topics/subscriptions", "bus/events/worker")
        runner = AzureRunner([server, namespace])
        runner.children = {
            ("sql", "db", "list", "--server", "sql", "--resource-group", "prod"): [database],
            ("servicebus", "queue", "list", "--namespace-name", "bus", "--resource-group", "prod"): [queue],
            ("servicebus", "topic", "list", "--namespace-name", "bus", "--resource-group", "prod"): [topic],
            ("servicebus", "topic", "subscription", "list", "--namespace-name", "bus", "--resource-group", "prod", "--topic-name", "events"): [subscription],
        }
        scope = self.inventory.inventory_azure(SUB, [], runner)
        self.assertEqual({r["type"] for r in scope["resources"]},
                         {server["type"], database["type"], queue["type"], topic["type"], subscription["type"]})

    def test_denied_enrichment_is_reported_and_existing_resource_retained(self):
        vm = row("Microsoft.Compute/virtualMachines", "web")
        runner = AzureRunner([vm]); runner.fail_show.add(vm["id"].lower())
        scope = self.inventory.inventory_azure(SUB, [], runner)
        self.assertEqual(len(scope["resources"]), 1)
        self.assertTrue(scope["warnings"])
        self.assertEqual(scope["provenance"]["collectionResults"][0]["status"], "failed")

    def test_unselected_subscription_and_identity_change_fail_closed(self):
        raw = row("Microsoft.Storage/storageAccounts", "evidence")
        raw["id"] = raw["id"].replace(SUB, "00000000-0000-0000-0000-000000000000")
        with self.assertRaisesRegex(RuntimeError, "out-of-scope"):
            self.inventory.inventory_azure(SUB, [], AzureRunner([raw]))
        runner = AzureRunner([]); runner.change_identity = True
        with self.assertRaisesRegex(RuntimeError, "identity changed"):
            self.inventory.inventory_azure(SUB, [], runner)

    def test_invalid_subscription_and_cli_missing_subscription(self):
        with self.assertRaises(ValueError):
            self.inventory.inventory_azure("prod", [], AzureRunner([]))
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.inventory.main(["--provider", "azure"])

    def test_cli_routes_explicit_subscription_to_azure_inventory(self):
        with patch.object(self.inventory, "inventory_azure", return_value={"provider": "azure"}) as discover:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(self.inventory.main(["--provider", "azure", "--subscription", SUB]), 0)
        self.assertEqual(discover.call_args.args[0], SUB)

    def test_failed_subscription_inventory_and_unsupported_cloud_abort_scope(self):
        with self.assertRaisesRegex(RuntimeError, "cloud must match"):
            self.inventory.inventory_azure(SUB, [], AzureRunner([], cloud="AzureChinaCloud"))
        runner = AzureRunner([])
        def denied(args):
            if args[1:3] == ["resource", "list"]:
                raise RuntimeError("subscription inventory denied")
            return runner(args)
        with self.assertRaisesRegex(RuntimeError, "inventory denied"):
            self.inventory.inventory_azure(SUB, [], denied)


class AzurePolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.validator = load("validate_cloud_config")
        cls.renderer = load("render_cloud_config")
        cls.delta = load("coverage_diff", ROOT / "skills/update-cloud-vdr-config/scripts")

    def resource(self, name="web", group="prod"):
        return {"provider": "azure", "type": "Microsoft.Compute/virtualMachines",
                "identifier": rid("Microsoft.Compute/virtualMachines", name, group).lower(),
                "name": name, "tags": {"env": "prod"}, "vdrTags": {}}

    def test_name_and_network_rules_use_tsw_matching_contract(self):
        resource = self.resource()
        self.assertTrue(self.validator.rule_matches({"match": "web"}, resource, "nameRules"))
        self.assertFalse(self.validator.rule_matches({"match": resource["identifier"]}, resource, "nameRules"))
        resource.update(networks=[rid("Microsoft.Network/virtualNetworks", "vnet").lower()],
                        subnets=[rid("Microsoft.Network/virtualNetworks/subnets", "vnet/apps").lower()])
        self.assertTrue(self.validator.rule_matches({"network": "VNET", "subnet": "APPS"}, resource, "networkRules"))

    def test_renderer_and_scope_keys_use_subscription_not_project(self):
        attestation = lambda value: {"value": value, "confidence": "high", "evidence": "operator-confirmed"}
        plan = {"defaults": {"class": attestation("C"), "multiAgency": attestation("false")},
                "scopes": [{"provider": "azure", "subscription": SUB.upper(),
                            "class": attestation("C"), "multiAgency": attestation("false")} ]}
        rendered = yaml.safe_load(self.renderer.render(plan))
        self.assertEqual(rendered["scopes"][0]["subscription"], SUB)
        self.assertNotIn("project", rendered["scopes"][0])
        self.assertEqual(self.validator.scope_key(plan["scopes"][0]), "azure/" + SUB)
        self.assertEqual(self.delta.scope_key(plan["scopes"][0]), "azure/" + SUB)

    def test_azure_coverage_update_preserves_existing_assignments(self):
        rule = {"type": "Microsoft.Compute/virtualMachines", "match": "web",
                "securityImpactProfile": "cr-m_ir-h_ar-m"}
        baseline = {"apiVersion": "vdr.fedramp.io/v1alpha1", "kind": "CloudResourceScoringConfig",
                    "defaults": {"class": "C", "multiAgency": "false"},
                    "scopes": [{"provider": "azure", "subscription": SUB.upper(), "nameRules": [rule]}]}
        inventory = {"scopes": [{"provider": "azure", "subscription": SUB, "resources": [self.resource(), self.resource("worker")]}]}
        candidate = copy.deepcopy(baseline)
        candidate["scopes"][0]["nameRules"].append({**rule, "match": "worker"})
        report = self.delta.analyze(baseline, inventory, "cloud", candidate=candidate)
        self.assertEqual(report["errors"], [])
        self.assertEqual(report["summary"], {"covered-unchanged": 1, "missing-assignment": 1})
        self.assertEqual(report["assignments"][1]["proposedProfile"], "cr-m_ir-h_ar-m")
        candidate["scopes"][0]["nameRules"][0]["securityImpactProfile"] = "cr-h_ir-h_ar-h"
        self.assertTrue(self.delta.analyze(baseline, inventory, "cloud", candidate=candidate)["errors"])

    def test_unknown_or_missing_scope_identity_is_rejected(self):
        for scope in ({"provider": "azure"}, {"provider": "other", "project": "p"}):
            with self.assertRaises(ValueError):
                self.delta.scope_key(scope)

    def test_generated_azure_document_passes_full_offline_validation(self):
        att = lambda value: {"value": value, "confidence": "high", "evidence": "operator-confirmed"}
        scope = {"provider": "azure", "subscription": SUB,
                 "class": att("C"), "multiAgency": att("false"),
                 "nameRules": [{"type": "Microsoft.Compute/virtualMachines", "match": "web",
                                "securityImpactProfile": "cr-m_ir-h_ar-m", "confidence": "high",
                                "evidence": "operator-confirmed", "manualReview": []}]}
        plan = {"defaults": {"class": att("C"), "multiAgency": att("false")}, "scopes": [scope]}
        inventory = {"scopes": [{"provider": "azure", "subscription": SUB, "resources": [self.resource()]}],
                     "summary": {"scopeCount": 1, "resourceCount": 1}}
        coverage = {"inventoryTotal": 1, "assignments": [{
            "scope": "azure/" + SUB, "type": "Microsoft.Compute/virtualMachines",
            "identifier": self.resource()["identifier"], "securityImpactProfile": "cr-m_ir-h_ar-m",
            "resolutionSource": "nameRules[0]", "multiAgency": "false", "multiAgencySource": "scope-default",
            "vector": "M/H/M", "derivationMethod": "direct-vector", "confidence": "high",
            "status": "operator-confirmed", "evidence": "operator-confirmed", "manualReview": []}]}
        self.assertEqual(self.validator.validate(plan, inventory, coverage, self.renderer.render(plan)), [])

    def test_storage_network_rule_and_duplicate_azure_scopes_are_rejected(self):
        errors = []
        self.validator._validate_scope_shape({"provider": "azure", "subscription": SUB,
            "networkRules": [{"network": "vnet", "type": "Microsoft.Storage/storageAccounts",
                              "securityImpactProfile": "cr-m_ir-h_ar-m", "confidence": "high"}]}, "azure/" + SUB, errors)
        self.assertTrue(any("network" in error.lower() for error in errors))
        att = lambda value: {"value": value, "confidence": "high", "evidence": "operator-confirmed"}
        scope = {"provider": "azure", "subscription": SUB, "class": att("C"), "multiAgency": att("false")}
        plan = {"defaults": {"class": att("C"), "multiAgency": att("false")},
                "scopes": [scope, {**scope, "subscription": SUB.upper()}]}
        inventory = {"scopes": [], "summary": {"resourceCount": 0}}
        errors = self.validator.validate(plan, inventory, {"inventoryTotal": 0, "assignments": []}, self.renderer.render(plan))
        self.assertIn("duplicate plan scope identity", errors)


if __name__ == "__main__":
    unittest.main()
