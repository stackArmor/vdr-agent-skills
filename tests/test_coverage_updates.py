import copy
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(skill, script):
    path = ROOT / "skills" / skill / "scripts" / (script + ".py")
    spec = importlib.util.spec_from_file_location(script, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def cloud_resource(name, kind="storage.googleapis.com/Bucket", **extra):
    return {"identifier": name, "type": kind, "tags": {}, "vdrTags": {}, **extra}


def cloud_policy():
    return {
        "apiVersion": "vdr.fedramp.io/v1alpha1",
        "kind": "CloudResourceScoringConfig",
        "defaults": {"class": "D", "multiAgency": "true"},
        "scopes": [
            {
                "provider": "gcp",
                "project": "example-prod",
                "nameRules": [
                    {
                        "type": "storage.googleapis.com/Bucket",
                        "match": "known-*",
                        "securityImpactProfile": "cr-m_ir-h_ar-m",
                    }
                ],
            }
        ],
    }


def cloud_inventory(*resources):
    return {
        "scopes": [
            {"provider": "gcp", "project": "example-prod", "resources": list(resources)}
        ]
    }


def configmap(scoring=None, **data):
    return {
        "kind": "ConfigMap",
        "apiVersion": "v1",
        "metadata": {"name": "vdr-fedramp", "namespace": "fedramp-vdr-trivy"},
        "data": {
            "class": "D",
            "multiAgency": "true",
            "scoring.yaml": json.dumps(scoring or {}),
            **data,
        },
    }


def workload(name, kind="Deployment", namespace="app", **extra):
    return {
        "name": name,
        "kind": kind,
        "namespace": namespace,
        "vdrLabels": {},
        **extra,
    }


def k8s_inventory(*resources, namespace_labels=None):
    return {
        "context": "reviewed-cluster",
        "scope": "all",
        "namespaces": [
            {"name": "app", "vdrLabels": namespace_labels or {}},
            {"name": "other", "vdrLabels": {}},
        ],
        "workloads": list(resources),
    }


class CoverageUpdateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load("update-cloud-vdr-config", "coverage_diff")

    def test_cloud_only_unmatched_resources_need_evaluation(self):
        report = self.mod.analyze(
            cloud_policy(),
            cloud_inventory(cloud_resource("known-new"), cloud_resource("missing")),
            "cloud",
        )
        self.assertEqual(
            report["summary"], {"covered-unchanged": 1, "missing-assignment": 1}
        )
        self.assertIsNone(report["assignments"][0]["newResource"])
        self.assertFalse(report["existingScoresReevaluated"])

    def test_cloud_addition_preserves_existing_score(self):
        baseline = cloud_policy()
        candidate = copy.deepcopy(baseline)
        candidate["scopes"][0]["nameRules"].append(
            {
                "type": "storage.googleapis.com/Bucket",
                "match": "missing",
                "securityImpactProfile": "cr-h_ir-h_ar-h",
            }
        )
        report = self.mod.analyze(
            baseline,
            cloud_inventory(cloud_resource("known-old"), cloud_resource("missing")),
            "cloud",
            candidate,
        )
        self.assertEqual(report["errors"], [])

    def test_cloud_new_project_requires_scope_and_metadata(self):
        baseline = cloud_policy()
        inventory = {
            "scopes": [
                {
                    "provider": "gcp",
                    "project": "new-prod",
                    "resources": [cloud_resource("state")],
                }
            ]
        }
        self.assertEqual(
            self.mod.analyze(baseline, inventory, "cloud")["summary"],
            {"missing-scope": 1},
        )
        candidate = copy.deepcopy(baseline)
        candidate["scopes"].append(
            {
                "provider": "gcp",
                "project": "new-prod",
                "class": "C",
                "multiAgency": "false",
                "nameRules": [
                    {
                        "type": "storage.googleapis.com/Bucket",
                        "match": "state",
                        "securityImpactProfile": "cr-h_ir-h_ar-h",
                    }
                ],
            }
        )
        self.assertEqual(
            self.mod.analyze(baseline, inventory, "cloud", candidate)["errors"], []
        )

    def test_cloud_guard_rejects_catalog_defaults_and_rule_rewrites(self):
        for mutation in ("defaults", "catalog", "rewrite", "delete"):
            with self.subTest(mutation=mutation):
                baseline, candidate = cloud_policy(), cloud_policy()
                if mutation == "defaults":
                    candidate["defaults"]["multiAgency"] = "false"
                elif mutation == "catalog":
                    candidate["archetypes"] = {
                        "new-name": {"cr": "M", "ir": "M", "ar": "M"}
                    }
                elif mutation == "rewrite":
                    candidate["scopes"][0]["nameRules"][0]["securityImpactProfile"] = (
                        "cr-l_ir-l_ar-l"
                    )
                else:
                    candidate["scopes"][0]["nameRules"] = []
                self.assertTrue(
                    self.mod.analyze(
                        baseline,
                        cloud_inventory(cloud_resource("known-old")),
                        "cloud",
                        candidate,
                    )["errors"]
                )

    def test_new_rules_cannot_touch_covered_resources_even_with_same_score(self):
        baseline = cloud_policy()
        candidate = copy.deepcopy(baseline)
        candidate["scopes"][0]["nameRules"].append(
            {
                "type": "storage.googleapis.com/Bucket",
                "match": "*",
                "securityImpactProfile": "cr-m_ir-h_ar-m",
            }
        )
        errors = self.mod.analyze(
            baseline,
            cloud_inventory(cloud_resource("known-old"), cloud_resource("missing")),
            "cloud",
            candidate,
        )["errors"]
        self.assertTrue(any("already-covered" in error for error in errors))

    def test_new_scope_broad_defaults_and_new_reachability_are_rejected(self):
        baseline = cloud_policy()
        candidate = copy.deepcopy(baseline)
        candidate["scopes"].append(
            {
                "provider": "gcp",
                "project": "new-prod",
                "securityImpactProfile": "cr-h_ir-h_ar-h",
            }
        )
        self.assertTrue(
            any(
                "broad SIP" in error
                for error in self.mod.analyze(
                    baseline,
                    cloud_inventory(cloud_resource("known-old")),
                    "cloud",
                    candidate,
                )["errors"]
            )
        )
        candidate = copy.deepcopy(baseline)
        candidate["scopes"][0]["nameRules"].append(
            {
                "type": "storage.googleapis.com/Bucket",
                "match": "missing",
                "securityImpactProfile": "cr-m_ir-h_ar-m",
                "internetReachable": "false",
            }
        )
        self.assertTrue(
            any(
                "reachability" in error
                for error in self.mod.analyze(
                    baseline,
                    cloud_inventory(cloud_resource("missing")),
                    "cloud",
                    candidate,
                )["errors"]
            )
        )

    def test_cloud_attribute_resolution_is_independent(self):
        baseline = cloud_policy()
        baseline["scopes"][0]["nameRules"][0]["internetReachable"] = "false"
        baseline["scopes"][0]["nameRules"][0]["internetReachableJustification"] = (
            "Approved source allowlist"
        )
        report = self.mod.analyze(
            baseline,
            cloud_inventory(cloud_resource("known-old")),
            "cloud",
            copy.deepcopy(baseline),
        )
        self.assertEqual(report["errors"], [])

    def test_invalid_override_blocks_update_not_automatic_repair(self):
        baseline = cloud_policy()
        inventory = cloud_inventory(
            cloud_resource("known-old", vdrTags={self.mod.SIP: "not-a-profile"})
        )
        report = self.mod.analyze(baseline, inventory, "cloud", copy.deepcopy(baseline))
        self.assertEqual(report["summary"], {"blocked-existing-profile": 1})
        self.assertTrue(report["errors"])

    def test_duplicate_identifiers_and_scopes_fail(self):
        with self.assertRaises(ValueError):
            self.mod.analyze(
                cloud_policy(),
                cloud_inventory(cloud_resource("same"), cloud_resource("same")),
                "cloud",
            )
        baseline = cloud_policy()
        baseline["scopes"].append(copy.deepcopy(baseline["scopes"][0]))
        with self.assertRaises(ValueError):
            self.mod.analyze(baseline, cloud_inventory(), "cloud")

    def test_prior_inventory_reports_new_and_not_observed_without_deletion(self):
        report = self.mod.analyze(
            cloud_policy(),
            cloud_inventory(cloud_resource("known-new")),
            "cloud",
            previous=cloud_inventory(cloud_resource("known-gone")),
        )
        self.assertTrue(report["assignments"][0]["newResource"])
        self.assertEqual(
            report["notObserved"],
            [["gcp/example-prod", "storage.googleapis.com/Bucket", "known-gone"]],
        )

    def test_degraded_inventory_warning_remains_visible(self):
        inventory = cloud_inventory(cloud_resource("known-old"))
        inventory["scopes"][0]["warnings"] = ["Control asset API unavailable"]
        report = self.mod.analyze(cloud_policy(), inventory, "cloud")
        self.assertIn("Control asset API unavailable", report["warnings"][0])

    def test_cross_type_same_name_is_not_a_duplicate(self):
        inventory = cloud_inventory(
            cloud_resource("same"),
            cloud_resource("same", kind="run.googleapis.com/Service"),
        )
        self.assertEqual(
            self.mod.analyze(cloud_policy(), inventory, "cloud")["inventoryTotal"], 2
        )

    def test_k8s_namespace_coverage_is_not_reassessed_for_new_workload(self):
        baseline = configmap(
            {
                "namespaceRules": [
                    {"match": "app", "securityImpactProfile": "cr-m_ir-h_ar-m"}
                ]
            }
        )
        report = self.mod.analyze(baseline, k8s_inventory(workload("brand-new")), "k8s")
        self.assertEqual(report["summary"], {"covered-unchanged": 1})

    def test_k8s_add_only_missing_assignment(self):
        baseline = configmap(
            {
                "nameRules": [
                    {
                        "namespace": "app",
                        "match": "old",
                        "securityImpactProfile": "cr-m_ir-h_ar-m",
                    }
                ]
            }
        )
        policy = self.mod.scoring(baseline)[1]
        policy["nameRules"].append(
            {
                "namespace": "app",
                "match": "new",
                "securityImpactProfile": "root-secrets.identity-control.mission-essential",
            }
        )
        candidate = configmap(policy)
        report = self.mod.analyze(
            baseline, k8s_inventory(workload("old"), workload("new")), "k8s", candidate
        )
        self.assertEqual(report["errors"], [])

    def test_k8s_label_precedence_and_invalid_label_blocker(self):
        baseline = configmap(
            {
                "namespaceRules": [
                    {"match": "app", "securityImpactProfile": "cr-m_ir-h_ar-m"}
                ]
            }
        )
        inventory = k8s_inventory(
            workload("valid", vdrLabels={self.mod.SIP: "cr-h_ir-h_ar-h"}),
            workload("bad", vdrLabels={self.mod.SIP: "unknown"}),
        )
        report = self.mod.analyze(baseline, inventory, "k8s")
        self.assertEqual(
            report["summary"], {"covered-unchanged": 1, "blocked-existing-profile": 1}
        )
        self.assertEqual(report["assignments"][0]["profile"], "cr-h_ir-h_ar-h")

    def test_k8s_default_unclassified_is_missing_but_intentional_default_is_covered(
        self,
    ):
        for profile, status in (
            ("unclassified", "missing-assignment"),
            ("cr-h_ir-h_ar-h", "covered-unchanged"),
        ):
            baseline = configmap({"defaults": {"securityImpactProfile": profile}})
            self.assertEqual(
                self.mod.analyze(baseline, k8s_inventory(workload("api")), "k8s")[
                    "summary"
                ],
                {status: 1},
            )

    def test_k8s_name_rule_cannot_rescore_other_kind_with_same_name(self):
        baseline = configmap(
            {
                "kindRules": [
                    {
                        "kind": "Deployment",
                        "namespace": "app",
                        "match": "same",
                        "securityImpactProfile": "cr-m_ir-h_ar-m",
                    }
                ]
            }
        )
        candidate = configmap(
            {
                **self.mod.scoring(baseline)[1],
                "nameRules": [
                    {
                        "namespace": "app",
                        "match": "same",
                        "securityImpactProfile": "cr-h_ir-h_ar-h",
                    }
                ],
            }
        )
        report = self.mod.analyze(
            baseline,
            k8s_inventory(workload("same"), workload("same", kind="Job")),
            "k8s",
            candidate,
        )
        self.assertTrue(
            any("existing effective assignment" in error for error in report["errors"])
        )

    def test_k8s_scalar_ceiling_and_ingress_attestations_frozen(self):
        baseline = configmap(
            {},
            securityRequirementsCeiling="cr-m_ir-m_ar-m",
            notInternetAccessibleIngressClasses="- corporate",
        )
        for key in (
            "class",
            "multiAgency",
            "securityRequirementsCeiling",
            "notInternetAccessibleIngressClasses",
        ):
            candidate = copy.deepcopy(baseline)
            candidate["data"][key] = "changed"
            self.assertTrue(
                self.mod.analyze(baseline, k8s_inventory(), "k8s", candidate)["errors"]
            )

    def test_k8s_prior_snapshot_must_match_context_and_scope(self):
        prior = k8s_inventory()
        prior["context"] = "another-cluster"
        with self.assertRaises(ValueError):
            self.mod.analyze(configmap(), k8s_inventory(), "k8s", previous=prior)

    def test_custom_profiles_validate_without_changing_catalog(self):
        baseline = configmap(
            {
                "archetypes": {"custom": {"cr": "L", "ir": "M", "ar": "H"}},
                "namespaceRules": [{"match": "app", "securityImpactProfile": "custom"}],
            }
        )
        self.assertEqual(
            self.mod.analyze(baseline, k8s_inventory(workload("api")), "k8s")[
                "summary"
            ],
            {"covered-unchanged": 1},
        )
        self.assertIsNotNone(
            self.mod.profile_error(
                "custom", {"archetypes": {"custom": {}}}, self.mod.load_validator()
            )
        )

    def test_go_negated_character_class_matching(self):
        self.assertTrue(self.mod.path_match("api-[^a]", "api-b"))
        self.assertFalse(self.mod.path_match("api-[^a]", "api-a"))

    def test_duplicate_yaml_keys_fail(self):
        with self.assertRaises(ValueError):
            self.mod.yaml_documents("kind: ConfigMap\nkind: ConfigMap\n")

    def test_cli_writes_report_and_fails_unsafe_candidate(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            baseline, candidate = cloud_policy(), cloud_policy()
            candidate["defaults"]["class"] = "B"
            for name, value in (
                ("baseline", baseline),
                ("candidate", candidate),
                ("inventory", cloud_inventory(cloud_resource("known-old"))),
            ):
                (root / name).write_text(json.dumps(value))
            command = [
                "python3",
                str(ROOT / "skills/update-cloud-vdr-config/scripts/coverage_diff.py"),
                "--mode",
                "cloud",
                "--baseline",
                str(root / "baseline"),
                "--inventory",
                str(root / "inventory"),
                "--candidate",
                str(root / "candidate"),
                "--output",
                str(root / "report"),
            ]
            result = subprocess.run(
                command, capture_output=True, text=True, check=False
            )
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertTrue(json.loads((root / "report").read_text())["errors"])


class ClusterSnapshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load("update-k8s-vdr-configmap", "snapshot_cluster")

    def test_read_only_context_pinned_snapshot(self):
        with (
            tempfile.TemporaryDirectory() as folder,
            patch.object(self.mod.subprocess, "run") as run,
        ):
            inventory = k8s_inventory(workload("api"))
            run.side_effect = [
                subprocess.CompletedProcess(
                    [], 0, stdout="kind: ConfigMap\n", stderr=""
                ),
                subprocess.CompletedProcess(
                    [], 0, stdout=json.dumps(inventory), stderr=""
                ),
            ]
            target = Path(folder) / "snapshot"
            self.mod.capture(context="reviewed-cluster", output_directory=target)
            args = run.call_args_list[0].args[0]
            self.assertEqual(
                args[:4], ["kubectl", "--context", "reviewed-cluster", "get"]
            )
            self.assertIn("configmap", args)
            self.assertEqual(
                (target / "baseline-configmap.yaml").read_text(), "kind: ConfigMap\n"
            )
            self.assertEqual(
                json.loads((target / "workload-inventory.json").read_text()), inventory
            )

    def test_failed_configmap_read_does_not_invent_empty_baseline(self):
        with (
            tempfile.TemporaryDirectory() as folder,
            patch.object(self.mod.subprocess, "run") as run,
        ):
            run.return_value = subprocess.CompletedProcess(
                [], 1, stdout="", stderr="forbidden"
            )
            target = Path(folder) / "snapshot"
            with self.assertRaises(ValueError):
                self.mod.capture(context="reviewed-cluster", output_directory=target)
            self.assertFalse(target.exists())
            self.assertEqual(run.call_count, 1)

    def test_failed_inventory_does_not_write_partial_snapshot(self):
        with (
            tempfile.TemporaryDirectory() as folder,
            patch.object(self.mod.subprocess, "run") as run,
        ):
            run.side_effect = [
                subprocess.CompletedProcess(
                    [], 0, stdout="kind: ConfigMap\n", stderr=""
                ),
                subprocess.CompletedProcess([], 1, stdout="", stderr="incomplete"),
            ]
            target = Path(folder) / "snapshot"
            with self.assertRaises(ValueError):
                self.mod.capture(context="reviewed-cluster", output_directory=target)
            self.assertFalse(target.exists())

    def test_local_baseline_skips_live_read_and_keeps_namespace_scope(self):
        with (
            tempfile.TemporaryDirectory() as folder,
            patch.object(self.mod.subprocess, "run") as run,
        ):
            baseline = Path(folder) / "baseline.yaml"
            baseline.write_text("kind: ConfigMap\n")
            run.return_value = subprocess.CompletedProcess(
                [], 0, stdout=json.dumps(k8s_inventory()), stderr=""
            )
            self.mod.capture(
                context="reviewed-cluster",
                output_directory=Path(folder) / "snapshot",
                baseline_file=baseline,
                namespace="app",
            )
            self.assertEqual(run.call_count, 1)
            self.assertEqual(run.call_args.args[0][-2:], ["-n", "app"])


if __name__ == "__main__":
    unittest.main()
