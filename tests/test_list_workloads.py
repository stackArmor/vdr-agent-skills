import unittest

from loader import load_script

mod = load_script("list_workloads")


def deployment_item(labels=None, template_labels=None):
    return {
        "kind": "Deployment",
        "metadata": {"namespace": "app", "name": "web", "labels": labels or {}},
        "spec": {"template": {
            "metadata": {"labels": template_labels or {}},
            "spec": {"containers": [{"name": "web", "image": "registry.example/web:1"}]},
        }},
    }


class LabelTests(unittest.TestCase):
    def test_constants(self):
        self.assertEqual(mod.SECURITY_REQUIREMENTS_LABEL,
                         "vdr.fedramp.io/security-requirements")
        self.assertEqual(mod.LEGACY_ARCHETYPE_LABEL,
                         "vdr.fedramp.io/asset-archetype")

    def test_entry_reports_both_labels(self):
        item = deployment_item(labels={
            "vdr.fedramp.io/security-requirements": "cr-m_ir-m_ar-l",
            "vdr.fedramp.io/asset-archetype": "service-content.bounded-processing.bounded-service",
        })
        entry = mod.workload_entry("Deployment", item)
        self.assertEqual(entry["securityRequirements"], "cr-m_ir-m_ar-l")
        self.assertEqual(entry["legacyArchetype"],
                         "service-content.bounded-processing.bounded-service")
        self.assertNotIn("archetype", entry)
        self.assertNotIn("cloudManagedNamespace", entry)

    def test_pod_template_labels_win(self):
        item = deployment_item(
            labels={"vdr.fedramp.io/security-requirements": "cr-l_ir-l_ar-l"},
            template_labels={"vdr.fedramp.io/security-requirements": "cr-h_ir-h_ar-h"},
        )
        entry = mod.workload_entry("Deployment", item)
        self.assertEqual(entry["securityRequirements"], "cr-h_ir-h_ar-h")


if __name__ == "__main__":
    unittest.main()
