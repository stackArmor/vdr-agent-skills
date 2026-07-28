import importlib.util
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "skills" / "capture-dataflow" / "scripts" / "capture_dataflow.py"
SPEC = importlib.util.spec_from_file_location("capture_dataflow", SCRIPT)
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


class DummyCluster:
    pass


def workload(name):
    return {"namespace": "rally", "kind": "deployment", "name": name}


class SuppressionTests(unittest.TestCase):
    def setUp(self):
        self.capture = mod.Capture(DummyCluster())

    def add_edge(self, name, service, *, hairpin):
        self.capture.add_edge(
            workload(name),
            "rally",
            service,
            443,
            "https",
            "declaredConfig",
            "env:BASE_URL; hairpin via example.test" if hairpin else "env:SERVICE_URL",
            internet_transit=hairpin,
        )

    def test_suppresses_only_matching_hairpin_edges(self):
        self.add_edge("worker", "frontend", hairpin=True)
        self.add_edge("worker", "postgres", hairpin=False)
        self.add_edge("other", "frontend", hairpin=True)

        count = mod.suppress_operator_edges(
            self.capture,
            [{
                "from": {"namespace": "rally", "kind": "deployment", "name": "worker"},
                "internetTransit": True,
                "reason": "base URL is link metadata",
            }],
        )

        self.assertEqual(count, 1)
        remaining = list(self.capture.edges.values())
        self.assertEqual(len(remaining), 2)
        self.assertTrue(any(e["from"]["name"] == "worker" and not e["internetTransit"]
                            for e in remaining))
        self.assertTrue(any(e["from"]["name"] == "other" and e["internetTransit"]
                            for e in remaining))

    def test_rejects_unsafe_broad_rule(self):
        self.add_edge("worker", "frontend", hairpin=True)
        with self.assertRaisesRegex(ValueError, "requires at least one edge selector"):
            mod.suppress_operator_edges(
                self.capture,
                [{
                    "from": {"namespace": "rally", "kind": "deployment", "name": "worker"},
                    "reason": "remove everything",
                }],
            )

    def test_operator_edge_is_added_after_discovered_edge_is_suppressed(self):
        self.add_edge("worker", "frontend", hairpin=True)
        merge = """
attestation:
  declaredTopologyComplete: false
suppressEdges:
  - from: {namespace: rally, kind: deployment, name: worker}
    internetTransit: true
    reason: "replace conservative fan-out"
edges:
  - from: {namespace: rally, kind: deployment, name: worker}
    to: {namespace: rally, service: auth, port: 443, protocol: https}
    evidence: ["operator: worker calls only auth"]
    internetTransit: true
"""
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "operator-edges.yaml"
            path.write_text(merge, encoding="utf-8")
            attestation = {"declaredTopologyComplete": False}
            mod.apply_merge(self.capture, path, attestation)

        edges = list(self.capture.edges.values())
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0]["to"]["service"], "auth")
        self.assertEqual(edges[0]["sources"], ["operatorDeclared"])
        self.assertIn("1 discovered edges suppressed", self.capture.stages[-1]["coverage"])


class MermaidTests(unittest.TestCase):
    def test_compact_exposure_omits_ingress_path_nodes(self):
        doc = {
            "sources": [],
            "exposedWorkloads": [{
                "namespace": "rally",
                "kind": "deployment",
                "name": "frontend",
                "via": ["ingress/rally/frontend (class gce)"],
                "publicHosts": ["rally.example.test"],
            }],
            "edges": [],
            "unresolved": [],
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = mod.write_mermaid(
                None,
                doc,
                "2026-07-28T00:00:00Z",
                temp_dir,
                compact_exposure=True,
            )
            mermaid = Path(paths[0]).read_text(encoding="utf-8")

        self.assertIn("internet --> w_rally_deployment_frontend", mermaid)
        self.assertNotIn("ingress/rally/frontend", mermaid)
        self.assertNotIn("class gce", mermaid)
        self.assertNotIn("subgraph edgezone", mermaid)


if __name__ == "__main__":
    unittest.main()
