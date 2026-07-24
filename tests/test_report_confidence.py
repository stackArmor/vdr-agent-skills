import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from loader import SCRIPTS, load_script

mod = load_script("report_confidence")


def level_detail(c, i, a, reason="role evidence"):
    return {"c": {"level": c, "reason": reason},
            "i": {"level": i, "reason": reason},
            "a": {"level": a, "reason": reason}}


def rationale_detail(c, i, a):
    return {"c": {"level": c, "rationale": "data profile"},
            "i": {"level": i, "rationale": "data profile"},
            "a": {"level": a, "rationale": "data profile"}}


def make_objectives():
    return {
        "systemProfile": {
            "product": "generic project management saas",
            "confirmedDescription": "portfolio planning records for one agency",
            "sso": rationale_detail("M", "M", "M"),
            "status": "operator-confirmed", "confidence": "high",
            "assumptions": [], "manualReview": [],
        },
        "agencyProfiles": [{
            "agency": "deploying-agency", "relationship": "definite",
            "overlays": [],
            "aso": rationale_detail("M", "M", "L"),
            "status": "operator-confirmed", "confidence": "high",
            "assumptions": [], "manualReview": [],
        }],
        "classPrior": {"class": "C", "divergences": []},
        "sso": {"c": "M", "i": "M", "a": "M"},
        "aso": {"c": "M", "i": "M", "a": "L"},
        "envelope": {"c": "M", "i": "M", "a": "L"},
        "ceilingMode": "semi-hard",
        "multiAgencyDetermination": {
            "scope": "cluster", "clusterDefault": False,
            "justification": "single tenant cluster",
            "status": "operator-confirmed", "confidence": "high",
            "assumptions": [], "manualReview": [],
        },
    }


def make_coverage():
    return {
        "context": "test-context",
        "inventoryTotal": 2,
        "assignments": [
            {"namespace": "app", "kind": "Deployment", "name": "db",
             "componentObjectives": level_detail("H", "H", "M"),
             "vector": "M/M/L", "securityRequirements": "cr-m_ir-m_ar-l",
             "capped": {"c": True, "i": True, "a": True},
             "resolutionSource": "nameRule", "status": "agent-inferred",
             "confidence": "medium", "evidence": "statefulset with pvc",
             "assumptions": ["system of record"],
             "manualReview": ["confirm the record store role"]},
            {"namespace": "app", "kind": "Deployment", "name": "agent-updater",
             "componentObjectives": level_detail("M", "H", "L"),
             "vector": "M/H/L", "securityRequirements": "cr-m_ir-h_ar-l",
             "capped": {"c": False, "i": False, "a": False},
             "breakouts": [{"objective": "i",
                            "category": "agency-endpoint-delivery",
                            "justification": "ships agents to agency devices"}],
             "resolutionSource": "nameRule", "status": "agent-inferred",
             "confidence": "medium", "evidence": "update channel service",
             "assumptions": [],
             "manualReview": ["verify endpoint update path"]},
        ],
        "configurationAssumptions": [],
        "summary": {},
    }


class GateTests(unittest.TestCase):
    def check(self, coverage, objectives):
        with tempfile.TemporaryDirectory() as tmp:
            cov = Path(tmp) / "coverage.json"
            obj = Path(tmp) / "objectives.json"
            cov.write_text(json.dumps(coverage), encoding="utf-8")
            obj.write_text(json.dumps(objectives), encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(SCRIPTS / "report_confidence.py"),
                 str(cov), str(obj)],
                capture_output=True, text=True)

    def test_happy_path_prints_sections(self):
        result = self.check(make_coverage(), make_objectives())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("NON-HIGH-CONFIDENCE MANUAL REVIEW (2)", result.stdout)
        self.assertIn("CAPPED COMPONENTS (1)", result.stdout)
        self.assertIn("CR H->M", result.stdout)
        self.assertIn("BREAKOUTS (1)", result.stdout)
        self.assertIn("agency-endpoint-delivery", result.stdout)
        self.assertNotIn("humanReviewCompleted", result.stdout)

    def test_envelope_must_be_min(self):
        objectives = make_objectives()
        objectives["envelope"] = {"c": "H", "i": "M", "a": "L"}
        result = self.check(make_coverage(), objectives)
        self.assertEqual(result.returncode, 2)
        self.assertIn("envelope", result.stderr)

    def test_final_must_match_envelope_math(self):
        coverage = make_coverage()
        coverage["assignments"][0]["vector"] = "H/M/L"
        coverage["assignments"][0]["securityRequirements"] = "cr-h_ir-m_ar-l"
        result = self.check(coverage, make_objectives())
        self.assertEqual(result.returncode, 2)

    def test_label_must_encode_vector(self):
        coverage = make_coverage()
        coverage["assignments"][0]["securityRequirements"] = "cr-l_ir-m_ar-l"
        result = self.check(coverage, make_objectives())
        self.assertEqual(result.returncode, 2)

    def test_capped_flags_must_be_accurate(self):
        coverage = make_coverage()
        coverage["assignments"][0]["capped"]["c"] = False
        result = self.check(coverage, make_objectives())
        self.assertEqual(result.returncode, 2)

    def test_breakout_cannot_be_high_confidence(self):
        coverage = make_coverage()
        coverage["assignments"][1]["confidence"] = "high"
        coverage["assignments"][1]["manualReview"] = []
        result = self.check(coverage, make_objectives())
        self.assertEqual(result.returncode, 2)

    def test_noop_breakout_rejected(self):
        coverage = make_coverage()
        record = coverage["assignments"][1]
        record["componentObjectives"] = level_detail("M", "M", "L")
        record["vector"] = "M/M/L"
        record["securityRequirements"] = "cr-m_ir-m_ar-l"
        result = self.check(coverage, make_objectives())
        self.assertEqual(result.returncode, 2)

    def test_unknown_breakout_category_rejected(self):
        coverage = make_coverage()
        coverage["assignments"][1]["breakouts"][0]["category"] = "vibes"
        result = self.check(coverage, make_objectives())
        self.assertEqual(result.returncode, 2)

    def test_inventory_equation_enforced(self):
        coverage = make_coverage()
        coverage["inventoryTotal"] = 3
        result = self.check(coverage, make_objectives())
        self.assertEqual(result.returncode, 2)

    def test_duplicate_assignments_rejected(self):
        coverage = make_coverage()
        coverage["assignments"].append(copy.deepcopy(coverage["assignments"][0]))
        coverage["inventoryTotal"] = 3
        result = self.check(coverage, make_objectives())
        self.assertEqual(result.returncode, 2)

    def test_high_confidence_requires_empty_review(self):
        coverage = make_coverage()
        coverage["assignments"][0]["confidence"] = "high"
        result = self.check(coverage, make_objectives())
        self.assertEqual(result.returncode, 2)

    def test_definite_agency_max_sets_aso(self):
        objectives = make_objectives()
        objectives["agencyProfiles"].append({
            "agency": "second-agency", "relationship": "definite",
            "overlays": [],
            "aso": rationale_detail("H", "M", "L"),
            "status": "agent-inferred", "confidence": "medium",
            "assumptions": [], "manualReview": ["confirm agency data profile"],
        })
        result = self.check(make_coverage(), objectives)
        self.assertEqual(result.returncode, 2)
        self.assertIn("aso", result.stderr)

    def test_namespace_scope_requires_namespaces(self):
        objectives = make_objectives()
        objectives["multiAgencyDetermination"]["scope"] = "namespace"
        result = self.check(make_coverage(), objectives)
        self.assertEqual(result.returncode, 2)

    def test_ceiling_mode_enforced(self):
        objectives = make_objectives()
        objectives["ceilingMode"] = "hard"
        result = self.check(make_coverage(), objectives)
        self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
