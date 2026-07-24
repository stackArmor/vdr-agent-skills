import itertools
import json
import subprocess
import sys
import unittest
from pathlib import Path

from loader import SCRIPTS, load_script

mod = load_script("derive_requirements")


def doc(sso, aso, components):
    return {"sso": sso, "aso": aso, "components": components}


def vec(c, i, a):
    return {"c": c, "i": i, "a": a}


class MathTests(unittest.TestCase):
    def test_normalize_level_accepts_case_insensitive(self):
        self.assertEqual(mod.normalize_level("m", "x"), "M")
        self.assertEqual(mod.normalize_level(" H ", "x"), "H")

    def test_normalize_level_rejects_garbage(self):
        for bad in ("", "Z", None, 3, "medium?"):
            with self.assertRaises(mod.DerivationError):
                mod.normalize_level(bad, "x")

    def test_normalize_vector_rejects_unknown_objectives(self):
        with self.assertRaises(mod.DerivationError):
            mod.normalize_vector({"c": "M", "i": "M", "a": "M", "q": "H"}, "x")

    def test_minimum_is_per_objective(self):
        self.assertEqual(
            mod.minimum(vec("H", "L", "M"), vec("M", "H", "M")),
            vec("M", "L", "M"),
        )

    def test_label_roundtrip_all_27(self):
        for c, i, a in itertools.product("LMH", repeat=3):
            vector = vec(c, i, a)
            label = mod.label_for(vector)
            self.assertRegex(label, r"^cr-[lmh]_ir-[lmh]_ar-[lmh]$")
            self.assertEqual(mod.vector_for_label(label), vector)

    def test_vector_for_label_rejects_bad_labels(self):
        for bad in ("cr-x_ir-m_ar-l", "cr-m.ir-m.ar-m", "", "cr-m_ir-m", None):
            with self.assertRaises(mod.DerivationError):
                mod.vector_for_label(bad)

    def test_catalog_has_27_unique_entries(self):
        text = mod.catalog_yaml()
        self.assertTrue(text.startswith("archetypes:\n"))
        keys = [line.strip() for line in text.splitlines() if line.strip().startswith('"')]
        self.assertEqual(len(keys), 27)
        self.assertEqual(len(set(keys)), 27)
        self.assertEqual(text.count("lens: requirements"), 27)
        self.assertIn('"cr-l_ir-l_ar-l":', text)
        self.assertIn("{lens: requirements, cr: H, ir: M, ar: L}", text)


class DeriveTests(unittest.TestCase):
    def test_envelope_and_capped_flags(self):
        result = mod.derive(doc(
            vec("M", "M", "M"), vec("M", "M", "L"),
            [{"id": "ns/Deployment/db", "cso": vec("H", "H", "M")}],
        ))
        self.assertEqual(result["envelope"], vec("M", "M", "L"))
        component = result["components"][0]
        self.assertEqual(component["final"], vec("M", "M", "L"))
        self.assertEqual(component["capped"], {"c": True, "i": True, "a": True})
        self.assertEqual(component["securityRequirements"], "cr-m_ir-m_ar-l")
        self.assertEqual(result["labelValuesUsed"], ["cr-m_ir-m_ar-l"])

    def test_component_below_envelope_is_untouched(self):
        result = mod.derive(doc(
            vec("H", "H", "H"), vec("M", "M", "M"),
            [{"id": "ns/Deployment/web", "cso": vec("L", "M", "L")}],
        ))
        component = result["components"][0]
        self.assertEqual(component["final"], vec("L", "M", "L"))
        self.assertEqual(component["capped"], {"c": False, "i": False, "a": False})

    def test_breakout_restores_component_objective(self):
        result = mod.derive(doc(
            vec("M", "M", "M"), vec("M", "M", "M"),
            [{"id": "ns/Deployment/agent-updater", "cso": vec("M", "H", "M"),
              "breakouts": [{"objective": "i",
                             "category": "agency-endpoint-delivery",
                             "justification": "controls the endpoint agent update channel"}]}],
        ))
        component = result["components"][0]
        self.assertEqual(component["final"], vec("M", "H", "M"))
        self.assertEqual(component["capped"], {"c": False, "i": False, "a": False})
        self.assertEqual(component["securityRequirements"], "cr-m_ir-h_ar-m")

    def test_noop_breakout_rejected(self):
        with self.assertRaises(mod.DerivationError):
            mod.derive(doc(
                vec("H", "H", "H"), vec("H", "H", "H"),
                [{"id": "x", "cso": vec("M", "M", "M"),
                  "breakouts": [{"objective": "i",
                                 "category": "cross-system-trust-anchor",
                                 "justification": "y"}]}],
            ))

    def test_unknown_breakout_category_rejected(self):
        with self.assertRaises(mod.DerivationError):
            mod.derive(doc(
                vec("M", "M", "M"), vec("M", "M", "M"),
                [{"id": "x", "cso": vec("H", "M", "M"),
                  "breakouts": [{"objective": "c", "category": "because-i-said-so",
                                 "justification": "y"}]}],
            ))

    def test_duplicate_breakout_objective_rejected(self):
        with self.assertRaises(mod.DerivationError):
            mod.derive(doc(
                vec("M", "M", "M"), vec("M", "M", "M"),
                [{"id": "x", "cso": vec("H", "H", "M"),
                  "breakouts": [
                      {"objective": "c", "category": "cross-system-trust-anchor",
                       "justification": "y"},
                      {"objective": "c", "category": "shared-csp-infrastructure",
                       "justification": "z"}]}],
            ))

    def test_breakout_requires_justification(self):
        with self.assertRaises(mod.DerivationError):
            mod.derive(doc(
                vec("M", "M", "M"), vec("M", "M", "M"),
                [{"id": "x", "cso": vec("H", "M", "M"),
                  "breakouts": [{"objective": "c",
                                 "category": "cross-system-trust-anchor",
                                 "justification": "  "}]}],
            ))

    def test_duplicate_component_ids_rejected(self):
        with self.assertRaises(mod.DerivationError):
            mod.derive(doc(
                vec("M", "M", "M"), vec("M", "M", "M"),
                [{"id": "x", "cso": vec("M", "M", "M")},
                 {"id": "x", "cso": vec("L", "L", "L")}],
            ))


class CliTests(unittest.TestCase):
    SCRIPT = SCRIPTS / "derive_requirements.py"

    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(self.SCRIPT), *args],
                              capture_output=True, text=True)

    def test_emit_catalog(self):
        result = self.run_cli("--emit-catalog")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.count("lens: requirements"), 27)

    def test_derive_happy_path(self):
        payload = doc(vec("M", "M", "M"), vec("M", "M", "L"),
                      [{"id": "ns/Deployment/db", "cso": vec("H", "H", "M")}])
        path = Path(self.id().replace(".", "_") + ".json")
        path.write_text(json.dumps(payload), encoding="utf-8")
        try:
            result = self.run_cli("--derive", str(path))
        finally:
            path.unlink()
        self.assertEqual(result.returncode, 0)
        parsed = json.loads(result.stdout)
        self.assertEqual(parsed["components"][0]["securityRequirements"], "cr-m_ir-m_ar-l")

    def test_derive_invalid_exits_2(self):
        path = Path(self.id().replace(".", "_") + ".json")
        path.write_text(json.dumps({"sso": {"c": "Z", "i": "M", "a": "M"},
                                    "aso": {"c": "M", "i": "M", "a": "M"},
                                    "components": []}), encoding="utf-8")
        try:
            result = self.run_cli("--derive", str(path))
        finally:
            path.unlink()
        self.assertEqual(result.returncode, 2)
        self.assertIn("error:", result.stderr)


if __name__ == "__main__":
    unittest.main()
