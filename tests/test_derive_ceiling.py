import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from loader import SCRIPTS, load_script

mod = load_script("derive_ceiling")


def vec(c, i, a):
    return {"c": c, "i": i, "a": a}


class DerivationTests(unittest.TestCase):
    def test_minimum_is_applied_per_objective(self):
        result = mod.derive_ceiling(
            vec("H", "L", "M"),
            vec("M", "H", "L"),
        )
        self.assertEqual(
            result,
            {
                "c": "M",
                "i": "L",
                "a": "L",
                "wire": "cr-m_ir-l_ar-l",
                "display": "CR:M/IR:L/AR:L",
            },
        )

    def test_levels_are_normalized(self):
        result = mod.derive_ceiling(
            vec(" h ", "m", "L"),
            vec("H", "M", "l"),
        )
        self.assertEqual(result["wire"], "cr-h_ir-m_ar-l")
        self.assertEqual(result["display"], "CR:H/IR:M/AR:L")

    def test_invalid_objective_rejected(self):
        for invalid in ("", "critical", None, 4):
            with self.assertRaises(mod.DerivationError):
                mod.derive_ceiling(
                    vec(invalid, "M", "L"),
                    vec("M", "M", "L"),
                )

    def test_unknown_objective_rejected(self):
        sso = {**vec("M", "M", "M"), "scope": "component"}
        with self.assertRaises(mod.DerivationError):
            mod.derive_ceiling(sso, vec("M", "M", "M"))


class CliTests(unittest.TestCase):
    SCRIPT = SCRIPTS / "derive_ceiling.py"

    def run_cli(self, document):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "objectives.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(self.SCRIPT), str(path)],
                capture_output=True,
                text=True,
                check=False,
            )

    def test_cli_outputs_ceiling(self):
        result = self.run_cli(
            {"sso": vec("H", "M", "M"), "aso": vec("M", "H", "L")}
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        parsed = json.loads(result.stdout)
        self.assertEqual(parsed["wire"], "cr-m_ir-m_ar-l")
        self.assertEqual(parsed["display"], "CR:M/IR:M/AR:L")

    def test_cli_rejects_invalid_document(self):
        result = self.run_cli({"sso": vec("M", "M", "M")})
        self.assertEqual(result.returncode, 2)
        self.assertIn("error:", result.stderr)


if __name__ == "__main__":
    unittest.main()
