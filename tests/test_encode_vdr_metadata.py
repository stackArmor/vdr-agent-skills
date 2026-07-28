import json
import subprocess
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (
    REPO_ROOT
    / "skills"
    / "tag-terraform-vdr-assets"
    / "scripts"
    / "encode_vdr_metadata.py"
)


class EncodeSIPMetadataTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--provider", "gcp", *args],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_encodes_decision_trace_under_only_sip_key(self):
        result = self.run_cli(
            "--security-impact-profile",
            "regulated-data.authoritative-record.shared-critical-path",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        document = json.loads(result.stdout)
        self.assertEqual(
            document["canonical"],
            {
                "vdr.fedramp.io/security-impact-profile":
                    "regulated-data.authoritative-record.shared-critical-path"
            },
        )
        self.assertEqual(document["vector"], {"cr": "H", "ir": "H", "ar": "H"})

    def test_accepts_direct_vector_and_named_archetype(self):
        direct = self.run_cli("--security-impact-profile", "cr-h_ir-m_ar-l")
        self.assertEqual(direct.returncode, 0, direct.stderr)
        self.assertEqual(
            json.loads(direct.stdout)["vector"],
            {"cr": "H", "ir": "M", "ar": "L"},
        )

        named = self.run_cli("--security-impact-profile", "platform-foundation")
        self.assertEqual(named.returncode, 0, named.stderr)
        self.assertEqual(
            json.loads(named.stdout)["vector"],
            {"cr": "L", "ir": "H", "ar": "H"},
        )

    def test_rejects_retired_transport_flags(self):
        for flag, value in (("--archetype", "platform-foundation"), ("--asset-value", "High")):
            result = self.run_cli(flag, value)
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
