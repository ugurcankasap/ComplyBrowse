import json
import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "qa_tests" / "macos_fixtures"
SANITIZER_PATH = ROOT / "tools" / "sanitize_public_report.py"


spec = importlib.util.spec_from_file_location("sanitize_public_report", SANITIZER_PATH)
sanitizer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sanitizer)


class TestPublicReportSanitization(unittest.TestCase):
    def test_macos_private_fields_are_removed_and_public_schema_remains(self):
        source = json.loads((FIXTURES / "public_report_input.json").read_text(encoding="utf-8"))
        report = sanitizer.build_public_report(source)

        self.assertEqual(report["browser"], "Firefox")
        self.assertEqual(report["platform"], "macOS")
        result = report["results"][0]
        self.assertEqual(
            set(result),
            {
                "browser",
                "platform",
                "control_id",
                "expected_value",
                "observed_value",
                "verdict",
                "evidence_type",
                "source_type",
            },
        )
        self.assertEqual(result["control_id"], "1.1")
        self.assertEqual(result["source_type"], "user_preference")
        self.assertNotIn("/Users/", json.dumps(report))
        self.assertNotIn("profile-alpha", json.dumps(report))
        self.assertNotIn("work-profile", json.dumps(report))
        self.assertNotIn("SERIAL-SYNTHETIC", json.dumps(report))
        self.assertNotIn("12345678-1234-4234-8234-123456789abc", json.dumps(report))
        self.assertNotIn("abcdefghijklmnopabcdefghijklmnop", json.dumps(report))
        self.assertNotIn("<plist>", json.dumps(report))
        self.assertNotIn("mdm_enrollment_id", json.dumps(report))
        self.assertNotIn("organization", json.dumps(report))


if __name__ == "__main__":
    unittest.main(verbosity=2)
