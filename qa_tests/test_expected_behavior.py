import ast
import unittest
from pathlib import Path

from browser_security_agent import BrowserSecurityAgent
from tests.test_framework import TestResult, TestStatus, Severity


ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "config.yaml"


def parse_declared_test_ids(config_path: Path):
    """Parse declared test IDs under each `package_*` block from raw config text."""
    package_test_ids = {}
    current_package = None
    in_test_packages = False

    for raw_line in config_path.read_text(encoding="utf-8").splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        indent = len(raw_line) - len(raw_line.lstrip(" "))

        if stripped == "test_packages:":
            in_test_packages = True
            current_package = None
            continue

        if not in_test_packages:
            continue

        if indent == 2 and stripped.endswith(":") and stripped.startswith("package_"):
            current_package = stripped[:-1]
            package_test_ids[current_package] = []
            continue

        if indent == 0:
            in_test_packages = False
            current_package = None
            continue

        if current_package and indent >= 6 and stripped.startswith("- test_id:"):
            test_id = stripped.split(":", 1)[1].strip().strip('"').strip("'")
            package_test_ids[current_package].append(test_id)

    return package_test_ids


class TestConfigAndPlanContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.agent = BrowserSecurityAgent(str(CONFIG_PATH))

    def test_package_order_matches_active_packages(self):
        package_order = self.agent.config.get("package_order", [])
        active_packages = self.agent.config.get("implementation_scope", {}).get("active_packages")
        self.assertEqual(len(package_order), active_packages)

    def test_package_order_has_no_duplicates(self):
        package_order = self.agent.config.get("package_order", [])
        self.assertEqual(len(package_order), len(set(package_order)))

    def test_package_plan_is_resolvable(self):
        package_plan = self.agent._get_package_plan()
        self.assertEqual(len(package_plan), 10)
        for entry in package_plan:
            self.assertIn("key", entry)
            self.assertIn("name", entry)
            self.assertIn("runner", entry)
            self.assertTrue(callable(entry["runner"]))


class TestRunnerOutputContracts(unittest.TestCase):
    ALLOWED_RESULT_STATUSES = {"passed", "failed", "warning", "inconclusive"}

    @classmethod
    def setUpClass(cls):
        cls.agent = BrowserSecurityAgent(str(CONFIG_PATH))
        cls.package_plan = cls.agent._get_package_plan()
        cls.declared_test_ids = parse_declared_test_ids(CONFIG_PATH)

    def test_each_runner_returns_expected_shape(self):
        for entry in self.package_plan:
            with self.subTest(package=entry["key"]):
                result = entry["runner"]("edge_unmanaged")
                self.assertIsInstance(result, dict)
                self.assertIn("package_id", result)
                self.assertIn("package_name", result)
                self.assertIn("results", result)
                self.assertIn("summary", result)

                self.assertIsInstance(result["results"], list)
                self.assertTrue(result["results"], "Runner should produce at least one test result")
                self.assertTrue(all(isinstance(item, TestResult) for item in result["results"]))

                observed_statuses = {item.status.value for item in result["results"]}
                self.assertTrue(observed_statuses.issubset(self.ALLOWED_RESULT_STATUSES))

                summary = result["summary"]
                self.assertEqual(summary["total"], len(result["results"]))
                observed_total = (
                    summary["passed"]
                    + summary["failed"]
                    + summary["warning"]
                    + summary["inconclusive"]
                )
                self.assertEqual(summary["total"], observed_total)

    def test_runner_test_count_matches_config(self):
        for entry in self.package_plan:
            with self.subTest(package=entry["key"]):
                result = entry["runner"]("edge_unmanaged")
                expected_count = len(self.declared_test_ids.get(entry["key"], []))
                self.assertEqual(len(result["results"]), expected_count)

    def test_runner_test_ids_match_declared_config_ids(self):
        for entry in self.package_plan:
            with self.subTest(package=entry["key"]):
                result = entry["runner"]("edge_unmanaged")
                actual_ids = {item.test_id for item in result["results"]}
                expected_ids = set(self.declared_test_ids.get(entry["key"], []))
                self.assertSetEqual(actual_ids, expected_ids)


class TestNoOutboundNetworkGuardrail(unittest.TestCase):
    FORBIDDEN_MODULES = {
        "requests",
        "httpx",
        "urllib",
        "socket",
        "subprocess",
        "ftplib",
        "smtplib",
        "telnetlib",
        "websocket",
    }

    FORBIDDEN_CALLS = {
        "urlopen",
        "urlretrieve",
        "system",
        "popen",
        "Popen",
        "run",
        "check_output",
    }

    def test_test_packages_do_not_import_network_or_process_modules(self):
        for py_file in sorted((ROOT / "tests").glob("test_package_*.py")):
            with self.subTest(file=py_file.name):
                tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            top_level = alias.name.split(".")[0]
                            self.assertNotIn(top_level, self.FORBIDDEN_MODULES)
                    elif isinstance(node, ast.ImportFrom) and node.module:
                        top_level = node.module.split(".")[0]
                        self.assertNotIn(top_level, self.FORBIDDEN_MODULES)

    def test_test_packages_do_not_call_forbidden_network_process_helpers(self):
        for py_file in sorted((ROOT / "tests").glob("test_package_*.py")):
            with self.subTest(file=py_file.name):
                tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
                for node in ast.walk(tree):
                    if isinstance(node, ast.Call):
                        func_name = None
                        if isinstance(node.func, ast.Name):
                            func_name = node.func.id
                        elif isinstance(node.func, ast.Attribute):
                            func_name = node.func.attr
                        if func_name:
                            self.assertNotIn(func_name, self.FORBIDDEN_CALLS)

    def test_test_packages_do_not_embed_external_urls(self):
        for py_file in sorted((ROOT / "tests").glob("test_package_*.py")):
            with self.subTest(file=py_file.name):
                content = py_file.read_text(encoding="utf-8")
                self.assertNotIn("http://", content.lower())
                self.assertNotIn("https://", content.lower())


class TestResultModelEnrichment(unittest.TestCase):
    def test_legacy_evidence_is_preserved_and_structured(self):
        result = TestResult(
            test_id="T-001",
            test_name="Legacy evidence test",
            package_id="PKG-X",
            browser="edge_unmanaged",
            status=TestStatus.PASSED,
            severity=Severity.LOW,
            evidence=["capture.pcap", "screen.png", "audit.json"]
        )

        payload = result.to_dict()
        self.assertEqual(payload["evidence"], ["capture.pcap", "screen.png", "audit.json"])
        self.assertEqual(len(payload["evidence_items"]), 3)
        kinds = {item["path"]: item["kind"] for item in payload["evidence_items"]}
        self.assertEqual(kinds["capture.pcap"], "network_capture")
        self.assertEqual(kinds["screen.png"], "screenshot")
        self.assertEqual(kinds["audit.json"], "log")

    def test_timeline_secondary_checks_and_comparison_are_serialized(self):
        result = TestResult(
            test_id="T-002",
            test_name="Enriched result",
            package_id="PKG-Y",
            browser="edge_unmanaged",
            status=TestStatus.FAILED,
            severity=Severity.HIGH
        )

        result.add_timeline_event(stage="precheck", outcome="passed", detail="Registry reachable")
        result.add_secondary_check(name="dns_policy", status="warning", detail="Custom DoH allowed")
        result.set_comparison(
            baseline_label="2026-07-baseline",
            current_label="2026-07-run-2",
            metrics={"risk_score": 72, "failed_tests": 19},
            delta={"risk_score": +4, "failed_tests": +1},
            verdict="regressed"
        )

        payload = result.to_dict()
        self.assertEqual(len(payload["timeline"]), 1)
        self.assertEqual(len(payload["secondary_checks"]), 1)
        self.assertEqual(payload["comparison"]["verdict"], "regressed")
        self.assertEqual(payload["comparison"]["delta"]["risk_score"], 4)


if __name__ == "__main__":
    unittest.main(verbosity=2)
