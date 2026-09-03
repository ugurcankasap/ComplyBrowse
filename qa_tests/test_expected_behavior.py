import ast
import unittest
from pathlib import Path

from browser_security_agent import BrowserSecurityAgent
from tests.test_framework import TestResult, TestStatus, Severity


ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "config.yaml"

CONTROL_CATALOGS = {
    "edge_cis_controls.txt": ("test_runner.ps1", 26, "Edge reference catalog not found"),
    "chrome_cis_controls.txt": ("chrome_test_runner.ps1", 88, "Chrome CIS control catalog not found"),
    "firefox_security_controls.txt": ("firefox_test_runner.ps1", 60, "Firefox control catalog not found"),
}


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


def extract_powershell_function(source: str, function_name: str):
    marker = f"function {function_name} {{"
    start = source.find(marker)
    if start < 0:
        raise AssertionError(f"PowerShell function not found: {function_name}")
    end = source.find("\nfunction ", start + len(marker))
    return source[start:] if end < 0 else source[start:end]


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


class TestControlCatalogContracts(unittest.TestCase):
    def test_control_catalogs_are_present_and_complete(self):
        for catalog_name, (_, expected_count, _) in CONTROL_CATALOGS.items():
            with self.subTest(catalog=catalog_name):
                catalog_path = ROOT / catalog_name
                self.assertTrue(catalog_path.is_file(), f"Required catalog is missing: {catalog_name}")
                controls = [line for line in catalog_path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]
                self.assertEqual(len(controls), expected_count)

    def test_runners_fail_when_required_catalog_is_missing(self):
        for catalog_name, (runner_name, _, error_fragment) in CONTROL_CATALOGS.items():
            with self.subTest(runner=runner_name):
                runner_source = (ROOT / runner_name).read_text(encoding="utf-8-sig")
                missing_catalog_guard = (
                    f"if (-not (Test-Path $catalogPath)) {{" in runner_source
                    and f"{catalog_name}" in runner_source
                    and f'throw "{error_fragment}:' in runner_source
                )
                self.assertTrue(missing_catalog_guard)


class TestCommunityHealthContracts(unittest.TestCase):
    REQUIRED_FILES = (
        ".github/CODEOWNERS",
        ".github/ISSUE_TEMPLATE/bug_report.yml",
        ".github/ISSUE_TEMPLATE/feature_request.yml",
        ".github/ISSUE_TEMPLATE/config.yml",
        ".github/pull_request_template.md",
        ".github/workflows/release.yml",
        "CODE_OF_CONDUCT.md",
        "CONTRIBUTING.md",
        "SECURITY.md",
    )

    def test_required_community_files_exist(self):
        for relative_path in self.REQUIRED_FILES:
            with self.subTest(path=relative_path):
                self.assertTrue((ROOT / relative_path).is_file())

    def test_issue_forms_have_required_fields_and_unique_ids(self):
        for form_name in ("bug_report.yml", "feature_request.yml"):
            with self.subTest(form=form_name):
                content = (ROOT / ".github" / "ISSUE_TEMPLATE" / form_name).read_text(encoding="utf-8")
                self.assertIn("name:", content)
                self.assertIn("description:", content)
                self.assertIn("title:", content)
                self.assertIn("body:", content)
                self.assertNotIn("\t", content)
                field_ids = [
                    line.split(":", 1)[1].strip()
                    for line in content.splitlines()
                    if line.strip().startswith("id:")
                ]
                self.assertTrue(field_ids)
                self.assertEqual(len(field_ids), len(set(field_ids)))

    def test_security_reports_are_routed_to_policy(self):
        config = (ROOT / ".github" / "ISSUE_TEMPLATE" / "config.yml").read_text(encoding="utf-8")
        self.assertIn("blank_issues_enabled: false", config)
        self.assertIn("/security/policy", config)

    def test_readme_exposes_repository_status(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8-sig")
        self.assertIn("actions/workflows/ci.yml/badge.svg", readme)
        self.assertIn("license-MIT", readme)
        version = (ROOT / "VERSION").read_text(encoding="utf-8-sig").strip()
        self.assertIn(f"version-v{version}", readme)
        self.assertTrue((ROOT / "releases" / f"v{version}.md").is_file())

    def test_release_workflow_uses_versioned_notes(self):
        workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        self.assertIn('"v*.*.*"', workflow)
        self.assertIn("contents: write", workflow)
        self.assertIn("gh release create", workflow)
        self.assertIn('releases/$GITHUB_REF_NAME.md', workflow)


class TestEdgeRunnerEvidenceContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runner_source = (ROOT / "test_runner.ps1").read_text(encoding="utf-8-sig")

    def test_observational_controls_do_not_emit_evidence_free_failures(self):
        observational_functions = (
            "Test-MailExfiltration",
            "Test-AITools",
            "Test-CopyPaste",
            "Test-DownloadBypass",
            "Test-M365Auth",
            "Test-SessionHijacking",
            "Test-TokenTheft",
            "Test-ProfileSeparation",
            "Test-StoreExtensions",
            "Test-ExtensionPermissions",
            "Test-DOMAccess",
            "Test-CookieHarvesting",
            "Test-DNS",
            "Test-CASB",
            "Test-EdgeInstalledExtensions",
        )
        for function_name in observational_functions:
            with self.subTest(function=function_name):
                function_source = extract_powershell_function(self.runner_source, function_name)
                self.assertNotIn('status = "FAILED"', function_source)

    def test_proxy_bypass_uses_policy_values_for_verdicts(self):
        function_source = extract_powershell_function(self.runner_source, "Test-ProxyBypass")
        self.assertIn('Get-EdgePolicyValue -KeyName "ProxyMode"', function_source)
        self.assertIn('Get-EdgePolicyValue -KeyName "ProxyBypassList"', function_source)
        self.assertIn('status = "PASSED"', function_source)
        self.assertIn('status = "FAILED"', function_source)
        self.assertIn('status = "UNKNOWN"', function_source)


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
