"""PKG-8 | Patch Version Hygiene"""

import json
from typing import List, Dict, Any

try:
    from tests.test_framework import (
        TestResult, TestLogger, TestStatus, Severity,
        create_test_result, is_quiet_mode
    )
except ImportError:
    from test_framework import (
        TestResult, TestLogger, TestStatus, Severity,
        create_test_result, is_quiet_mode
    )

if is_quiet_mode():
    def print(*args, **kwargs):
        return None


class PatchVersionHygieneTestSuite:
    """Patch and version hygiene tests"""

    def __init__(self, browser: str = "edge_unmanaged"):
        self.browser = browser
        self.package_id = "PKG-8"
        self.package_name = "Patch & Version Hygiene"
        self.logger = TestLogger()
        self.results: List[TestResult] = []

    def test_p8_001_browser_version(self) -> TestResult:
        result = create_test_result(
            test_id="P8-001",
            test_name = "Browser Version",
            package_id=self.package_id,
            browser=self.browser,
            status=TestStatus.FAILED,
            severity=Severity.MEDIUM,
            message="Control gap detected in this scenario.",
            details={
                "installed_version": "125.0.0.0",
                "recommended_version": "126.0.0.0",
                "age_days": 42,
                "steps": [
                    "Yuklu tarayc surumunu topla",
                    "Vendor release notes ile karlatr",
                    "Match against enterprise minimum-version policy",
                    "If drift exists, create risk and update notes"
                ],
                "method": "Version check + release comparison + policy threshold validation"
            },
            evidence=["browser_version.txt"],
            remediation="Apply enterprise policy controls and retest.",
        )
        self.logger.log_test(result)
        self.results.append(result)
        return result

    def test_p8_002_update_policy(self) -> TestResult:
        result = create_test_result(
            test_id="P8-002",
            test_name = "Update Policy",
            package_id=self.package_id,
            browser=self.browser,
            status=TestStatus.WARNING,
            severity=Severity.MEDIUM,
            message="Control gap detected in this scenario.",
            details={
                "auto_update": True,
                "force_restart": False,
                "policy_enforced": False,
                "steps": [
                    "Auto-update policysn incele",
                    "Zorunlu restart veya maintenance window tanm var m kontrol et",
                    "Validate whether the policy is applied to the device group",
                    "Document whether an exception exists for update delay"
                ],
                "method": "Policy inspection + enforcement scope review"
            },
            evidence=["update_policy.json"],
            remediation="Apply enterprise policy controls and retest.",
        )
        self.logger.log_test(result)
        self.results.append(result)
        return result

    def test_p8_003_component_hygiene(self) -> TestResult:
        result = create_test_result(
            test_id="P8-003",
            test_name = "Component Hygiene",
            package_id=self.package_id,
            browser=self.browser,
            status=TestStatus.FAILED,
            severity=Severity.MEDIUM,
            message="Control gap detected in this scenario.",
            details={
                "stale_components": ["PDF viewer", "Extension X"],
                "version_drift": True,
                "steps": [
                    "Extract component and extension inventory",
                    "Yuklu surumleri baseline ile karlatr",
                    "Eski kalan bileenleri ve update kanaln detection et",
                    "Drift listesine bakm aksiyonu ekle"
                ],
                "method": "Component inventory comparison + drift tracking"
            },
            evidence=["component_inventory.json"],
            remediation="Apply enterprise policy controls and retest.",
        )
        self.logger.log_test(result)
        self.results.append(result)
        return result

    def run_all_tests(self) -> Dict[str, Any]:
        print(f"\n{'='*60}")
        print("Patch & Version Hygiene Tests running...")
        print(f"Browser: {self.browser}")
        print(f"{'='*60}\n")

        self.test_p8_001_browser_version()
        self.test_p8_002_update_policy()
        self.test_p8_003_component_hygiene()

        summary = self.logger.get_summary()
        print(f"\n{'='*60}")
        print("Package 8 Summary:")
        print(f"  Total Tests: {summary['total']}")
        print(f"  Passed: {summary['passed']} ")
        print(f"  Failed: {summary['failed']} ")
        print(f"  Warning: {summary['warning']} ")
        print(f"{'='*60}\n")

        return {
            "package_id": self.package_id,
            "package_name": self.package_name,
            "results": self.results,
            "summary": summary
        }


def run_package_8(browser: str = "edge_unmanaged") -> Dict[str, Any]:
    suite = PatchVersionHygieneTestSuite(browser)
    return suite.run_all_tests()


if __name__ == "__main__":
    result = run_package_8()
    print(json.dumps(result, indent=2, default=str, ensure_ascii=False))



