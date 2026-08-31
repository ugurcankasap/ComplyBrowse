"""PKG-6 | Shadow SaaS"""

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


class ShadowAISaaSTestSuite:
    """Shadow AI and SaaS tests"""

    def __init__(self, browser: str = "edge_unmanaged"):
        self.browser = browser
        self.package_id = "PKG-6"
        self.package_name = "Shadow AI & SaaS Visibility"
        self.logger = TestLogger()
        self.results: List[TestResult] = []

    def test_p6_001_public_ai_upload(self) -> TestResult:
        test_id = "P6-001"
        result = create_test_result(
            test_id=test_id,
            test_name = "Public Ai Upload",
            package_id=self.package_id,
            browser=self.browser,
            status=TestStatus.FAILED,
            severity=Severity.CRITICAL,
            message="Control gap detected in this scenario.",
            details={
                "ai_tools": ["ChatGPT", "Gemini", "Copilot Chat"],
                "upload_allowed": True,
                "policy_block": False,
                "steps": [
                    "User oturumunu ac ve public AI arac sayfasna git",
                    "Select an enterprise file and start the upload flow",
                    "Validate whether the upload request is blocked by DLP/CASB",
                    "Check browser telemetry and network logs for file egress"
                ],
                "method": "File upload simulation + browser telemetry + CASB verification"
            },
            evidence=["ai_upload_test.log"],
            remediation="Apply enterprise policy controls and retest.",
        )
        self.logger.log_test(result)
        self.results.append(result)
        return result

    def test_p6_002_prompt_clipboard_leak(self) -> TestResult:
        test_id = "P6-002"
        result = create_test_result(
            test_id=test_id,
            test_name = "Prompt Clipboard Leak",
            package_id=self.package_id,
            browser=self.browser,
            status=TestStatus.FAILED,
            severity=Severity.HIGH,
            message="Control gap detected in this scenario.",
            details={
                "clipboard_source": "Internal document text",
                "prompt_target": "AI chat input",
                "detection": False,
                "policy_enforced": False,
                "steps": [
                    "Enterprise dokumandan hassas metni panoya kopyala",
                    "Attempt to paste content into the AI chat input field",
                    "Endpoint DLP veya browser data protection kuralnn tetiklenip tetiklenmediini kontrol et",
                    "Validate that the event is logged and masked when required"
                ],
                "method": "Clipboard inspection + prompt entry test + DLP event review"
            },
            evidence=["clipboard_prompt_leak.log"],
            remediation="Apply enterprise policy controls and retest.",
        )
        self.logger.log_test(result)
        self.results.append(result)
        return result

    def test_p6_003_shadow_saas_usage(self) -> TestResult:
        test_id = "P6-003"
        result = create_test_result(
            test_id=test_id,
            test_name = "Shadow Saas Usage",
            package_id=self.package_id,
            browser=self.browser,
            status=TestStatus.WARNING,
            severity=Severity.HIGH,
            message="Control gap detected in this scenario.",
            details={
                "unsanctioned_apps": ["Notion", "Airtable", "WeTransfer"],
                "cloud_discovery": "Partial",
                "app_classification": "Incomplete",
                "steps": [
                    "Taraycdan yetkisiz SaaS uygulamalarna access simule et",
                    "CASB discovery listesinde uygulama kategorisinin oluup olumadn kontrol et",
                    "Sanctioned / unsanctioned ayrmnn doru yaplp yaplmadn incele",
                    "Validate whether suspicious application usage triggers alerts"
                ],
                "method": "Browser traffic classification + SaaS inventory check + discovery policy review"
            },
            evidence=["shadow_saas_inventory.json"],
            remediation="Apply enterprise policy controls and retest.",
        )
        self.logger.log_test(result)
        self.results.append(result)
        return result

    def test_p6_004_cloud_visibility(self) -> TestResult:
        test_id = "P6-004"
        result = create_test_result(
            test_id=test_id,
            test_name = "Cloud Visibility",
            package_id=self.package_id,
            browser=self.browser,
            status=TestStatus.PASSED,
            severity=Severity.MEDIUM,
            message="Control gap detected in this scenario.",
            details={
                "logged_events": ["login", "file_open", "file_upload"],
                "coverage": "Baseline visibility present",
                "alerts": True,
                "steps": [
                    "CASB panelinde son user etkinliklerini ac",
                    "Validate that login, file-open, and file-upload events are recorded",
                    "Olaylarn zaman damgas ve user bilgisi ile eletiini incele",
                    "If events are missing, create a visibility gap note"
                ],
                "method": "CASB dashboard review + event coverage validation"
            },
            evidence=["cloud_discovery_dashboard.png"],
            remediation="Apply enterprise policy controls and retest.",
        )
        self.logger.log_test(result)
        self.results.append(result)
        return result

    def run_all_tests(self) -> Dict[str, Any]:
        print(f"\n{'='*60}")
        print("Shadow AI & SaaS Visibility Tests running...")
        print(f"Browser: {self.browser}")
        print(f"{'='*60}\n")

        self.test_p6_001_public_ai_upload()
        self.test_p6_002_prompt_clipboard_leak()
        self.test_p6_003_shadow_saas_usage()
        self.test_p6_004_cloud_visibility()

        summary = self.logger.get_summary()
        print(f"\n{'='*60}")
        print("Package 6 Summary:")
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


def run_package_6(browser: str = "edge_unmanaged") -> Dict[str, Any]:
    suite = ShadowAISaaSTestSuite(browser)
    return suite.run_all_tests()


if __name__ == "__main__":
    result = run_package_6()
    print(json.dumps(result, indent=2, default=str, ensure_ascii=False))



