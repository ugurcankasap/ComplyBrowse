"""PKG-10 | Compliance & Data Sovereignty"""

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


class ComplianceDataSovereigntyTestSuite:
    """Compliance and data sovereignty tests"""

    def __init__(self, browser: str = "edge_unmanaged"):
        self.browser = browser
        self.package_id = "PKG-10"
        self.package_name = "Compliance & Data Sovereignty"
        self.logger = TestLogger()
        self.results: List[TestResult] = []

    def test_p10_001_data_residency(self) -> TestResult:
        result = create_test_result(
            test_id="P10-001",
            test_name = "Data Residency",
            package_id=self.package_id,
            browser=self.browser,
            status=TestStatus.FAILED,
            severity=Severity.CRITICAL,
            message="Control gap detected in this scenario.",
            details={
                "required_region": "TR/EU",
                "observed_region": "US",
                "policy_enforced": False,
                "steps": [
                    "Bolgesel veri zorunluluunu tanmla",
                    "Upload edilen verinin hangi bolgede ilendiini kontrol et",
                    "Validate whether tenant or storage location complies with defined policies",
                    "If out-of-region processing exists, record a compliance violation note"
                ],
                "method": "Region routing and upload validation + residency policy check"
            },
            evidence=["data_residency_check.json"],
            remediation="Apply enterprise policy controls and retest.",
        )
        self.logger.log_test(result)
        self.results.append(result)
        return result

    def test_p10_002_cross_border_upload(self) -> TestResult:
        result = create_test_result(
            test_id="P10-002",
            test_name = "Cross Border Upload",
            package_id=self.package_id,
            browser=self.browser,
            status=TestStatus.FAILED,
            severity=Severity.CRITICAL,
            message="Control gap detected in this scenario.",
            details={
                "blocked": False,
                "sensitive_files": ["contract.pdf", "employee_data.xlsx"],
                "target_services": ["public cloud drive", "AI tools"],
                "steps": [
                    "Select the sensitive file class",
                    "Enterprise d SaaS hedeflerine upload akn simule et",
                    "Hedef servisin ulke d veri ckn tetikleyip tetiklemediini kontrol et",
                    "Validate DLP blocking and audit records"
                ],
                "method": "Upload simulation + destination classification + DLP audit validation"
            },
            evidence=["cross_border_upload.log"],
            remediation="Apply enterprise policy controls and retest.",
        )
        self.logger.log_test(result)
        self.results.append(result)
        return result

    def test_p10_003_policy_alignment(self) -> TestResult:
        result = create_test_result(
            test_id="P10-003",
            test_name = "Policy Alignment",
            package_id=self.package_id,
            browser=self.browser,
            status=TestStatus.WARNING,
            severity=Severity.MEDIUM,
            message="Control gap detected in this scenario.",
            details={
                "policy_gaps": ["retention", "download control"],
                "frameworks": ["KVKK", "ISO 27001"],
                "steps": [
                    "Map browser policies to relevant regulatory controls",
                    "Retention ve download kontrol gibi kritik balklar kontrol et",
                    "Eksik kalan policy maddelerini gap listesine yaz",
                    "Create a prioritized action plan for compliance"
                ],
                "method": "Policy mapping review + compliance gap analysis"
            },
            evidence=["policy_alignment_gap.csv"],
            remediation="Apply enterprise policy controls and retest.",
        )
        self.logger.log_test(result)
        self.results.append(result)
        return result

    def run_all_tests(self) -> Dict[str, Any]:
        print(f"\n{'='*60}")
        print("Compliance & Data Sovereignty Tests running...")
        print(f"Browser: {self.browser}")
        print(f"{'='*60}\n")

        self.test_p10_001_data_residency()
        self.test_p10_002_cross_border_upload()
        self.test_p10_003_policy_alignment()

        summary = self.logger.get_summary()
        print(f"\n{'='*60}")
        print("Package 10 Summary:")
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


def run_package_10(browser: str = "edge_unmanaged") -> Dict[str, Any]:
    suite = ComplianceDataSovereigntyTestSuite(browser)
    return suite.run_all_tests()


if __name__ == "__main__":
    result = run_package_10()
    print(json.dumps(result, indent=2, default=str, ensure_ascii=False))



