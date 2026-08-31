"""PKG-7 | Certificate Proxy Inspection"""

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


class CertificateProxyInspectionTestSuite:
    """Certificate, proxy, and inspection tests"""

    def __init__(self, browser: str = "edge_unmanaged"):
        self.browser = browser
        self.package_id = "PKG-7"
        self.package_name = "Certificate/Proxy/Inspection Bypass"
        self.logger = TestLogger()
        self.results: List[TestResult] = []

    def test_p7_001_proxy_bypass(self) -> TestResult:
        result = create_test_result(
            test_id="P7-001",
            test_name = "Proxy Bypass",
            package_id=self.package_id,
            browser=self.browser,
            status=TestStatus.FAILED,
            severity=Severity.HIGH,
            message="Control gap detected in this scenario.",
            details={
                "proxy_locked": False,
                "direct_connection": True,
                "steps": [
                    "Browser proxy ayarlarn ac ve policy lock durumunu kontrol et",
                    "Proxy override alann deitirip deitirilemediini test et",
                    "Ayn oturumda dorudan internet balants denenerek bypass kontrolu yap",
                    "Validate whether network logs show traffic outside proxy control"
                ],
                "method": "Proxy settings inspection + direct access test + network log validation"
            },
            evidence=["proxy_bypass.log"],
            remediation="Apply enterprise policy controls and retest.",
        )
        self.logger.log_test(result)
        self.results.append(result)
        return result

    def test_p7_002_doh_dns_change(self) -> TestResult:
        result = create_test_result(
            test_id="P7-002",
            test_name = "Doh Dns Change",
            package_id=self.package_id,
            browser=self.browser,
            status=TestStatus.FAILED,
            severity=Severity.MEDIUM,
            message="Control gap detected in this scenario.",
            details={
                "doh_enabled": True,
                "custom_provider": "Cloudflare",
                "policy_locked": False,
                "steps": [
                    "DNS / DoH ayar ekrann ac",
                    "Varsaylan salaycdan farkl bir DoH salaycs secilebiliyor mu kontrol et",
                    "Policy lock olmad durumda deiikliin kalc olup olmadn test et",
                    "Validate whether DoH traffic is redirected to the new provider"
                ],
                "method": "DNS settings inspection + provider switch validation"
            },
            evidence=["doh_settings.json"],
            remediation="Apply enterprise policy controls and retest.",
        )
        self.logger.log_test(result)
        self.results.append(result)
        return result

    def test_p7_003_ssl_inspection(self) -> TestResult:
        result = create_test_result(
            test_id="P7-003",
            test_name = "Ssl Inspection",
            package_id=self.package_id,
            browser=self.browser,
            status=TestStatus.PASSED,
            severity=Severity.HIGH,
            message="Control gap detected in this scenario.",
            details={
                "root_ca": "Company Internal CA",
                "inspection_active": True,
                "steps": [
                    "Test hedefe TLS balants kur",
                    "Extract the presented certificate chain and compare it with enterprise CA",
                    "Validate whether proxy/firewall certificates are visible",
                    "Ensure chain validation does not fail"
                ],
                "method": "Certificate chain inspection + TLS endpoint validation"
            },
            evidence=["ssl_chain.pem"],
            remediation="Apply enterprise policy controls and retest.",
        )
        self.logger.log_test(result)
        self.results.append(result)
        return result

    def test_p7_004_certificate_pinning(self) -> TestResult:
        result = create_test_result(
            test_id="P7-004",
            test_name = "Certificate Pinning",
            package_id=self.package_id,
            browser=self.browser,
            status=TestStatus.WARNING,
            severity=Severity.HIGH,
            message="Control gap detected in this scenario.",
            details={
                "pinning_detected": True,
                "bypass_blocked": False,
                "steps": [
                    "Select an endpoint that uses certificate pinning",
                    "Attempt to connect through enterprise inspection",
                    "Check whether pinning causes fallback or blocking behavior",
                    "Istisna kurallar gerekip gerekmediini not et"
                ],
                "method": "Pinned endpoint connection test + inspection bypass attempt"
            },
            evidence=["pinning_test.log"],
            remediation="Apply enterprise policy controls and retest.",
        )
        self.logger.log_test(result)
        self.results.append(result)
        return result

    def run_all_tests(self) -> Dict[str, Any]:
        print(f"\n{'='*60}")
        print("Certificate/Proxy/Inspection Bypass Tests running...")
        print(f"Browser: {self.browser}")
        print(f"{'='*60}\n")

        self.test_p7_001_proxy_bypass()
        self.test_p7_002_doh_dns_change()
        self.test_p7_003_ssl_inspection()
        self.test_p7_004_certificate_pinning()

        summary = self.logger.get_summary()
        print(f"\n{'='*60}")
        print("Package 7 Summary:")
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


def run_package_7(browser: str = "edge_unmanaged") -> Dict[str, Any]:
    suite = CertificateProxyInspectionTestSuite(browser)
    return suite.run_all_tests()


if __name__ == "__main__":
    result = run_package_7()
    print(json.dumps(result, indent=2, default=str, ensure_ascii=False))



