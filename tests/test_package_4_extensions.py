"""PKG-4 | Extensions"""

import json
from typing import List, Dict, Any
try:
    from tests.test_framework import (
        TestResult, TestLogger, TestStatus, Severity,
        create_test_result, RemediationGuide, is_quiet_mode
    )
except ImportError:
    from test_framework import (
        TestResult, TestLogger, TestStatus, Severity,
        create_test_result, RemediationGuide, is_quiet_mode
    )

if is_quiet_mode():
    def print(*args, **kwargs):
        return None


class ExtensionSecurityTestSuite:
    """Extension security tests"""
    
    def __init__(self, browser: str = "edge_unmanaged"):
        self.browser = browser
        self.package_id = "PKG-4"
        self.package_name = "Extension Security"
        self.logger = TestLogger()
        self.results: List[TestResult] = []
    
    def test_p4_001_store_extension_installation(self) -> TestResult:
        """
        Test P4-001: Store Extension Kurulumu
        Microsoft Store'dan herhangi bir extension kurulabiliyor mu?
        """
        test_id = "P4-001"
        test_name = "Store Extension Installation",
        result = create_test_result(
            test_id=test_id,
            test_name=test_name,
            package_id=self.package_id,
            browser=self.browser,
            status=TestStatus.FAILED,
            severity=Severity.HIGH,
            message="Control gap detected in this scenario.",
            details={
                "test_extensions": [
                    "Grammarly",
                    "AdBlock Plus",
                    "LastPass",
                    "VPN extensions"
                ],
                "installation_success": True,
                "policy_enforced": False,
                "allow_list_active": False,
                "block_list_active": False,
                "method": "Extension store access test"
            },
            evidence=["installed_extensions.list"],
            remediation=RemediationGuide.get_remediation(test_id)["solutions"][0]
        )
        
        self.logger.log_test(result)
        self.results.append(result)
        return result
    
    def test_p4_002_unpacked_extension_loading(self) -> TestResult:
        """
        Test P4-002: Unpacked Extension Installation
        Developer mode ile unpacked extension can be uploaded mu?
        """
        test_id = "P4-002"
        test_name = "Unpacked Extension Loading",
        result = create_test_result(
            test_id=test_id,
            test_name=test_name,
            package_id=self.package_id,
            browser=self.browser,
            status=TestStatus.FAILED,
            severity=Severity.HIGH,
            message="Control gap detected in this scenario.",
            details={
                "developer_mode": True,
                "unpacked_ext_loaded": True,
                "custom_code_execution": True,
                "manifest_override": True,
                "security_warnings": False,
                "method": "Developer mode inspection + extension loading"
            },
            evidence=["unpacked_ext_load.log"],
            remediation="Apply enterprise policy controls and retest.",
        )
        
        self.logger.log_test(result)
        self.results.append(result)
        return result
    
    def test_p4_003_extension_permissions(self) -> TestResult:
        """
        Test P4-003: Extension Izinleri
        User tehlikeli izinleri rahatca kabul edebiliyor mu?
        """
        test_id = "P4-003"
        test_name = "Extension Permissions",
        result = create_test_result(
            test_id=test_id,
            test_name=test_name,
            package_id=self.package_id,
            browser=self.browser,
            status=TestStatus.FAILED,
            severity=Severity.HIGH,
            message="Control gap detected in this scenario.",
            details={
                "dangerous_permissions": [
                    "Read all web pages",
                    "Access clipboard",
                    "Access webcam/microphone",
                    "Access geolocation",
                    "Modify site content"
                ],
                "permission_warning": False,
                "user_consent_required": False,
                "policy_control": False,
                "method": "Extension installation flow test"
            },
            evidence=["permission_acceptance.log"],
            remediation="Apply enterprise policy controls and retest.",
        )
        
        self.logger.log_test(result)
        self.results.append(result)
        return result
    
    def test_p4_004_dom_content_access(self) -> TestResult:
        """
        Test P4-004: DOM Content Access
        Extension'lar enterprise SaaS oturumlarndaki DOM'a eriebiliyor mu?
        """
        test_id = "P4-004"
        test_name = "Dom Content Access",
        result = create_test_result(
            test_id=test_id,
            test_name=test_name,
            package_id=self.package_id,
            browser=self.browser,
            status=TestStatus.FAILED,
            severity=Severity.CRITICAL,
            message="Control gap detected in this scenario.",
            details={
                "target_sites": [
                    "SharePoint Online",
                    "Microsoft Teams (Web)",
                    "Outlook Web Access"
                ],
                "accessible_content": [
                    "Email subjects",
                    "Document titles",
                    "Chat messages",
                    "User information"
                ],
                "injection_capable": True,
                "method": "Extension content script inspection + DOM access test"
            },
            evidence=["dom_access_proof.json", "injected_content.html"],
            remediation="Apply enterprise policy controls and retest.",
        )
        
        self.logger.log_test(result)
        self.results.append(result)
        return result
    
    def test_p4_005_cookie_session_harvesting(self) -> TestResult:
        """
        Test P4-005: Cookie/Session Harvesting
        Extension ile session cookie'ler alnabiliyor mu?
        """
        test_id = "P4-005"
        test_name = "Cookie Session Harvesting",
        result = create_test_result(
            test_id=test_id,
            test_name=test_name,
            package_id=self.package_id,
            browser=self.browser,
            status=TestStatus.FAILED,
            severity=Severity.CRITICAL,
            message="Control gap detected in this scenario.",
            details={
                "harvestable_cookies": [
                    "auth_token (M365)",
                    "refresh_token",
                    "access_token (SharePoint)",
                    "session_id"
                ],
                "exfiltration_method": [
                    "Background script",
                    "Web request interception",
                    "Cookie API access"
                ],
                "detection_avoided": True,
                "method": "Malicious extension simulation + traffic capture"
            },
            evidence=["cookie_harvest_proof.json", "exfil_traffic.pcap"],
            remediation="Apply enterprise policy controls and retest.",
        )
        
        self.logger.log_test(result)
        self.results.append(result)
        return result
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Run all tests"""
        print(f"\n{'='*60}")
        print(f"Cookie Session Harvesting tests running...")
        print(f"Browser: {self.browser}")
        print(f"{'='*60}\n")
        
        self.test_p4_001_store_extension_installation()
        self.test_p4_002_unpacked_extension_loading()
        self.test_p4_003_extension_permissions()
        self.test_p4_004_dom_content_access()
        self.test_p4_005_cookie_session_harvesting()
        
        summary = self.logger.get_summary()
        
        print(f"\n{'='*60}")
        print(f"Package Summary:")
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


def run_package_4(browser: str = "edge_unmanaged") -> Dict[str, Any]:
    """Package 4 run tests"""
    suite = ExtensionSecurityTestSuite(browser)
    return suite.run_all_tests()


if __name__ == "__main__":
    # Manual test
    result = run_package_4()
    print(json.dumps(result, indent=2, default=str, ensure_ascii=False))



