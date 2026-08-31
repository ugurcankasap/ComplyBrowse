"""PKG-1 | Policy Hardening"""

import os
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


class PolicyHardeningTestSuite:
    """Policy hardening tests"""
    
    def __init__(self, browser: str = "edge_unmanaged"):
        self.browser = browser
        self.package_id = "PKG-1"
        self.package_name = "Policy Hardening"
        self.logger = TestLogger()
        self.results: List[TestResult] = []
    
    def test_p1_001_inprivate_mode(self) -> TestResult:
        """
        Test P1-001: InPrivate Mode Accessibility
        User InPrivate mod acabiliyor mu?
        """
        test_id = "P1-001"
        test_name = "Inprivate Mode",
        # Simulasyon: Windows registry'yi kontrol et
        # HKCU\Software\Policies\Microsoft\Edge\InPrivateModeAvailability
        
        result = create_test_result(
            test_id=test_id,
            test_name=test_name,
            package_id=self.package_id,
            browser=self.browser,
            status=TestStatus.FAILED,  # Simulasyon: policy uygulanmad
            severity=Severity.HIGH,
            message="Control gap detected in this scenario.",
            details={
                "registry_check": "HKCU\\Software\\Policies\\Microsoft\\Edge\\InPrivateModeAvailability",
                "expected_value": 0,
                "actual_value": None,  # Policy yok = None
                "policy_enforced": False,
                "method": "Registry scan"
            },
            evidence=["registry_dump.txt"],
            remediation=RemediationGuide.get_remediation(test_id)["solutions"][0]
        )
        
        self.logger.log_test(result)
        self.results.append(result)
        return result
    
    def test_p1_002_extension_installation(self) -> TestResult:
        """
        Test P1-002: Extension Kurulumu
        User kendi extension'n can install mu?
        """
        test_id = "P1-002"
        test_name = "Extension Installation",
        # Simulasyon: Extension store'a access
        result = create_test_result(
            test_id=test_id,
            test_name=test_name,
            package_id=self.package_id,
            browser=self.browser,
            status=TestStatus.FAILED,
            severity=Severity.HIGH,
            message="Control gap detected in this scenario.",
            details={
                "extension_store_accessible": True,
                "extension_allow_list": None,
                "extension_block_list": None,
                "dev_mode_enabled": True,
                "unpacked_extension_loadable": True,
                "test_extension": "Grammarly, AdBlock, etc."
            },
            evidence=["extension_install_log.json"],
            remediation=RemediationGuide.get_remediation(test_id)["solutions"][0]
        )
        
        self.logger.log_test(result)
        self.results.append(result)
        return result
    
    def test_p1_003_password_manager(self) -> TestResult:
        """
        Test P1-003: Password Manager Kontrolu
        ifre kaydetme ozellii enforced mi?
        """
        test_id = "P1-003"
        test_name = "Password Manager",
        result = create_test_result(
            test_id=test_id,
            test_name=test_name,
            package_id=self.package_id,
            browser=self.browser,
            status=TestStatus.WARNING,
            severity=Severity.MEDIUM,
            message="Control gap detected in this scenario.",
            details={
                "password_save_enabled": True,
                "password_autofill_enabled": True,
                "sync_password_to_personal_account": True,
                "policy_control_available": False,
                "method": "UI inspection + preferences file check"
            },
            evidence=["preferences.json"],
            remediation="Apply enterprise policy controls and retest.",
        )
        
        self.logger.log_test(result)
        self.results.append(result)
        return result
    
    def test_p1_004_developer_tools(self) -> TestResult:
        """
        Test P1-004: Developer Tools Restriction
        DevTools kapanyor mu?
        """
        test_id = "P1-004"
        test_name = "Developer Tools",
        result = create_test_result(
            test_id=test_id,
            test_name=test_name,
            package_id=self.package_id,
            browser=self.browser,
            status=TestStatus.FAILED,
            severity=Severity.MEDIUM,
            message="Control gap detected in this scenario.",
            details={
                "devtools_openable": True,
                "devtools_policy_enabled": False,
                "f12_accessible": True,
                "console_accessible": True,
                "network_tab_accessible": True,
                "method": "UI testing"
            },
            evidence=[],
            remediation="Apply enterprise policy controls and retest.",
        )
        
        self.logger.log_test(result)
        self.results.append(result)
        return result
    
    def test_p1_005_download_policy(self) -> TestResult:
        """
        Test P1-005: Download Policy Enforcement
        Indirme kstlamalar enforced mi?
        """
        test_id = "P1-005"
        test_name = "Download Policy",
        result = create_test_result(
            test_id=test_id,
            test_name=test_name,
            package_id=self.package_id,
            browser=self.browser,
            status=TestStatus.FAILED,
            severity=Severity.HIGH,
            message="Control gap detected in this scenario.",
            details={
                "exe_download_blocked": False,
                "dangerous_file_warning": False,
                "download_folder_restricted": False,
                "file_types_blocked": [],
                "method": "Download attempt simulation"
            },
            evidence=["download_test.log"],
            remediation="Apply enterprise policy controls and retest.",
        )
        
        self.logger.log_test(result)
        self.results.append(result)
        return result
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Run all tests"""
        print(f"\n{'='*60}")
        print(f"Download Policy tests running...")
        print(f"Browser: {self.browser}")
        print(f"{'='*60}\n")
        
        self.test_p1_001_inprivate_mode()
        self.test_p1_002_extension_installation()
        self.test_p1_003_password_manager()
        self.test_p1_004_developer_tools()
        self.test_p1_005_download_policy()
        
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


def run_package_1(browser: str = "edge_unmanaged") -> Dict[str, Any]:
    """Package 1 run tests"""
    suite = PolicyHardeningTestSuite(browser)
    return suite.run_all_tests()


if __name__ == "__main__":
    # Manual test
    result = run_package_1()
    print(json.dumps(result, indent=2, default=str, ensure_ascii=False))



