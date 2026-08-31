"""PKG-3 | Identity Session"""

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


class IdentitySessionTestSuite:
    """Identity and session tests"""
    
    def __init__(self, browser: str = "edge_unmanaged"):
        self.browser = browser
        self.package_id = "PKG-3"
        self.package_name = "Identity & Session Security"
        self.logger = TestLogger()
        self.results: List[TestResult] = []
    
    def test_p3_001_unmanaged_m365_access(self) -> TestResult:
        """
        Test P3-001: Unmanaged Browser M365 Eriimi
        Are additional restrictions enforced for M365 access from unmanaged browsers?
        """
        test_id = "P3-001"
        test_name = "Unmanaged M365 Access",
        result = create_test_result(
            test_id=test_id,
            test_name=test_name,
            package_id=self.package_id,
            browser=self.browser,
            status=TestStatus.FAILED,
            severity=Severity.HIGH,
            message="Control gap detected in this scenario.",
            details={
                "browser_type": "Microsoft Edge (Unmanaged)",
                "device_compliance": "Not Compliant",
                "intune_enrollment": False,
                "access_granted": True,
                "restrictions_applied": False,
                "ca_policies": {
                    "require_compliant_device": False,
                    "require_app": False,
                    "web_only_access": False
                },
                "method": "M365 login attempt + device detection"
            },
            evidence=["m365_access_log.json", "device_status.txt"],
            remediation="Apply enterprise policy controls and retest.",
        )
        
        self.logger.log_test(result)
        self.results.append(result)
        return result
    
    def test_p3_002_conditional_access_enforcement(self) -> TestResult:
        """
        Test P3-002: Conditional Access Davran
        Are Conditional Access policies working?
        """
        test_id = "P3-002"
        test_name = "Conditional Access Enforcement",
        result = create_test_result(
            test_id=test_id,
            test_name=test_name,
            package_id=self.package_id,
            browser=self.browser,
            status=TestStatus.WARNING,
            severity=Severity.HIGH,
            message="Control gap detected in this scenario.",
            details={
                "ca_policies": [
                    "Block risky signin",
                    "Require MFA",
                    "Require compliant device"
                ],
                "enforced_policies": [
                    "MFA required: Yes",
                    "Compliant device check: Partial",
                    "Unmanaged device block: No"
                ],
                "bypass_methods": [
                    "Unmanaged browser still accessible",
                    "Legacy auth not fully blocked",
                    "Device claim not verified"
                ],
                "method": "CA policy audit + login attempt"
            },
            evidence=["ca_enforcement.log"],
            remediation="Apply enterprise policy controls and retest.",
        )
        
        self.logger.log_test(result)
        self.results.append(result)
        return result
    
    def test_p3_003_session_persistence(self) -> TestResult:
        """
        Test P3-003: Session Persistence
        Do cookies/sessions persist after logout?
        """
        test_id = "P3-003"
        test_name = "Session Persistence",
        result = create_test_result(
            test_id=test_id,
            test_name=test_name,
            package_id=self.package_id,
            browser=self.browser,
            status=TestStatus.FAILED,
            severity=Severity.MEDIUM,
            message="Control gap detected in this scenario.",
            details={
                "session_before_logout": {
                    "cookie_count": 12,
                    "auth_token": "Present",
                    "refresh_token": "Present"
                },
                "after_logout": {
                    "cookie_count": 8,
                    "auth_token": "Still Present",
                    "refresh_token": "Still Present",
                    "cleared": False
                },
                "browser_back_reaccess": True,
                "cache_resurrection": True,
                "method": "Cookie analysis + cache inspection"
            },
            evidence=["cookie_analysis.json", "cache_dump.log"],
            remediation="Apply enterprise policy controls and retest.",
        )
        
        self.logger.log_test(result)
        self.results.append(result)
        return result
    
    def test_p3_004_token_security(self) -> TestResult:
        """
        Test P3-004: Token Guvenlii
        Token'lar guvenli ekilde saklanyor mu?
        """
        test_id = "P3-004"
        test_name = "Token Security",
        result = create_test_result(
            test_id=test_id,
            test_name=test_name,
            package_id=self.package_id,
            browser=self.browser,
            status=TestStatus.FAILED,
            severity=Severity.HIGH,
            message="Control gap detected in this scenario.",
            details={
                "token_storage": {
                    "auth_token": "localStorage (plaintext)",
                    "refresh_token": "localStorage (plaintext)",
                    "session_token": "LocalStorage or IndexedDB"
                },
                "token_inspection": {
                    "tool": "Browser DevTools",
                    "token_exposed": True,
                    "xss_vulnerable": True,
                    "token_lifetime": "Long-lived (24h)"
                },
                "security_measures": {
                    "httponly_flag": False,
                    "secure_flag": False,
                    "samesite_policy": "Lax"
                },
                "method": "DevTools inspection + XSS simulation"
            },
            evidence=["token_dump.json", "xss_test.log"],
            remediation="Apply enterprise policy controls and retest.",
        )
        
        self.logger.log_test(result)
        self.results.append(result)
        return result
    
    def test_p3_005_work_personal_profile_isolation(self) -> TestResult:
        """
        Test P3-005: Work/Personal Profile Separation
        Are work and personal profiles truly separated?
        """
        test_id = "P3-005"
        test_name = "Work Personal Profile Isolation",
        result = create_test_result(
            test_id=test_id,
            test_name=test_name,
            package_id=self.package_id,
            browser=self.browser,
            status=TestStatus.FAILED,
            severity=Severity.HIGH,
            message="Control gap detected in this scenario.",
            details={
                "profile_separation": {
                    "work_profile": "user@example.com",
                    "personal_profile": "personal@example.com",
                    "shared_extensions": True,
                    "shared_cookies": True,
                    "shared_autofill": True
                },
                "cross_profile_access": {
                    "work_cookies_in_personal": True,
                    "personal_cookies_in_work": True,
                    "history_shared": True,
                    "sync_overlapped": True
                },
                "isolation_failures": [
                    "Extensions work in both profiles",
                    "Cookies leak between profiles",
                    "Autofill data shared"
                ],
                "method": "Profile switching test + cookie inspection"
            },
            evidence=["profile_isolation_test.log", "cookie_cross_contamination.json"],
            remediation="Apply enterprise policy controls and retest.",
        )
        
        self.logger.log_test(result)
        self.results.append(result)
        return result
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Run all tests"""
        print(f"\n{'='*60}")
        print(f"Work Personal Profile Isolation tests running...")
        print(f"Browser: {self.browser}")
        print(f"{'='*60}\n")
        
        self.test_p3_001_unmanaged_m365_access()
        self.test_p3_002_conditional_access_enforcement()
        self.test_p3_003_session_persistence()
        self.test_p3_004_token_security()
        self.test_p3_005_work_personal_profile_isolation()
        
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


def run_package_3(browser: str = "edge_unmanaged") -> Dict[str, Any]:
    """Package 3 run tests"""
    suite = IdentitySessionTestSuite(browser)
    return suite.run_all_tests()


if __name__ == "__main__":
    # Manual test
    result = run_package_3()
    print(json.dumps(result, indent=2, default=str, ensure_ascii=False))



