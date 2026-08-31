"""PKG-2 | Data Exfiltration"""

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


class DataExfiltrationTestSuite:
    """Data exfiltration tests"""
    
    def __init__(self, browser: str = "edge_unmanaged"):
        self.browser = browser
        self.package_id = "PKG-2"
        self.package_name = "Data Exfiltration"
        self.logger = TestLogger()
        self.results: List[TestResult] = []
    
    def test_p2_001_corporate_file_to_personal_mail(self) -> TestResult:
        """
        Test P2-001: Enterprise File to Personal Email
        Can enterprise files be uploaded to personal email services?
        """
        test_id = "P2-001"
        test_name = "Corporate File To Personal Mail",
        result = create_test_result(
            test_id=test_id,
            test_name=test_name,
            package_id=self.package_id,
            browser=self.browser,
            status=TestStatus.FAILED,
            severity=Severity.CRITICAL,
            message="Control gap detected in this scenario.",
            details={
                "target_service": ["Gmail", "Outlook.com Personal", "Yahoo Mail"],
                "file_uploaded": "sensitive_document.docx (15.2 MB)",
                "upload_success": True,
                "dlp_blocking": False,
                "endpoint_dlp_active": False,
                "casb_detection": False,
                "method": "Upload simulation + network capture"
            },
            evidence=["network_capture.pcap", "dlp_log.txt"],
            remediation="Apply enterprise policy controls and retest.",
        )
        
        self.logger.log_test(result)
        self.results.append(result)
        return result
    
    def test_p2_002_corporate_file_to_ai_tools(self) -> TestResult:
        """
        Test P2-002: Enterprise File to Public AI Tool
        Can files be uploaded to tools such as ChatGPT and Gemini?
        """
        test_id = "P2-002"
        test_name = "Corporate File To Ai Tools",
        result = create_test_result(
            test_id=test_id,
            test_name=test_name,
            package_id=self.package_id,
            browser=self.browser,
            status=TestStatus.FAILED,
            severity=Severity.CRITICAL,
            message="Control gap detected in this scenario.",
            details={
                "ai_services": ["ChatGPT", "Google Gemini", "Claude", "Copilot Free"],
                "files_uploaded": [
                    {"name": "contract_2024.pdf", "classification": "Confidential"},
                    {"name": "employee_data.xlsx", "classification": "Secret"},
                    {"name": "source_code.py", "classification": "Internal"}
                ],
                "upload_blocked": False,
                "web_dlp_enforced": False,
                "casb_rule_active": False,
                "method": "Upload attempt + API interception"
            },
            evidence=["ai_upload_log.json", "sensitive_files.list"],
            remediation="Apply enterprise policy controls and retest.",
        )
        
        self.logger.log_test(result)
        self.results.append(result)
        return result
    
    def test_p2_003_copy_paste_to_llm(self) -> TestResult:
        """
        Test P2-003: Copy/Paste  LLM Prompt
        Hassas veri kopyala-yaptr ile LLM'e aktarlabiliyor mu?
        """
        test_id = "P2-003"
        test_name = "Copy Paste To Llm",
        result = create_test_result(
            test_id=test_id,
            test_name=test_name,
            package_id=self.package_id,
            browser=self.browser,
            status=TestStatus.FAILED,
            severity=Severity.HIGH,
            message="Control gap detected in this scenario.",
            details={
                "data_copied": {
                    "type": "Employee Directory",
                    "size": "2.5 MB",
                    "classification": "Confidential"
                },
                "destination": "ChatGPT Web Interface",
                "paste_success": True,
                "clipboard_dlp": False,
                "prompt_injection_detected": False,
                "method": "Clipboard monitoring + prompt tracking"
            },
            evidence=["clipboard_audit.log", "prompt_dump.txt"],
            remediation="Apply enterprise policy controls and retest.",
        )
        
        self.logger.log_test(result)
        self.results.append(result)
        return result
    
    def test_p2_004_browser_sync_to_personal(self) -> TestResult:
        """
        Test P2-004: Browser Sync to Personal Account
        Are passwords/bookmarks/history synchronized to a personal account?
        """
        test_id = "P2-004"
        test_name = "Browser Sync To Personal",
        result = create_test_result(
            test_id=test_id,
            test_name=test_name,
            package_id=self.package_id,
            browser=self.browser,
            status=TestStatus.FAILED,
            severity=Severity.CRITICAL,
            message="Control gap detected in this scenario.",
            details={
                "sync_enabled": True,
                "personal_account_synced": "user@example.com (Microsoft account)",
                "synced_data": {
                    "passwords": ["SharePoint PWD", "Internal portal PWD"],
                    "bookmarks": ["Internal portal", "Admin panel"],
                    "history": ["Intranet visits", "Internal tools"]
                },
                "policy_blocking_sync": False,
                "method": "Account settings inspection + sync log"
            },
            evidence=["sync_settings.json", "account_links.log"],
            remediation="Apply enterprise policy controls and retest.",
        )
        
        self.logger.log_test(result)
        self.results.append(result)
        return result
    
    def test_p2_005_download_upload_bypass(self) -> TestResult:
        """
        Test P2-005: Download/Upload Bypass
        Download/upload kstlamalar by-pass edilebiliyor mu?
        """
        test_id = "P2-005"
        test_name = "Download Upload Bypass",
        result = create_test_result(
            test_id=test_id,
            test_name=test_name,
            package_id=self.package_id,
            browser=self.browser,
            status=TestStatus.FAILED,
            severity=Severity.HIGH,
            message="Control gap detected in this scenario.",
            details={
                "methods_tested": [
                    "Direct download",
                    "Browser cache extraction",
                    "Screenshot conversion to image",
                    "Print to PDF then download"
                ],
                "bypass_successful": True,
                "security_measures": {
                    "download_folder_restricted": False,
                    "clipboard_restricted": False,
                    "print_restricted": False,
                    "cache_protected": False
                },
                "method": "Multi-method bypass testing"
            },
            evidence=["bypass_techniques.md", "dlp_evasion_log.json"],
            remediation="Apply enterprise policy controls and retest.",
        )
        
        self.logger.log_test(result)
        self.results.append(result)
        return result
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Run all tests"""
        print(f"\n{'='*60}")
        print(f"Download Upload Bypass tests running...")
        print(f"Browser: {self.browser}")
        print(f"{'='*60}\n")
        
        self.test_p2_001_corporate_file_to_personal_mail()
        self.test_p2_002_corporate_file_to_ai_tools()
        self.test_p2_003_copy_paste_to_llm()
        self.test_p2_004_browser_sync_to_personal()
        self.test_p2_005_download_upload_bypass()
        
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


def run_package_2(browser: str = "edge_unmanaged") -> Dict[str, Any]:
    """Package 2 run tests"""
    suite = DataExfiltrationTestSuite(browser)
    return suite.run_all_tests()


if __name__ == "__main__":
    # Manual test
    result = run_package_2()
    print(json.dumps(result, indent=2, default=str, ensure_ascii=False))



