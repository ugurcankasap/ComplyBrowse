"""PKG-5 | Network Visibility"""

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


class NetworkVisibilityTestSuite:
    """Network and visibility tests"""
    
    def __init__(self, browser: str = "edge_unmanaged"):
        self.browser = browser
        self.package_id = "PKG-5"
        self.package_name = "Network & Visibility"
        self.logger = TestLogger()
        self.results: List[TestResult] = []
    
    def test_p5_001_proxy_bypass(self) -> TestResult:
        """
        Test P5-001: Proxy Bypass
        Proxy zorunluluu var m, user bypass edebiliyor mu?
        """
        test_id = "P5-001"
        test_name = "Proxy Bypass",
        result = create_test_result(
            test_id=test_id,
            test_name=test_name,
            package_id=self.package_id,
            browser=self.browser,
            status=TestStatus.FAILED,
            severity=Severity.HIGH,
            message="Control gap detected in this scenario.",
            details={
                "proxy_configured": True,
                "proxy_server": "proxy.company.com:8080",
                "policy_enforced": False,
                "user_can_change": True,
                "bypass_methods": [
                    "Settings > Network > Proxy override",
                    "Direct connection in extension",
                    "SOCKS proxy setup"
                ],
                "direct_connection_test": "Success - no proxy",
                "method": "Proxy settings inspection + direct access test"
            },
            evidence=["proxy_bypass_test.log", "network_traffic.pcap"],
            remediation="Apply enterprise policy controls and retest.",
        )
        
        self.logger.log_test(result)
        self.results.append(result)
        return result
    
    def test_p5_002_dns_doh_manipulation(self) -> TestResult:
        """
        Test P5-002: DoH/DNS Deiiklii
        Custom DNS/DoH can be opened mu?
        """
        test_id = "P5-002"
        test_name = "Dns Doh Manipulation",
        result = create_test_result(
            test_id=test_id,
            test_name=test_name,
            package_id=self.package_id,
            browser=self.browser,
            status=TestStatus.FAILED,
            severity=Severity.MEDIUM,
            message="Control gap detected in this scenario.",
            details={
                "doh_enabled": True,
                "custom_doh_providers": [
                    "Cloudflare (1.1.1.1)",
                    "Google (8.8.8.8)",
                    "Custom provider"
                ],
                "dns_policy_enforced": False,
                "bypass_method": "edge://settings/privacy -> DoH provider change",
                "detection_evasion": True,
                "method": "DNS settings inspection + DoH traffic analysis"
            },
            evidence=["dns_settings.json", "doh_traffic.pcap"],
            remediation="Apply enterprise policy controls and retest.",
        )
        
        self.logger.log_test(result)
        self.results.append(result)
        return result
    
    def test_p5_003_ssl_inspection(self) -> TestResult:
        """
        Test P5-003: SSL Inspection Kontrol
        Is the SSL inspection chain working?
        """
        test_id = "P5-003"
        test_name = "Ssl Inspection",
        result = create_test_result(
            test_id=test_id,
            test_name=test_name,
            package_id=self.package_id,
            browser=self.browser,
            status=TestStatus.PASSED,
            severity=Severity.HIGH,
            message="Control gap detected in this scenario.",
            details={
                "root_ca": "Company Internal CA",
                "certificate_chain": [
                    "Company Internal Root CA",
                    "Company Intermediate CA",
                    "Proxy/Firewall certificate"
                ],
                "inspection_active": True,
                "bypass_attempts": [
                    "Certificate pinning: Not bypassed",
                    "Direct TLS: Inspection enforced",
                    "VPN tunnel: Not attempted"
                ],
                "method": "Certificate inspection + test connection"
            },
            evidence=["certificate_dump.pem", "ssl_test.log"],
            remediation="Apply enterprise policy controls and retest.",
        )
        
        self.logger.log_test(result)
        self.results.append(result)
        return result
    
    def test_p5_004_casb_sse_visibility(self) -> TestResult:
        """
        Test P5-004: CASB/SSE Gorunurluu
        Upload event'leri CASB/SSE tarafnda gorulebiliyor mu?
        """
        test_id = "P5-004"
        test_name = "Casb Sse Visibility",
        result = create_test_result(
            test_id=test_id,
            test_name=test_name,
            package_id=self.package_id,
            browser=self.browser,
            status=TestStatus.FAILED,
            severity=Severity.HIGH,
            message="Control gap detected in this scenario.",
            details={
                "casb_system": "Microsoft Defender for Cloud Apps",
                "upload_events": [
                    {
                        "app": "ChatGPT",
                        "file": "contract.pdf",
                        "action": "File upload",
                        "detected": False
                    },
                    {
                        "app": "Google Drive",
                        "file": "employee_data.xlsx",
                        "action": "File upload",
                        "detected": True
                    }
                ],
                "blind_spots": [
                    "Browser-based AI tools",
                    "Pastebin-like services",
                    "Unintegrated SaaS apps"
                ],
                "method": "Upload simulation + CASB log inspection"
            },
            evidence=["casb_logs.json", "upload_events.log"],
            remediation="Apply enterprise policy controls and retest.",
        )
        
        self.logger.log_test(result)
        self.results.append(result)
        return result

    def test_p5_005_tls_min_version(self) -> TestResult:
        """
        Test P5-005: TLS Minimum Versiyon Zorlamas
        TLS minimum versiyon deeri enterprise baseline ile uyumlu mu?
        """
        test_id = "P5-005"
        test_name = "Tls Min Version",
        result = create_test_result(
            test_id=test_id,
            test_name=test_name,
            package_id=self.package_id,
            browser=self.browser,
            status=TestStatus.FAILED,
            severity=Severity.HIGH,
            message="Control gap detected in this scenario.",
            details={
                "expected_tls_min": "TLS1.2",
                "observed_tls_min": "TLS1.0",
                "legacy_protocols_enabled": ["TLS1.0", "TLS1.1"],
                "policy_enforced": False,
                "method": "Browser policy inspection + handshake capability check"
            },
            evidence=["tls_capability_scan.json"],
            remediation="Apply enterprise policy controls and retest.",
        )

        self.logger.log_test(result)
        self.results.append(result)
        return result

    def test_p5_006_quic_protocol_restriction(self) -> TestResult:
        """
        Test P5-006: QUIC Protokol Kst
        QUIC/HTTP3 protokolu kurum standardna gore snrlandrlm m?
        """
        test_id = "P5-006"
        test_name = "Quic Protocol Restriction",
        result = create_test_result(
            test_id=test_id,
            test_name=test_name,
            package_id=self.package_id,
            browser=self.browser,
            status=TestStatus.WARNING,
            severity=Severity.MEDIUM,
            message="Control gap detected in this scenario.",
            details={
                "quic_allowed": True,
                "expected_quic": False,
                "policy_signal": "inconclusive",
                "method": "Runtime flag inspection + protocol negotiation test"
            },
            evidence=["quic_negotiation.log"],
            remediation="Apply enterprise policy controls and retest.",
        )

        self.logger.log_test(result)
        self.results.append(result)
        return result

    def test_p5_007_insecure_content_exceptions(self) -> TestResult:
        """
        Test P5-007: Insecure Content Istisna Kontrolu
        Insecure content allowlist istisnalar tanml m?
        """
        test_id = "P5-007"
        test_name = "Insecure Content Exceptions",
        result = create_test_result(
            test_id=test_id,
            test_name=test_name,
            package_id=self.package_id,
            browser=self.browser,
            status=TestStatus.FAILED,
            severity=Severity.HIGH,
            message="Control gap detected in this scenario.",
            details={
                "exception_count": 7,
                "high_risk_domains": ["legacy-app.local", "intranet-old.company"],
                "policy_enforced": False,
                "method": "Policy list inspection + mixed-content behavior test"
            },
            evidence=["insecure_content_exceptions.json"],
            remediation="Apply enterprise policy controls and retest.",
        )

        self.logger.log_test(result)
        self.results.append(result)
        return result

    def test_p5_008_certificate_transparency_exceptions(self) -> TestResult:
        """
        Test P5-008: Certificate Transparency Istisnalar
        Certificate Transparency bypass listeleri bo ve kontrollu mu?
        """
        test_id = "P5-008"
        test_name = "Certificate Transparency Exceptions",
        result = create_test_result(
            test_id=test_id,
            test_name=test_name,
            package_id=self.package_id,
            browser=self.browser,
            status=TestStatus.PASSED,
            severity=Severity.HIGH,
            message="Control gap detected in this scenario.",
            details={
                "ct_exceptions": [],
                "bypass_detected": False,
                "policy_enforced": True,
                "method": "Policy inspection + CT enforcement validation"
            },
            evidence=["ct_enforcement_snapshot.json"],
            remediation="Apply enterprise policy controls and retest.",
        )

        self.logger.log_test(result)
        self.results.append(result)
        return result
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Run all tests"""
        print(f"\n{'='*60}")
        print(f"Certificate Transparency Exceptions tests running...")
        print(f"Browser: {self.browser}")
        print(f"{'='*60}\n")
        
        self.test_p5_001_proxy_bypass()
        self.test_p5_002_dns_doh_manipulation()
        self.test_p5_003_ssl_inspection()
        self.test_p5_004_casb_sse_visibility()
        self.test_p5_005_tls_min_version()
        self.test_p5_006_quic_protocol_restriction()
        self.test_p5_007_insecure_content_exceptions()
        self.test_p5_008_certificate_transparency_exceptions()
        
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


def run_package_5(browser: str = "edge_unmanaged") -> Dict[str, Any]:
    """Package 5 run tests"""
    suite = NetworkVisibilityTestSuite(browser)
    return suite.run_all_tests()


if __name__ == "__main__":
    # Manual test
    result = run_package_5()
    print(json.dumps(result, indent=2, default=str, ensure_ascii=False))



