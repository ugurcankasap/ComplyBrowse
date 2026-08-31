"""
Browser Security Test Suite
Browser Security Test Package
"""

import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

__version__ = "1.0.0"
__author__ = "Security Team"

from .test_framework import (
    TestStatus,
    Severity,
    TestResult,
    TestPackageResult,
    SecurityAuditReport,
    TestLogger,
    RemediationGuide,
    RiskCalculator
)

from .test_package_1_policy_bypass import run_package_1
from .test_package_2_data_exfiltration import run_package_2
from .test_package_3_identity_session import run_package_3
from .test_package_4_extensions import run_package_4
from .test_package_5_network_visibility import run_package_5
from .test_package_6_shadow_saas import run_package_6
from .test_package_7_certificate_proxy_inspection import run_package_7
from .test_package_8_patch_version_hygiene import run_package_8
from .test_package_9_forensic_audit_deficiency import run_package_9
from .test_package_10_compliance_data_sovereignty import run_package_10

__all__ = [
    'TestStatus',
    'Severity',
    'TestResult',
    'TestPackageResult',
    'SecurityAuditReport',
    'TestLogger',
    'RemediationGuide',
    'RiskCalculator',
    'run_package_1',
    'run_package_2',
    'run_package_3',
    'run_package_4',
    'run_package_5',
    'run_package_6',
    'run_package_7',
    'run_package_8',
    'run_package_9',
    'run_package_10'
]


