"""
Browser Security Test Framework
Browser Security Test Framework

Central test utilities and helper functions
"""

import json
import os
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
import hashlib


def is_quiet_mode() -> bool:
    """Return True when CI/quiet mode should suppress verbose console output."""
    quiet_values = {"1", "true", "yes", "on"}
    quiet_flag = os.getenv("BROWSER_SECURITY_QUIET", "").strip().lower()
    ci_flag = os.getenv("CI", "").strip().lower()
    return quiet_flag in quiet_values or ci_flag in quiet_values


class TestStatus(Enum):
    """Test statuses"""
    NOT_RUN = "not_run"
    PASSED = "passed"
    FAILED = "failed"
    WARNING = "warning"
    INCONCLUSIVE = "inconclusive"


class Severity(Enum):
    """Risk seviyesi"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class EvidenceItem:
    """Yaplandrlm kant oesi"""
    path: str
    kind: str = "artifact"
    source: str = "test"
    note: str = ""
    hash_sha256: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "kind": self.kind,
            "source": self.source,
            "note": self.note,
            "hash_sha256": self.hash_sha256
        }


@dataclass
class TimelineEvent:
    """Test srasnda oluan adm/zaman olay"""
    stage: str
    outcome: str = "info"
    detail: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stage": self.stage,
            "outcome": self.outcome,
            "detail": self.detail,
            "timestamp": self.timestamp
        }


@dataclass
class SecondaryCheck:
    """Ana testi destekleyen ikincil dorulama sonucu"""
    name: str
    status: str
    detail: str = ""
    data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "detail": self.detail,
            "data": self.data
        }


@dataclass
class ComparisonSnapshot:
    """Mevcut test sonucunun baseline ile karlatrma ozeti"""
    baseline_label: str
    current_label: str
    metrics: Dict[str, Any] = field(default_factory=dict)
    delta: Dict[str, Any] = field(default_factory=dict)
    verdict: str = "not_evaluated"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "baseline_label": self.baseline_label,
            "current_label": self.current_label,
            "metrics": self.metrics,
            "delta": self.delta,
            "verdict": self.verdict
        }


@dataclass
class TestResult:
    """Single test result"""
    test_id: str
    test_name: str
    package_id: str
    browser: str
    status: TestStatus
    severity: Severity
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    evidence: List[str] = field(default_factory=list)  # screenshot, log file paths
    evidence_items: List[EvidenceItem] = field(default_factory=list)
    timeline: List[TimelineEvent] = field(default_factory=list)
    secondary_checks: List[SecondaryCheck] = field(default_factory=list)
    comparison: Optional[ComparisonSnapshot] = None
    remediation: str = ""

    def __post_init__(self):
        """Backward compatibility: legacy evidence list -> structured evidence_items."""
        if self.evidence and not self.evidence_items:
            self.evidence_items = [
                EvidenceItem(path=item, kind=self._infer_evidence_kind(item))
                for item in self.evidence
            ]
        if not self.timeline:
            self._bootstrap_timeline_from_details()
        if not self.secondary_checks:
            self._bootstrap_secondary_checks_from_details()

    @staticmethod
    def _infer_evidence_kind(path: str) -> str:
        lowered = path.lower()
        if lowered.endswith((".png", ".jpg", ".jpeg", ".gif", ".webp")):
            return "screenshot"
        if lowered.endswith((".pcap", ".cap")):
            return "network_capture"
        if lowered.endswith((".json", ".log", ".txt", ".csv")):
            return "log"
        return "artifact"

    def _bootstrap_timeline_from_details(self):
        steps = self.details.get("steps")
        if isinstance(steps, list):
            for index, step in enumerate(steps, start=1):
                if isinstance(step, str) and step.strip():
                    self.timeline.append(
                        TimelineEvent(
                            stage=f"step_{index}",
                            outcome="observed",
                            detail=step.strip()
                        )
                    )

    def _bootstrap_secondary_checks_from_details(self):
        method = self.details.get("method")
        if isinstance(method, str) and method.strip():
            self.secondary_checks.append(
                SecondaryCheck(
                    name="method_documented",
                    status="passed",
                    detail=method.strip(),
                    data={"source": "details.method"}
                )
            )

    def add_evidence(self, path: str, kind: Optional[str] = None,
                     source: str = "test", note: str = "",
                     hash_sha256: Optional[str] = None):
        resolved_kind = kind or self._infer_evidence_kind(path)
        self.evidence.append(path)
        self.evidence_items.append(
            EvidenceItem(
                path=path,
                kind=resolved_kind,
                source=source,
                note=note,
                hash_sha256=hash_sha256
            )
        )

    def add_timeline_event(self, stage: str, outcome: str = "info",
                           detail: str = ""):
        self.timeline.append(
            TimelineEvent(stage=stage, outcome=outcome, detail=detail)
        )

    def add_secondary_check(self, name: str, status: str,
                            detail: str = "", data: Optional[Dict[str, Any]] = None):
        self.secondary_checks.append(
            SecondaryCheck(
                name=name,
                status=status,
                detail=detail,
                data=data or {}
            )
        )

    def set_comparison(self, baseline_label: str, current_label: str,
                       metrics: Optional[Dict[str, Any]] = None,
                       delta: Optional[Dict[str, Any]] = None,
                       verdict: str = "not_evaluated"):
        self.comparison = ComparisonSnapshot(
            baseline_label=baseline_label,
            current_label=current_label,
            metrics=metrics or {},
            delta=delta or {},
            verdict=verdict
        )
    
    def to_dict(self):
        return {
            "test_id": self.test_id,
            "test_name": self.test_name,
            "package_id": self.package_id,
            "browser": self.browser,
            "status": self.status.value,
            "severity": self.severity.value,
            "timestamp": self.timestamp,
            "message": self.message,
            "details": self.details,
            "evidence": self.evidence,
            "evidence_items": [item.to_dict() for item in self.evidence_items],
            "timeline": [event.to_dict() for event in self.timeline],
            "secondary_checks": [check.to_dict() for check in self.secondary_checks],
            "comparison": self.comparison.to_dict() if self.comparison else None,
            "remediation": self.remediation
        }


@dataclass
class TestPackageResult:
    """Test package result"""
    package_id: str
    package_name: str
    total_tests: int
    passed: int = 0
    failed: int = 0
    warning: int = 0
    inconclusive: int = 0
    results: List[TestResult] = field(default_factory=list)
    summary: str = ""
    
    def calculate_score(self) -> float:
        """0-100 arasnda test sonuc yuzdesi hesapla"""
        if self.total_tests == 0:
            return 0.0
        return (self.passed / self.total_tests) * 100
    
    def to_dict(self):
        return {
            "package_id": self.package_id,
            "package_name": self.package_name,
            "total_tests": self.total_tests,
            "passed": self.passed,
            "failed": self.failed,
            "warning": self.warning,
            "inconclusive": self.inconclusive,
            "score": self.calculate_score(),
            "results": [r.to_dict() for r in self.results],
            "summary": self.summary
        }


@dataclass
class SecurityAuditReport:
    """Complete security audit report"""
    organization: str
    test_date: str
    environment: str
    tester_name: str
    total_packages: int = 5
    packages: List[TestPackageResult] = field(default_factory=list)
    overall_score: float = 0.0
    risk_summary: Dict[str, int] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    
    def calculate_overall_score(self):
        """Calculate overall score"""
        if not self.packages:
            self.overall_score = 0.0
            return
        
        total_score = sum(p.calculate_score() for p in self.packages)
        self.overall_score = total_score / len(self.packages)
    
    def calculate_risk_summary(self):
        """Calculate risk summary"""
        self.risk_summary = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }
        
        for pkg in self.packages:
            for result in pkg.results:
                severity = result.severity.value
                if result.status == TestStatus.FAILED:
                    self.risk_summary[severity] = self.risk_summary.get(severity, 0) + 1
    
    def to_dict(self):
        self.calculate_overall_score()
        self.calculate_risk_summary()
        
        return {
            "organization": self.organization,
            "test_date": self.test_date,
            "environment": self.environment,
            "tester_name": self.tester_name,
            "total_packages": self.total_packages,
            "overall_score": round(self.overall_score, 2),
            "risk_summary": self.risk_summary,
            "packages": [p.to_dict() for p in self.packages],
            "recommendations": self.recommendations
        }


class TestLogger:
    """Test logging system"""
    
    def __init__(self, log_dir: str = "reports"):
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        self.results: List[TestResult] = []
    
    def log_test(self, result: TestResult):
        """Log test result"""
        self.results.append(result)
        if not is_quiet_mode():
            print(f"[{result.test_id}] {result.test_name}: {result.status.value}")
            if result.message:
                print(f"   {result.message}")
    
    def save_results_json(self, filename: str = None) -> str:
        """Save results as JSON"""
        if filename is None:
            filename = f"test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        filepath = os.path.join(self.log_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump([r.to_dict() for r in self.results], f, indent=2, ensure_ascii=False)
        
        print(f" Results saved: {filepath}")
        return filepath
    
    def get_summary(self) -> Dict[str, int]:
        """Test summary"""
        summary = {
            "total": len(self.results),
            "passed": sum(1 for r in self.results if r.status == TestStatus.PASSED),
            "failed": sum(1 for r in self.results if r.status == TestStatus.FAILED),
            "warning": sum(1 for r in self.results if r.status == TestStatus.WARNING),
            "inconclusive": sum(1 for r in self.results if r.status == TestStatus.INCONCLUSIVE)
        }
        return summary


class RemediationGuide:
    """ozum rehberi"""
    
    REMEDIATION_MAP = {
        "P1-001": {
            "issue": "InPrivate mode can be opened",
            "solutions": [
                "Microsoft Intune -> Device Configuration -> Restrictions -> 'InPrivate mode' disable",
                "Group Policy: gpedit.msc -> User Config -> Administrative Templates -> Windows Components -> Microsoft Edge -> 'Allow InPrivate browsing'",
                "Registry: HKCU\\Software\\Policies\\Microsoft\\Edge -> InPrivateModeAvailability = 0"
            ]
        },
        "P1-002": {
            "issue": "Additional extensions can be installed",
            "solutions": [
                "Intune -> Device Configuration -> Custom profile -> OMA-URI: ./Device/Vendor/MSFT/Policy/Config/MicrosoftEdge/ExtensionAllowlistIsExclusive",
                "Group Policy: 'ExtensionAllowList' and define 'ExtensionBlockList' policies",
                "Microsoft Edge Enterprise admin template kullan"
            ]
        },
        "P2-001": {
            "issue": "Enterprise files can be uploaded to personal email",
            "solutions": [
                "Microsoft Purview -> Data Loss Prevention -> Endpoint DLP kurallar",
                "Microsoft 365 Defender -> App governance -> SaaS risk policies",
                "Upload content type blocking: Confidential and Secret files to personal mail services"
            ]
        },
        "P4-001": {
            "issue": "Zararl extension kurulabiliyor",
            "solutions": [
                "ExtensionAllowList: Yalnzca onayl extension'lar tanmla",
                "ExtensionBlockList: Tehlikeli extension'lar yasakla",
                "Microsoft Defender SmartScreen -> Block malicious extensions"
            ]
        },
        "P5-001": {
            "issue": "Proxy bypass is possible",
            "solutions": [
                "Group Policy -> Internet Options -> Proxy settings enforce",
                "Intune -> Device Configuration -> VPN/Proxy lock",
                "Windows Firewall -> Egress filtering",
                "CASB/SSE: Detect proxy-bypass traffic"
            ]
        }
    }
    
    @staticmethod
    def get_remediation(test_id: str) -> Dict[str, Any]:
        """Test ID'ye ait cozum rehberini getir"""
        return RemediationGuide.REMEDIATION_MAP.get(
            test_id,
            {
                "issue": "No remediation guidance available for this test",
                "solutions": ["Contact the security team"]
            }
        )


class RiskCalculator:
    """Risk calculator"""
    
    @staticmethod
    def calculate_risk_score(results: List[TestResult]) -> float:
        """Calculate total risk score (0-100)"""
        if not results:
            return 0.0
        
        critical_failures = sum(1 for r in results if r.status == TestStatus.FAILED and r.severity == Severity.CRITICAL)
        high_failures = sum(1 for r in results if r.status == TestStatus.FAILED and r.severity == Severity.HIGH)
        
        risk_score = (critical_failures * 10) + (high_failures * 5)
        return min(risk_score, 100)  # Cap at 100
    
    @staticmethod
    def get_risk_level(score: float) -> str:
        """Determine risk level from risk score"""
        if score >= 80:
            return " KRITIK (Critical)"
        elif score >= 60:
            return " YKSEK (High)"
        elif score >= 40:
            return " MEDIUM (Medium)"
        else:
            return " DK (Low)"


def create_test_result(test_id: str, test_name: str, package_id: str, 
                      browser: str, status: TestStatus, severity: Severity,
                      message: str = "", **kwargs) -> TestResult:
    """Create a TestResult object."""
    return TestResult(
        test_id=test_id,
        test_name=test_name,
        package_id=package_id,
        browser=browser,
        status=status,
        severity=severity,
        message=message,
        **kwargs
    )


