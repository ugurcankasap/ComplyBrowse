"""Browser Security orchestrator for Python package-based test suites."""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List

from tests.test_framework import (
    RiskCalculator,
    SecurityAuditReport,
    TestPackageResult,
    TestResult,
)
from tests.test_package_1_policy_bypass import run_package_1
from tests.test_package_2_data_exfiltration import run_package_2
from tests.test_package_3_identity_session import run_package_3
from tests.test_package_4_extensions import run_package_4
from tests.test_package_5_network_visibility import run_package_5
from tests.test_package_6_shadow_saas import run_package_6
from tests.test_package_7_certificate_proxy_inspection import run_package_7
from tests.test_package_8_patch_version_hygiene import run_package_8
from tests.test_package_9_forensic_audit_deficiency import run_package_9
from tests.test_package_10_compliance_data_sovereignty import run_package_10


_RUNNER_MAP: Dict[str, Callable[[str], Dict[str, Any]]] = {
    "package_1": run_package_1,
    "package_2": run_package_2,
    "package_3": run_package_3,
    "package_4": run_package_4,
    "package_5": run_package_5,
    "package_6": run_package_6,
    "package_7": run_package_7,
    "package_8": run_package_8,
    "package_9": run_package_9,
    "package_10": run_package_10,
}


class BrowserSecurityAgent:
    """Orchestrates Python test packages using config-driven package order."""

    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = Path(config_path)
        self.config = self._load_config(self.config_path)
        self.package_results: List[Dict[str, Any]] = []
        self.audit_report: SecurityAuditReport | None = None

    def _load_config(self, config_path: Path) -> Dict[str, Any]:
        text = config_path.read_text(encoding="utf-8")
        cfg: Dict[str, Any] = {
            "general": {},
            "implementation_scope": {},
            "package_order": [],
            "test_packages": {},
        }

        in_general = False
        in_impl_scope = False
        in_package_order = False
        in_test_packages = False
        current_package_key = ""

        for raw_line in text.splitlines():
            if not raw_line.strip() or raw_line.strip().startswith("#"):
                continue

            indent = len(raw_line) - len(raw_line.lstrip(" "))
            stripped = raw_line.strip()

            if indent == 0 and stripped.endswith(":"):
                in_general = stripped == "general:"
                in_impl_scope = stripped == "implementation_scope:"
                in_package_order = stripped == "package_order:"
                in_test_packages = stripped == "test_packages:"
                if not in_test_packages:
                    current_package_key = ""
                continue

            if in_general and indent == 2 and ":" in stripped:
                key, value = stripped.split(":", 1)
                cfg["general"][key.strip()] = self._parse_scalar(value)
                continue

            if in_impl_scope and indent == 2 and ":" in stripped:
                key, value = stripped.split(":", 1)
                cfg["implementation_scope"][key.strip()] = self._parse_scalar(value)
                continue

            if in_package_order and indent == 2 and stripped.startswith("-"):
                cfg["package_order"].append(stripped[1:].strip())
                continue

            if in_test_packages and indent == 2 and stripped.endswith(":") and stripped.startswith("package_"):
                current_package_key = stripped[:-1]
                cfg["test_packages"][current_package_key] = {}
                continue

            if in_test_packages and current_package_key and indent == 4 and ":" in stripped:
                key, value = stripped.split(":", 1)
                cfg["test_packages"][current_package_key][key.strip()] = self._parse_scalar(value)

        active = cfg["implementation_scope"].get("active_packages")
        if not isinstance(active, int):
            cfg["implementation_scope"]["active_packages"] = len(cfg["package_order"])

        return cfg

    @staticmethod
    def _parse_scalar(value: str) -> Any:
        raw = value.strip()
        if raw.startswith('"') and raw.endswith('"'):
            return raw[1:-1]
        if raw.startswith("'") and raw.endswith("'"):
            return raw[1:-1]
        if re.fullmatch(r"-?\d+", raw):
            return int(raw)
        return raw

    def _get_package_plan(self) -> List[Dict[str, Any]]:
        package_order = self.config.get("package_order", [])
        test_packages = self.config.get("test_packages", {})

        plan: List[Dict[str, Any]] = []
        for package_key in package_order:
            runner = _RUNNER_MAP.get(package_key)
            if runner is None:
                continue

            package_cfg = test_packages.get(package_key, {})
            package_name = package_cfg.get("name", package_key.replace("_", " ").title())

            plan.append(
                {
                    "key": package_key,
                    "name": package_name,
                    "runner": runner,
                }
            )

        return plan

    def run_all_packages(self, browser: str = "edge_unmanaged") -> List[Dict[str, Any]]:
        self.package_results = []
        for entry in self._get_package_plan():
            self.package_results.append(entry["runner"](browser))
        return self.package_results

    def _to_package_result(self, payload: Dict[str, Any]) -> TestPackageResult:
        results = payload.get("results", [])
        summary = payload.get("summary", {})
        return TestPackageResult(
            package_id=payload.get("package_id", ""),
            package_name=payload.get("package_name", ""),
            total_tests=summary.get("total", len(results)),
            passed=summary.get("passed", 0),
            failed=summary.get("failed", 0),
            warning=summary.get("warning", 0),
            inconclusive=summary.get("inconclusive", 0),
            results=results,
            summary=payload.get("summary_text", ""),
        )

    def generate_report(self) -> SecurityAuditReport:
        if not self.package_results:
            self.run_all_packages()

        general = self.config.get("general", {})
        report = SecurityAuditReport(
            organization=str(general.get("organization", "Unknown")),
            test_date=str(general.get("test_date", datetime.now().strftime("%Y-%m-%d"))),
            environment=str(general.get("environment", "Unknown")),
            tester_name=str(general.get("tester_name", "Unknown")),
            total_packages=len(self.package_results),
        )

        report.packages = [self._to_package_result(item) for item in self.package_results]
        report.recommendations = self._recommendations_from_results(report.packages)
        report.calculate_overall_score()
        report.calculate_risk_summary()

        self.audit_report = report
        return report

    @staticmethod
    def _recommendations_from_results(packages: List[TestPackageResult]) -> List[str]:
        all_results: List[TestResult] = []
        for pkg in packages:
            all_results.extend(pkg.results)

        risk_score = RiskCalculator.calculate_risk_score(all_results)
        level = RiskCalculator.get_risk_level(risk_score)
        recommendations = [f"Overall risk score: {risk_score:.1f} ({level})"]

        failed = [r for r in all_results if r.status.value == "failed"]
        if failed:
            recommendations.append("Prioritize FAILED controls with critical/high severity first.")
        if any(r.status.value == "warning" for r in all_results):
            recommendations.append("Review WARNING results for potential enforcement gaps.")
        return recommendations

    def print_summary(self) -> None:
        if self.audit_report is None:
            self.generate_report()

        assert self.audit_report is not None
        report_dict = self.audit_report.to_dict()
        print("=" * 72)
        print("Browser Security Audit Summary")
        print("=" * 72)
        print(f"Organization : {report_dict['organization']}")
        print(f"Date         : {report_dict['test_date']}")
        print(f"Environment  : {report_dict['environment']}")
        print(f"Packages     : {report_dict['total_packages']}")
        print(f"Score        : {report_dict['overall_score']}")
        print(f"Risk Summary : {report_dict['risk_summary']}")

    def save_report_json(self, output_path: str | None = None) -> str:
        if self.audit_report is None:
            self.generate_report()

        assert self.audit_report is not None
        report_dict = self.audit_report.to_dict()

        reports_dir = self.config_path.parent / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = str(reports_dir / f"browser_security_report_{timestamp}.json")

        out_file = Path(output_path)
        out_file.write_text(json.dumps(report_dict, indent=2, ensure_ascii=False), encoding="utf-8")
        return str(out_file)

    def save_report_html(self, output_path: str | None = None) -> str:
        if self.audit_report is None:
            self.generate_report()

        assert self.audit_report is not None
        report_dict = self.audit_report.to_dict()

        reports_dir = self.config_path.parent / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = str(reports_dir / f"browser_security_report_{timestamp}.html")

        html = self._build_html(report_dict)
        out_file = Path(output_path)
        out_file.write_text(html, encoding="utf-8")
        return str(out_file)

    @staticmethod
    def _build_html(report: Dict[str, Any]) -> str:
        rows = []
        for package in report.get("packages", []):
            rows.append(
                "<tr>"
                f"<td>{package.get('package_id', '')}</td>"
                f"<td>{package.get('package_name', '')}</td>"
                f"<td>{package.get('total_tests', 0)}</td>"
                f"<td>{package.get('passed', 0)}</td>"
                f"<td>{package.get('failed', 0)}</td>"
                f"<td>{package.get('warning', 0)}</td>"
                f"<td>{package.get('score', 0):.1f}</td>"
                "</tr>"
            )

        recommendation_items = "".join(f"<li>{item}</li>" for item in report.get("recommendations", []))

        return f"""<!DOCTYPE html>
<html lang=\"tr\">
<head>
  <meta charset=\"UTF-8\" />
  <title>Browser Security Report</title>
  <style>
    body {{ font-family: Segoe UI, Arial, sans-serif; margin: 24px; color: #1f2937; }}
    h1 {{ margin-bottom: 8px; }}
    table {{ border-collapse: collapse; width: 100%; margin-top: 16px; }}
    th, td {{ border: 1px solid #d1d5db; padding: 8px; text-align: left; }}
    th {{ background: #f3f4f6; }}
  </style>
</head>
<body>
  <h1>Browser Security Audit Report</h1>
  <p><strong>Organization:</strong> {report.get('organization', '')}</p>
  <p><strong>Date:</strong> {report.get('test_date', '')}</p>
  <p><strong>Environment:</strong> {report.get('environment', '')}</p>
  <p><strong>Overall Score:</strong> {report.get('overall_score', 0)}</p>

  <h2>Package Summary</h2>
  <table>
    <thead>
      <tr>
        <th>Package ID</th>
        <th>Package</th>
        <th>Total</th>
        <th>Passed</th>
        <th>Failed</th>
        <th>Warning</th>
        <th>Score</th>
      </tr>
    </thead>
    <tbody>
      {''.join(rows)}
    </tbody>
  </table>

  <h2>Recommendations</h2>
  <ul>{recommendation_items}</ul>
</body>
</html>
"""


def main() -> None:
    agent = BrowserSecurityAgent("config.yaml")
    agent.run_all_packages("edge_unmanaged")
    agent.generate_report()
    agent.print_summary()
    json_path = agent.save_report_json()
    html_path = agent.save_report_html()
    print(f"JSON report saved: {json_path}")
    print(f"HTML report saved: {html_path}")


if __name__ == "__main__":
    main()
