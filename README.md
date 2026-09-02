# ComplyBrowse: Enterprise Browser Security Testing and Compliance Verification

ComplyBrowse is an evidence-driven browser security assessment framework for Microsoft Edge, Google Chrome, and Mozilla Firefox. It verifies browser policies, runtime behavior, identity controls, extension security, data exfiltration risks, network visibility, and compliance posture across enterprise environments.

## Overview

This project has two layers:

- Python package-test layer: 42 contract/scenario tests across risk domains
- PowerShell verification layer: browser-specific broad coverage with layered compliance verification

Current snapshot (latest verified outputs in this repository):

- Edge: 57 tests
- Chrome: 104 tests
- Firefox: 80 tests

The canonical source of package order and active scope is [config.yaml](config.yaml). This README provides a practical summary.

## Requirements

For the complete browser verification flow, use Windows with PowerShell 5.1 or
later, Python 3.8 or later, and the browser being assessed installed locally.
Some policy checks require an elevated PowerShell session. The Python report
sanitizer uses only the standard library; `coverage` is installed for the
contract-test coverage gate.

PowerShell scripts may require this one-time per-user setting:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

Risk domains:

1. Policy Hardening
2. Data Exfiltration
3. Identity and Session Security
4. Extension Threats
5. Network and Visibility
6. Shadow AI and SaaS
7. Certificate and Proxy Inspection
8. Patch and Version Hygiene
9. Compliance and Data Sovereignty

## Project Structure

```
Browser_Security/
├── browser_security_agent.py          # Main orchestrator
├── config.yaml                        # Test configuration
├── requirements.txt                   # Python dependencies
├── README.md                          # This file
├── tests/
│   ├── __init__.py
│   ├── test_framework.py
│   ├── test_package_1_policy_bypass.py
│   ├── test_package_2_data_exfiltration.py
│   ├── test_package_3_identity_session.py
│   ├── test_package_4_extensions.py
│   ├── test_package_5_network_visibility.py
│   ├── test_package_6_shadow_saas.py
│   ├── test_package_7_certificate_proxy_inspection.py
│   ├── test_package_8_patch_version_hygiene.py
│   ├── test_package_9_forensic_audit_deficiency.py
│   └── test_package_10_compliance_data_sovereignty.py
└── reports/
    ├── browser_security_report_YYYYMMDD_HHMMSS.html
    └── browser_security_report_YYYYMMDD_HHMMSS.json
```

## Setup

### 1. Install dependencies

```bash
py -3 -m pip install -r requirements.txt
```

If the `py` launcher is unavailable, use `python -m pip` with the Python
executable that is installed on the machine.

### 2. Update configuration

Edit organization values in [config.yaml](config.yaml):

```yaml
general:
  organization: "Your Organization"
  test_date: "2026-06-29"
  environment: "Production"
  tester_name: "Security Team"
```

## Practical Start

Move from static/simulation checks to dynamic, evidence-driven verification:

1. Focus first on 3 critical controls:
   - InPrivate/Incognito restriction
   - Password Manager posture
   - Developer Tools restriction
3. Keep at least one evidence item per result (observed/expected/evidence_type).

### Recommended daily flow

1. Generate a raw JSON report:

```powershell
.\test_runner.ps1 -TestId ALL -OutputJSON -OutputFile .\reports\raw\edge_raw_report.json
```

2. Generate an anonymized public report:

```powershell
.\export_public_report.ps1 -InputJson .\reports\raw\edge_raw_report.json
```

3. Export report results to CSV:

```powershell
.\export_report_csv.ps1 -InputJson .\reports\raw\edge_raw_report.json
```

**Export from dashboard:**

- Open `integrated_report.html` and select the relevant browser tab.
- Apply filters (status/severity/search).
- Click `CSV Export` button to download filtered results.

4. For GitHub/LinkedIn sharing, publish only files under reports/public.

5. Before packaging/release, remove local evidence outputs:

```powershell
.\prepare_publish_safe.ps1
```

Note: local raw reports and artifacts should remain excluded from commits via .gitignore.

## Usage

### Basic run

```bash
python browser_security_agent.py
```

### Active PowerShell verification flow (recommended)

```powershell
.\test_runner.ps1 -OutputJSON -OutputFile .\edge_test_results.json
.\apply_verification.ps1 -InputFile .\edge_test_results.json -Browser Edge -OutputFile .\edge_verified.json
```

The same pattern applies to `chrome_test_runner.ps1` and
`firefox_test_runner.ps1`, using the corresponding browser name. The generated
`*_test_results.json` and `*_verified.json` files are local assessment output;
they may contain endpoint evidence and must not be published.

To create a shareable report, sanitize a verified JSON file instead:

```powershell
.\export_public_report.ps1 -InputJson .\edge_verified.json
```

Only files ending in `_public.json` under `reports/public/` are intended for
external sharing. Keep `artifacts/`, `reports/raw/`, `reports/private/`,
`reports/csv/`, and local verification JSON files out of a public repository.

### One-command local CI-equivalent validation

Use [run_all_tests.bat](run_all_tests.bat) as the single entry point:

```bat
run_all_tests.bat
```

Host-independent behavior (portable):

- `run_all_tests.bat` resolves its working directory from its own location, so it does not require a fixed absolute path.
- If `.venv\Scripts\python.exe` exists in the repo root, it is used automatically.
- Otherwise, `run_local_ci_validation.ps1` auto-detects Python via `python3`, `python`, or `py`.

Requirements on another PC:

- PowerShell execution allowed for local scripts (for example with `RemoteSigned`).
- Python 3 available either through a local `.venv` or system PATH/`py` launcher.
- The three independent test catalogs must remain in the repository:
  `edge_cis_controls.txt`, `chrome_cis_controls.txt`, and
  `firefox_security_controls.txt`.

Or run PowerShell directly:

```powershell
.\run_local_ci_validation.ps1
```

Options:

- -SkipPythonInstall: skips pip installation
- -DisableBreakSystemPackages: disables --break-system-packages fallback for externally managed Python environments
- -PythonPath "<python_exe>": uses a specific Python executable

### Run a specific package

```python
from tests.test_package_1_policy_bypass import run_package_1

result = run_package_1("edge_unmanaged")
```

### Programmatic usage

```python
from browser_security_agent import BrowserSecurityAgent

agent = BrowserSecurityAgent("config.yaml")
agent.run_all_packages("edge_unmanaged")
agent.generate_report()
agent.print_summary()
agent.save_report_html()
agent.save_report_json()
```

## Automated Verification Contracts

Contract tests validate expected package behavior.

- Contract test file: [qa_tests/test_expected_behavior.py](qa_tests/test_expected_behavior.py)
- CI workflow: [.github/workflows/ci.yml](.github/workflows/ci.yml)

Run locally:

```bash
python -m compileall browser_security_agent.py tests qa_tests
python -m unittest discover -s qa_tests -p "test_*.py" -v
coverage run --source=browser_security_agent,tests -m unittest discover -s qa_tests -p "test_*.py"
coverage report --fail-under=60
```

These contracts check:

- package order and active package consistency
- runner output schema integrity
- test counts against config declarations
- exact test_id set matching against config
- allowed result status values
- no external network/process call guardrail violations in test packages

CI runs these contracts as mandatory gates.

Quiet mode:

- BROWSER_SECURITY_QUIET=1 minimizes package/test logs
- CI enables this by default

## Test Packages

The canonical list, order, and scope come from [config.yaml](config.yaml) under package_order and test_packages. README provides only a summary.

Summary:

- Python package layer: 10 active packages, 42 tests
- PowerShell verified snapshot: Edge 57, Chrome 104, Firefox 80
- Package details: [config.yaml](config.yaml)
- Test implementations: [tests](tests)

## Report Outputs

### Primary Report Viewer

**[integrated_report.html](integrated_report.html)** — Canonical unified viewer for all 3 browsers
- Reads verified JSON outputs: `edge_verified.json`, `chrome_verified.json`, `firefox_verified.json`
- Displays: verdicts, evidence breakdown, compliance scores, data quality metrics
- Filters: by status, severity, package, risk domain
- Export: CSV (filtered results)
- Setup: `powershell -File http_server.ps1 -Port 8888 -Path .`, then open http://localhost:8888/integrated_report.html

Legacy viewers (archived, not recommended for new deployments):
- `dashboard.html` (single-browser, outdated)
- `layer_topology_diagram.html` (architecture reference only)

### HTML Report

- visual status indicators
- risk summary
- test results table
- remediation guidance

### JSON Report

- machine-readable format
- suitable for programmatic processing
- full test details

The result model includes richer fields:

- evidence_items: evidence type/process/hash metadata
- timeline: test steps and observed event sequence
- secondary_checks: supporting secondary validations
- comparison: baseline vs current run summary

Backward compatibility is preserved: the legacy evidence list continues to work.

## Documentation

### Public Documentation

- **[README.md](README.md)** — This file; quick start guide
- **[VERIFICATION_METHODOLOGY.md](VERIFICATION_METHODOLOGY.md)** — Technical architecture, verdict logic, layer precedence
- **[SECURITY.md](SECURITY.md)** — Security policy, use disclaimers, responsible disclosure
- **[CONTRIBUTING.md](CONTRIBUTING.md)** — Developer contribution guidelines
- **[NOTICE](NOTICE)** — Third-party attribution and licensing

### Release Documentation

- **[RELEASE_POLICY.md](RELEASE_POLICY.md)** — Versioning rules and release strategy
- **[RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md)** — Release validation steps
- **[RELEASE_READY_5_CHECKS.md](RELEASE_READY_5_CHECKS.md)** — Pre-release gates (maintainers)
- **[PUBLISH_PREPARE.md](PUBLISH_PREPARE.md)** — Git init, tag, publish workflow (step-by-step)
- **[CHANGELOG.md](CHANGELOG.md)** — Version history and release notes

## Release Management

This repository follows release-based versioning. The canonical version is stored in [VERSION](VERSION).

- Policy: [RELEASE_POLICY.md](RELEASE_POLICY.md)
- Changelog: [CHANGELOG.md](CHANGELOG.md)
- Release checklist: [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md)
- Fast release readiness card: [RELEASE_READY_5_CHECKS.md](RELEASE_READY_5_CHECKS.md)
- Publish preparation: [PUBLISH_PREPARE.md](PUBLISH_PREPARE.md)
- Draft release notes:
  - [releases/v1.0.0.md](releases/v1.0.0.md)
  - [releases/v1.1.0.md](releases/v1.1.0.md)
  - [releases/v1.2.0.md](releases/v1.2.0.md)

## Attribution & License

**License:** This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

**Third-Party References:**
- **CIS**: Control identifiers are used as interoperability references. This project is independent and is not affiliated with or endorsed by CIS; no official benchmark text is distributed.
- **Tenable**: No Tenable audit files or API metadata are included. Tenable and Nessus are trademarks of Tenable, Inc.; this project is independent and is not affiliated with or endorsed by Tenable.
- **Mozilla Firefox Documentation**: Referenced for browser policy and preference interoperability; no Mozilla documentation text is distributed.
- **Microsoft Edge & Chromium Policies**: Policy documentation from Microsoft and Chromium projects.

For complete attribution, see [NOTICE](NOTICE).

**Security & Use Policy:** See [SECURITY.md](SECURITY.md) for authorized-use-only disclaimers, responsible disclosure, and privacy considerations.

## Remediation Guide

You can retrieve remediation guidance per test:

```python
from test_framework import RemediationGuide

remediation = RemediationGuide.get_remediation("P1-001")
print(remediation["issue"])
print(remediation["solutions"])
```

Typical remediation categories:

- Policy Hardening: Intune device configuration, Group Policy, registry settings
- Data Exfiltration: Purview DLP, Defender for Cloud Apps, Endpoint DLP
- Identity Issues: Conditional Access, device compliance, session management
- Extension Threats: allow/block lists, Manifest V3, permission policies
- Network Issues: proxy enforcement, DNS/DoH controls, SSL inspection checks

## Risk Score Calculation

Total risk score range: 0-100.

- 80-100: CRITICAL - immediate action required
- 60-79: HIGH - plan quick remediation
- 40-59: MEDIUM - short-term planning
- 0-39: LOW - routine monitoring

Formula:

```
Risk Score = (Critical Failed × 10) + (High Failed × 5)
```

## Expected Findings

Typical findings in unmanaged Edge environments:

| Finding | Probability | Severity |
|---|---:|---|
| User can enable sync with a personal account | 95% | Critical |
| File upload to AI tools is allowed | 90% | Critical |
| Extensions can be freely installed | 95% | High |
| InPrivate usage is allowed | 85% | High |
| Proxy bypass is possible | 80% | High |

## Security Notes

Use this testing agent only in:

- officially authorized environments
- controlled test environments
- ethical and legal boundaries

Do not use this project for:

- active malicious URL or payload delivery
- real attack execution
- any operation intended to damage systems

## Support and Development

### Adding a new test

1. Extend the test framework
2. Create a new test class
3. Add it to test_package_X.py
4. Register the package in the main agent

### Customizing test output

```python
from test_framework import TestStatus, Severity, create_test_result

result = create_test_result(
    test_id="CUSTOM-001",
    test_name="Custom Test",
    package_id="PKG-CUSTOM",
    browser="edge_managed",
    status=TestStatus.FAILED,
    severity=Severity.CRITICAL,
    message="Test failed",
    details={"custom_field": "value"}
)
```

## Logging and Debugging

During execution:

- real-time console output is shown
- a log file is generated per test
- detailed JSON output is saved

Debug mode:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Learning Resources

- [Microsoft Edge Enterprise Policies](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies)
- [Microsoft Intune Device Configuration](https://learn.microsoft.com/en-us/intune/device-profile-create)
- [Azure AD Conditional Access](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/)
- [Microsoft Purview DLP](https://learn.microsoft.com/en-us/purview/dlp-learn-about-dlp)

## License

This test agent is intended for internal enterprise security validation.

## Contact

For questions and suggestions, contact your security team.

---

Version: 1.0
Last Updated: 2026-06-29
Status: Active
