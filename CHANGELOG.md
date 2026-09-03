# Changelog

All notable changes to this project are documented in this file.

## [v1.0.1] - 2026-09-03

### Reliability
- Browser control catalogs now fail fast when missing or unparseable instead of silently reducing test coverage.
- Catalog contracts enforce the published Edge (26), Chrome (88), and Firefox (60) reference-control counts.
- Edge observational checks no longer emit FAIL from file presence, inventory counts, or other non-conclusive signals.
- Edge proxy bypass evaluation now compares `ProxyMode` and `ProxyBypassList` policy values.

### Community
- Added structured bug and feature request forms with private security-report routing.
- Added pull request checklist, CODEOWNERS, and contributor conduct policy.
- Added repository status badges and automated community-health contracts.

## [v1.0.0] - 2026-08-20

### Overview
Baseline release: 241 total tests across Edge (57), Chrome (104), Firefox (80) with 3-layer verification engine and 4-verdict framework.

### Core Features
- **3-Layer Verification Engine**: Managed policy (L1) > User config (L2) > Runtime/behavioral observation (L3)
- **4-Verdict Framework**: PASS, PASS_NOT_ENFORCED, FAIL, NOT_ASSESSED
- **10 Risk Domain Packages**: Policy hardening, data exfiltration, identity/session, extensions, network visibility, shadow SaaS, certificate/proxy, patch hygiene, compliance, forensic audit
- **Browser Support**: Microsoft Edge, Google Chrome, Mozilla Firefox
- **Evidence Model**: Value-based comparison with expected/observed/evidence_type tracking
- **Policy Mapping**: Independent browser policy mappings with CIS control identifiers used as references
- **Root-Cause Taxonomy**: Categorized failure analysis (configuration, policy, enforcement, management channel)
- **Behavioral Validation**: Suspicious verdict downgrade when evidence is weak (LIMITED/NONE)
- **Multi-Platform Detection**: GPO, Intune CSP, MDM ADMX, ManageEngine, Workspace ONE, cloud-managed
- **Report Generation**: HTML viewer with risk summary, CSV export, JSON structured output
- **Compliance Audit**: Result integrity gates (A1–A7 defect codes), verification engine self-validation (15 truth table + 9 scenarios)

### Architecture
- PowerShell 5.1+ verification runners (host-independent)
- Python 3 package test layer (10 packages, 42 tests, ≥60% coverage gate)
- Data quality metrics (evidence basis, layer distribution, confidence scoring)
- Policy provenance tracking per result

### Safety & Compliance
- Authorized-use-only security disclaimers ([SECURITY.md](SECURITY.md))
- MIT License with third-party attribution ([NOTICE](NOTICE))
- Data privacy: Local evidence output cleanup via `prepare_publish_safe.ps1`
- Contract gates: Python syntax, coverage ≥60%, test package isolation
- Regression gates: Verification logic validation, result defect audit

### Known Limitations
- Requires elevated (admin) PowerShell for policy registry reads
- Firefox runtime checks detect only existing processes (no auto-launch)
- Some Edge tests are observational only (filesystem, preferences; no live policy data)
- Edge DevTools checks (CDP) marked NOT_ASSESSED when browser not running
- Public CI runs on Windows with browsers installed; EDR may block script execution

### Public Artifacts
- [README.md](README.md): Quick start and usage
- [VERIFICATION_METHODOLOGY.md](VERIFICATION_METHODOLOGY.md): Technical architecture
- [SECURITY.md](SECURITY.md): Use policies and responsible disclosure
- [CONTRIBUTING.md](CONTRIBUTING.md): Code contribution guidelines
- [NOTICE](NOTICE): Third-party attribution (CIS, Tenable, Mozilla, Microsoft)
- GitHub Actions CI: Python contract tests (Ubuntu) + verification regression (Windows with browsers)

### Release Artifacts
- 3 browser-specific test runners (Edge, Chrome, Firefox)
- 1 value-verification applier (4-verdict layer logic)
- 1 integrity auditor (defect detection)
- 1 engine validator (truth table + scenarios)
- 1 HTML/JSON report generator
- 1 public sanitize flow (evidence cleanup)
