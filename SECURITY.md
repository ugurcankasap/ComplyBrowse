# Security Policy

## Overview

This project is a **browser security verification framework** designed for enterprise security assessments and compliance testing. It performs configuration inspection and policy evaluation on Edge, Chrome, and Firefox.

## Important Disclaimers

### Authorized Use Only

This tool **must only be used on systems you own or have explicit written authorization to test**. Unauthorized access to computer systems is illegal. Always obtain written permission before conducting security assessments.

### Educational and Professional Use

- This tool is designed for security professionals and administrators.
- Results are indicators only; they do not constitute a formal compliance audit or security certification.
- A qualified security analyst must interpret findings in the context of your organization's policies and risk profile.

### Not a Substitute for Professional Audit

- Use this tool as part of a broader security assessment program, not as the sole source of compliance determination.
- For regulatory compliance (HIPAA, PCI-DSS, SOC 2, etc.), engage qualified third-party auditors.

### Data Sensitivity

- This tool accesses browser configurations, which may include organizational policies and user profiles.
- Always run in controlled environments and sanitize outputs before sharing.
- Use the `prepare_publish_safe.ps1` script before publishing results externally.

## Responsible Disclosure

If you discover a security vulnerability in this project's code:

1. **Do not** open a public issue.
2. Email a detailed report to the repository maintainer.
3. Include affected version(s), reproduction steps, and potential impact.
4. Allow 7 days for acknowledgment and up to 30 days for a patch.

## Compliance and Attribution

This project includes references to:
- **CIS** — Control identifiers are used only as independent interoperability references; this project is not affiliated with or endorsed by CIS.
- **Tenable** — No Tenable audit files or API metadata are distributed by this project; this project is not affiliated with or endorsed by Tenable, Inc.

See [NOTICE](NOTICE) for detailed attribution and usage terms.

## Version

Current policy version: 1.0 (2026-08-20)
