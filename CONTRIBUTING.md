# Contributing to ComplyBrowse

Thank you for your interest in contributing to this project.

## Before You Start

1. **Read the License** — This project is MIT-licensed. All contributions are accepted under this license.
2. **Read the Security Policy** — Understand the authorized use disclaimers in [SECURITY.md](SECURITY.md).
3. **Project Scope** — This is a browser security verification framework, not a general browser tool.

## Contribution Guidelines

### Development Workflow

1. Open or choose an issue before starting a substantial change.
2. Create a branch from the latest `main` branch, for example `fix/edge-proxy-evidence` or `feature/sarif-export`.
3. Keep each pull request focused on one problem.
4. Run the relevant focused checks, then the full QA contract suite.
5. Open a pull request and complete the repository checklist.

Direct pushes to `main` should be limited to repository administration. Code changes should normally be reviewed through pull requests.

### Code Changes

1. Ensure all PowerShell scripts run without EDR blocks on a clean test system.
2. Add test cases to the appropriate package in `tests/` or `qa_tests/` before submitting.
3. Verify the contract gate passes locally:
   ```powershell
   python -m unittest discover -s qa_tests -p "test_*.py" -v
   ```
4. Include clear docstrings explaining what your change does and why.
5. Follow existing code style (PowerShell: PascalCase functions, Python: snake_case).

### Documentation

1. Update [CHANGELOG.md](CHANGELOG.md) under the unreleased version.
2. If adding a new test package, document it in [config.yaml](config.yaml) and README.md.
3. For architectural changes, update [VERIFICATION_METHODOLOGY.md](VERIFICATION_METHODOLOGY.md).

### Testing

- **Python contract tests** must pass: `python -m unittest discover -s qa_tests -p "test_*.py"`
- **Coverage gate** must be ≥60%: `coverage report --fail-under=60`
- **Verification regression**: Run `run_local_ci_validation.ps1` to validate end-to-end.

### Commit Messages

- Keep first line ≤ 50 characters, descriptive.
- Reference issue numbers if applicable: `Fixes #123`.
- Example: `Add Chrome extension intent evaluator for CIS 2.3.3`

## Reporting Issues

- **Security vulnerabilities**: See [SECURITY.md](SECURITY.md) for responsible disclosure.
- **Bugs**: Include PowerShell version, Python version, OS, and reproduction steps.
- **Enhancement requests**: Describe the use case and expected behavior.

## Project Structure

```
Browser_Security/
├── tests/                          # Python test packages
│   ├── test_package_*.py          # 10 risk domain packages
│   └── test_framework.py          # Test utilities
├── qa_tests/                       # Contract/regression tests
├── config.yaml                     # Test package configuration
├── *_test_runner.ps1              # Browser-specific runner scripts
├── apply_verification.ps1         # Verification verdict layer
├── verify_value_based.ps1         # Layer 1/2/3 evidence collectors
├── VERIFICATION_METHODOLOGY.md    # Technical architecture
└── README.md                       # Quick start
```

## Key Concepts

### 4-Verdict System
- **PASS**: Policy configured correctly, behavior enforced.
- **PASS_NOT_ENFORCED**: Policy configured but no behavioral evidence.
- **FAIL**: Policy misconfigured or control failed.
- **NOT_ASSESSED**: Cannot measure (missing data, unsupported platform, etc.).

### Layer Precedence
- **L1**: Managed policy (most authoritative)
- **L2**: User preference/profile config
- **L3**: Runtime/behavioral observation
- Policy always outranks user pref; evidence precedence chain applies.

### No Key Presence Logic
- A policy key existing ≠ compliance. Always verify the **value** matches expectations.
- If no user-pref equivalent exists, return **NOT_APPLICABLE**, never invent a result.

## Questions?

- Check [VERIFICATION_METHODOLOGY.md](VERIFICATION_METHODOLOGY.md) for technical details.

Thank you for contributing!
