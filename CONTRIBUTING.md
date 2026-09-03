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

### Adding a Control

A control enters ComplyBrowse through one of two paths:

| Path | Use when | Registration point |
| --- | --- | --- |
| Reference catalog | A benchmark/reference line has a stable control ID and expected state | Browser catalog plus `*_cis_policy_map.json` |
| Runner-native | The check is project-specific, behavioral, runtime, or not represented by a catalog | Test function plus the runner's `$BaseTestMap` |

Do not add the same control through both paths. Start by writing the evidence
contract: the expected state, the observable value, the source that can prove
it, and the condition that must produce `NOT_ASSESSED`.

#### 1. Choose the control ID and evidence class

- Keep catalog IDs identical to their source IDs. Generated test IDs are
   prefixed by the browser runner (`EDGE-REF-*`, `CIS-*`, or `FF-REF-*`).
- Use the existing package-style ID for runner-native controls (`P1-001`,
   `C-001`, `F-001`, and so on) and do not reuse an ID.
- Use a value comparison whenever a policy or preference has a deterministic
   expectation. Use an observation only when no machine-comparable expectation
   exists.
- Return an inconclusive runner status when the required source is unavailable.
   Missing telemetry, a cloud-only console, or a file's mere presence is not a
   failure.

#### 2. Add a reference catalog entry

Use the catalog belonging to the browser:

| Browser | Catalog | Accepted line shape |
| --- | --- | --- |
| Edge | `edge_cis_controls.txt` | `<id> Ensure '<title>' is set to '<expected>'` |
| Chrome | `chrome_cis_controls.txt` | `<id> Ensure '<title>' is set to '<expected>'` |
| Firefox | `firefox_security_controls.txt` | `<id> (L1) <title>` |

Keep one control per non-empty line. The runners fail fast when a catalog is
missing or contains no parseable controls. After changing catalog scope, update
the expected count in `CONTROL_CATALOGS` inside
`qa_tests/test_expected_behavior.py`; this makes accidental scope loss a CI
failure.

#### 3. Map the control to a policy or preference

Add the same `control_id` to the browser map:

- `edge_cis_policy_map.json`
- `chrome_cis_policy_map.json`
- `firefox_cis_policy_map.json`

For a managed policy, use this shape:

```json
{
   "control_id": "9.9",
   "policy_key": "ExamplePolicyEnabled",
   "mode": "POLICY",
   "equivalent_policy_keys": ["ReplacementPolicyKey"]
}
```

`equivalent_policy_keys` is optional and must contain only documented policies
with equivalent security intent. Firefox also supports `PREF` for `prefs.js` /
`user.js`, `RUNTIME` for process evidence, and `MANUAL` when no local machine
source exists. Do not invent a policy key from control prose.

#### 4. Implement or register runner evidence

Catalog controls are registered automatically by
`Get-EdgeCisTestsFromCatalog`, `Get-CisTestsFromCatalog`, or
`Get-FirefoxCisTestsFromCatalog`. Extend the browser's expectation evaluator
only when the existing boolean, enum, numeric, list, or object comparison cannot
represent the policy.

For a runner-native control, add a `Test-*` function and register it in the
browser runner's `$BaseTestMap`. A conclusive result should emit at least:

```powershell
return @{
      status = "PASSED" # or FAILED only after a real comparison
      message = "Example policy matches the expected state"
      details = "Registry policy: ExamplePolicyEnabled = 1"
      expected_value = "Expected: true"
      observed_value = "1"
      evidence_type = "registry_policy"
      confidence = "HIGH"
}
```

Set `PolicyKey` in `$BaseTestMap` when a deterministic policy key exists. For a
genuinely observational control, set `PolicyMapping = "OBSERVATIONAL"` and
return `UNKNOWN` when the observation cannot prove compliance or
non-compliance. `PASSED` and `FAILED` must never be inferred from key presence,
file presence, inventory count, or the absence of a risky string alone.

#### 5. Connect verification semantics

- Add an L2 preference mapping in `verify_value_based.ps1` only when the
   browser has a real user-level equivalent for the managed policy.
- Add absence-as-compliance cases to `control_semantics.json` for bypass lists,
   exception lists, and similar controls where an absent value is the secure
   state.
- Keep verdict logic in `apply_verification.ps1` and
   `verify_value_based.ps1` standard-agnostic. Do not branch on CIS, PCI, NIST,
   or another framework name.
- Ensure raw results provide `expected_value` and `observed_value` whenever a
   value comparison is possible. The verification output must explain its
   `mapping_class`, `evidence_basis`, `deciding_layer`, and root cause.

#### 6. Validate the complete path

Run the smallest affected test first, then the contracts and integrity gates:

```powershell
# Replace the runner, browser, and test ID for the control being added.
.\test_runner.ps1 -TestId EDGE-REF-9-9 -OutputJSON -OutputFile .\_tmp_raw.json
.\apply_verification.ps1 -InputFile .\_tmp_raw.json -Browser edge -OutputFile .\_tmp_verified.json
.\audit_result_integrity.ps1 -InputFile .\_tmp_verified.json

python -m unittest discover -s qa_tests -p "test_*.py" -v
.\validate_verification_engine.ps1
.\run_local_ci_validation.ps1
```

Before opening the pull request, inspect the generated result and confirm:

- The expected and observed values are both present when comparison is claimed.
- `FAIL` rests on an explicit mismatch, not missing collector capability.
- Unavailable evidence becomes `NOT_ASSESSED` and is excluded from the score.
- Managed policy outranks user configuration; runtime evidence arbitrates only
   runtime controls or a real conflict.
- The result passes `audit_result_integrity.ps1` and does not increase
   `POLICY_ONLY`, `MANUAL`, `UNKNOWN`, or unresolved-key counts without a
   documented reason.

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
