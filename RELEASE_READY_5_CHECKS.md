# Release Ready - 5 Checks

**⚠️ Internal release documentation.** This file is for maintainers preparing a release.

Use this quick card before tagging a release commit.

## 1) Core Flow Works

- Main run path completes successfully.
- Quick report flow opens the report viewer.

Pass condition:
- No blocking runtime error in the primary user flow.

## 2) Output Quality Is Correct

- Report JSON is generated.
- Required fields for the target version are present and meaningful.

Pass condition:
- No broken/empty critical fields for scoped checks.

## 3) No Blocking Errors & Regression Gates Pass

- No critical script/runtime failure.
- Viewer loads and report rendering works.
- `run_local_ci_validation.ps1` exits 0 (all gates pass).
- `validate_verification_engine.ps1` exits 0 (15/15 truth table + scenarios).
- `audit_result_integrity.ps1` reports 0 blocking defects.

Pass condition:
- Only non-blocking warnings are allowed.
- All verification gates clean.

## 4) Public Safety Gate Passed

- Public sanitize/export flow executed.
- No private organization/user/host/path leakage in public artifacts.

Pass condition:
- Shareable output is sanitized and safe.

## 5) Release Notes Are Ready

- CHANGELOG entry is updated.
- GitHub Release notes draft exists for the target version.

Pass condition:
- "What changed" and "Known limitations" are documented.

---

## Final Rule

If all 5 checks are PASS, the commit is release-ready.
