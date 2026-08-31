# Release Checklist

Use this checklist for every release.

## 1) Scope Lock

- Confirm release scope and target version.
- Freeze non-release changes.

## 2) Validation

- Run target test suites.
- Verify report viewers load correctly.
- Verify JSON schema-level expectations for current scope.

## 3) Security and Privacy

- Run workspace cleanup before packaging:

```powershell
.\prepare_publish_safe.ps1
```

- Run public sanitize export for sample reports.
- Verify no private host, path, org, or user data in public artifacts.

## 4) Documentation

- Update CHANGELOG.md.
- Update or create GitHub Release notes.
- Include known limitations and next-step items.

## 5) Release Operation

- Tag commit with version (for example: v1.2.0).
- Publish release notes in GitHub Releases.
- Announce summary (optional: LinkedIn/GitHub post).

Local-only mode (no publish yet):
- Prepare tag candidates and keep them as planned commands in a local prep file.
- Skip GitHub Release publishing and external announcement.

## 6) Post-Release

- Smoke check quick run scripts.
- Record follow-up items for next version.
