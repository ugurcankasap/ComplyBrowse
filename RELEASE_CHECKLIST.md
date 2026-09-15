# Release Checklist

Use this checklist for every release.

## 1) Scope Lock

- Confirm release scope and target version.
- Confirm the release tag matches `VERSION`, and promote the finalized `CHANGELOG.md` Unreleased section into the matching GitHub Release notes.
- Freeze non-release changes.
- Review every staged, modified, deleted, and untracked file with `git status --short`.
- Do not stage deleted tools or new platform collectors until their purpose and release scope are confirmed.

## 2) Validation

- Run target test suites.
- Verify report viewers load correctly.
- Verify JSON schema-level expectations for current scope.

## 3) Security and Privacy

- Run workspace cleanup before packaging:

```powershell
.\prepare_publish_safe.ps1
```

- Confirm the automated private artifact and evidence leak gate passes:

```powershell
.\tools\check_publish_safety.ps1
```

- Run public sanitize export for sample reports.
- Verify no private host, path, org, or user data in public artifacts.

## 4) Documentation

- Update CHANGELOG.md.
- Update or create GitHub Release notes.
- Include known limitations and next-step items.
- Describe macOS CI as fixture-only validation; do not present it as live browser or MDM verification.

## 5) Release Operation

- Tag commit with version (for example: v1.1.0).
- Publish release notes in GitHub Releases.
- Announce summary (optional: LinkedIn/GitHub post).

Local-only mode (no publish yet):
- Prepare tag candidates and keep them as planned commands in a local prep file.
- Skip GitHub Release publishing and external announcement.

## 6) Post-Release

- Smoke check quick run scripts.
- Record follow-up items for next version.
