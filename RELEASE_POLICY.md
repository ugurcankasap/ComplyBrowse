# Release Policy

This project uses semantic versioning with the following release line:
- v1.0.0: Pre-dynamic baseline (last stable state before dynamic transition)
- v1.1.0: Quick-report and reporting-quality improvements
- v1.2.0: Dynamic evidence transition (expected/observed/evidence/confidence + artifacts)

## Versioning Rules

- MAJOR: Breaking changes to report schema, API-like interfaces, or workflows.
- MINOR: Backward-compatible feature additions.
- PATCH: Backward-compatible bug fixes and small quality updates.

## Current Baseline Decision

- v1.0.0 is defined as the final stable commit before dynamic transition work.
- v1.1.0 is intentionally separated to represent the quality and operational improvements before full dynamic transition.
- v1.2.0 represents the first dynamic evidence-ready release.

## Release Artifacts

Each release should include:
- Git tag (for example: v1.1.0)
- GitHub Release notes (English)
- CHANGELOG.md update
- Validation summary (tests run and outcomes)

## Public Sharing Safety Gate

Before publishing release artifacts externally:
- Use the public sanitize flow.
- Do not publish raw private artifacts.
- Keep organization-sensitive metadata masked.

## Branch and Tag Convention

- Main development happens on the primary branch.
- Release candidate can be validated from a temporary release branch when needed.
- Final release is created by tagging the validated commit.
