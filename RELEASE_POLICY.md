# Release Policy

This project uses semantic versioning with the following release line:
- v1.0.0: Pre-dynamic baseline (last stable state before dynamic transition)
- v1.0.1: Catalog reliability, Edge verdict correctness, and community workflow
- v1.1.0: macOS platform support (Chrome, Firefox, limited Safari) and the publish-safety gate
- v1.2.0 (planned): Dynamic evidence transition (expected/observed/evidence/confidence + artifacts)

## Versioning Rules

- MAJOR: Breaking changes to report schema, API-like interfaces, or workflows.
- MINOR: Backward-compatible feature additions.
- PATCH: Backward-compatible bug fixes and small quality updates.

## Current Baseline Decision

- v1.0.0 is defined as the final stable commit before dynamic transition work.
- v1.1.0 extends the assessment surface to macOS without breaking the Windows report schema.
- v1.2.0 represents the first dynamic evidence-ready release and is not shipped yet.

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
