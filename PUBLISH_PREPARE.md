# Pre-Publish Preparation Checklist

This document captures the complete preparation sequence before publishing Browser Security to GitHub.

## Step 1: Environment Validation (Before Git Init)

Run the local validation suite to ensure gates pass:

```powershell
cd path\to\Browser_Security
.\run_local_ci_validation.ps1
```

**Expected output:** All gates PASS (or only non-blocking warnings).

If any gate fails:
- `verify_value_based.ps1` syntax/logic error → check recent PowerShell edits
- `apply_verification.ps1` verdict logic → check verdict assignment in layers
- `audit_result_integrity.ps1` blocking defect → blocking defect codes A1–A7 must be resolved
- Python contract tests → run `python -m unittest discover -s qa_tests -p "test_*.py" -v`

## Step 2: Data Cleanup (Publish Safety)

Remove all local endpoint evidence before git init:

```powershell
.\prepare_publish_safe.ps1
```

This removes:
- `artifacts/` (36 local assessment runs)
- `reports/raw/`, `reports/private/`, `reports/csv/`
- `*_test_results.json`, `*_verified.json` (endpoint snapshots)
- `.coverage` (coverage artifacts)
- `reports/turkish_test_lines.txt`

Verify cleanup:

```powershell
git status  # (after git init) — should show clean tree or only new files
```

## Step 3: Git Initialization

**One-time setup** (transforms folder into a git repository):

```powershell
cd path\to\Browser_Security
git init
git add .
git commit -m "Initial commit: Browser Security verification framework"
```

**Local config** (use different account if needed):

```powershell
git config user.name "your-github-username"
git config user.email "your-github-email@example.com"
```

**Add remote** (replace `YOUR_USERNAME` and `YOUR_REPO`):

```powershell
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git
git branch -M main
git push -u origin main
```

## Step 4: Tag Release Version

```powershell
git tag v1.0.0 -m "Release v1.0.0: Baseline verification framework"
git push origin v1.0.0
```

## Step 5: Verify GitHub Presence

1. Navigate to `https://github.com/YOUR_USERNAME/YOUR_REPO`
2. Confirm all files are present:
   - LICENSE ✓
   - SECURITY.md ✓
   - CONTRIBUTING.md ✓
   - NOTICE ✓
   - README.md ✓
3. Confirm no evidence outputs are visible:
   - No `*_verified.json` ✓
   - No `*_test_results.json` ✓
   - No `reports/csv/` ✓
4. Confirm CI workflow exists: `.github/workflows/ci.yml` ✓

## Step 6: Create GitHub Release

In GitHub web UI:

1. Click **Releases** → **Draft a new release**
2. Tag: `v1.0.0`
3. Title: `Browser Security v1.0.0`
4. Description:

```markdown
## Release v1.0.0 — Baseline Verification Framework

### Highlights
- 3-layer verification engine (managed policy, user config, runtime evidence)
- 4-verdict framework (PASS, PASS_NOT_ENFORCED, FAIL, NOT_ASSESSED)
- 241 total tests across Edge (57), Chrome (104), Firefox (80)
- 10 active risk domain packages
- HTML report viewer and CSV export

### Important Notes
- Educational and professional use only; see [SECURITY.md](SECURITY.md)
- Not a substitute for professional security audit
- Use `prepare_publish_safe.ps1` before sharing results

### Known Limitations
- Requires elevated (admin) PowerShell for policy registry access
- Firefox runtime checks detect only existing processes (no launch)
- Some Edge tests are observational only (no live policy data)

### Install & Run
1. Clone: `git clone https://github.com/YOUR_USERNAME/YOUR_REPO`
2. Install: `pip install -r requirements.txt`
3. Run: `.\run_all_tests.bat` or `.\test_runner.ps1 -OutputJSON -OutputFile .\edge_test_results.json`

See [README.md](README.md) for details.
```

5. Click **Publish release**

## Step 7: Monitor CI

GitHub will automatically run `.github/workflows/ci.yml`:

- **quality-gates** job (Ubuntu): Python syntax, contract tests, coverage ≥60% ✓
- **verification-regression** job (Windows): Browser runners, verification gates ✓

If CI fails on Windows:
- Check if browsers are installed (Edge, Chrome, Firefox)
- Check PowerShell execution policy: `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`
- Review job logs in GitHub Actions tab

## Step 8: Portability — Moving to Another PC

To continue development on a different machine:

1. **Clone the repo:**
   ```powershell
   git clone https://github.com/YOUR_USERNAME/YOUR_REPO.git
   ```

2. **Install dependencies:**
   ```powershell
   cd YOUR_REPO
   pip install -r requirements.txt
   ```

3. **Run validation:**
   ```powershell
   .\run_all_tests.bat
   ```

**Note:** Repository memory (Copilot session context) does not transfer. See [VERIFICATION_METHODOLOGY.md](VERIFICATION_METHODOLOGY.md) for technical architecture and working rules.

## Troubleshooting

### "git is not recognized"

- Install Git: `winget install Git.Git` (requires admin)
- Or use GitHub Desktop: https://desktop.github.com/

### "Python is not recognized"

- Install Python 3.10+: https://www.python.org/downloads/
- Or use Windows Store: `ms-windows-store://pdp/?productid=9NRWMJP3717K`
- Verify: `python --version` or `py --version`

### "Execution policy prevents script execution"

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### CI job fails on Windows

1. Ensure Edge, Chrome, Firefox are installed
2. Run locally first: `.\run_local_ci_validation.ps1`
3. Check PowerShell version: `$PSVersionTable.PSVersion`
4. For EDR issues, disable script runners in CI or skip Windows jobs

---

**Last Updated:** 2026-08-20
