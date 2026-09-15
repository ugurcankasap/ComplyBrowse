#!/bin/zsh

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
RUN_DIR="$(mktemp -d "${TMPDIR:-/tmp}/complybrowse-macos.XXXXXX")"

cleanup_on_error() {
    print "MacOS security assessment failed. Local files remain in: $RUN_DIR" >&2
}
trap cleanup_on_error ERR

if [[ "$(uname -s)" != "Darwin" ]]; then
    print "This launcher must be run on macOS." >&2
    exit 1
fi

if ! command -v pwsh >/dev/null 2>&1; then
    print "PowerShell 7 (pwsh) is required. Install it before running this launcher." >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    print "Python 3 is required to serve the local report." >&2
    exit 1
fi

print "ComplyBrowse macOS assessment"
print "Local output: $RUN_DIR"

for app in "Google Chrome" "Firefox" "Safari"; do
    if [[ -d "/Applications/$app.app" ]]; then
        open -ga "$app" || print "Warning: could not open $app" >&2
    fi
done

python3 - <<'PY'
import subprocess
import time

patterns = ("Google Chrome", "Firefox", "Safari")
deadline = time.monotonic() + 10
while time.monotonic() < deadline:
    processes = subprocess.run(("/bin/ps", "-axo", "comm="), capture_output=True, text=True, check=False).stdout
    if all(any(pattern in line for line in processes.splitlines()) for pattern in patterns):
        break
    time.sleep(0.25)
PY

pwsh -NoProfile -File "$ROOT_DIR/chrome_macos_test_runner.ps1" \
    -OutputJSON -OutputFile "$RUN_DIR/chrome_macos_test_results.json"

pwsh -NoProfile -File "$ROOT_DIR/firefox_macos_test_runner.ps1" \
    -OutputJSON -OutputFile "$RUN_DIR/firefox_macos_test_results.json"

pwsh -NoProfile -File "$ROOT_DIR/safari_macos_test_runner.ps1" \
    -OutputJSON -OutputFile "$RUN_DIR/safari_macos_test_results.json"

python3 "$ROOT_DIR/macos_local_report.py" \
    --template "$ROOT_DIR/integrated_report.html" \
    --output "$RUN_DIR/macos_security_report.html" \
    --chrome "$RUN_DIR/chrome_macos_test_results.json" \
    --firefox "$RUN_DIR/firefox_macos_test_results.json" \
    --safari "$RUN_DIR/safari_macos_test_results.json" \
    --chrome-map "$ROOT_DIR/chrome_macos_policy_map.json" \
    --firefox-map "$ROOT_DIR/firefox_macos_policy_map.json" \
    --safari-map "$ROOT_DIR/safari_macos_policy_map.json"

print "Assessment complete. Opening local report..."
open "$RUN_DIR/macos_security_report.html"
print "Report: $RUN_DIR/macos_security_report.html"
print "No assessment output was written to the repository."