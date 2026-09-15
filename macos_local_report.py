#!/usr/bin/env python3

import argparse
import html
import json
from pathlib import Path


def load_report(path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def load_policy_map(path):
    if not path:
        return []
    payload = load_report(path)
    return payload if isinstance(payload, list) else payload.get("controls", [])


def result_rows(report):
    rows = report.get("results", [])
    if isinstance(rows, dict):
        rows = rows.get("results", [])
    return rows if isinstance(rows, list) else []


def row_verdict(row):
    return str(row.get("verdict") or row.get("runner_verdict") or "NOT_ASSESSED")


def render_browser(name, report):
    rows = result_rows(report)
    declared = report.get("summary", {})
    values = {row_verdict(row) for row in rows}
    counts = {value: sum(row_verdict(row) == value for row in rows) for value in values}
    cards = " ".join(
        f'<span class="pill {html.escape(key.lower())}">{html.escape(key)}: {value}</span>'
        for key, value in sorted(counts.items())
    )
    table = []
    for row in rows:
        table.append(
            "<tr>"
            f"<td>{html.escape(str(row.get('test_id', row.get('control_id', ''))))}</td>"
            f"<td>{html.escape(str(row.get('test_name', row.get('name', ''))))}</td>"
            f"<td>{html.escape(row_verdict(row))}</td>"
            f"<td>{html.escape(str(row.get('evidence_type', '')))}</td>"
            f"<td>{html.escape(str(row.get('root_cause', row.get('not_assessed_reason', ''))))}</td>"
            "</tr>"
        )
    return (
        f'<section><h2>{html.escape(name)}</h2>'
        f'<p class="summary">Total: {len(rows)} &nbsp; '
        f"Score: {html.escape(str(declared.get('compliance_score_percent', declared.get('risk_score', 'n/a'))))}</p>"
        f'<div class="pills">{cards}</div>'
        '<table><thead><tr><th>ID</th><th>Control</th><th>Verdict</th>'
        '<th>Evidence</th><th>Root cause</th></tr></thead><tbody>'
        + "".join(table)
        + "</tbody></table></section>"
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--chrome", type=Path, required=True)
    parser.add_argument("--firefox", type=Path, required=True)
    parser.add_argument("--safari", type=Path, required=True)
    parser.add_argument("--template", type=Path)
    parser.add_argument("--chrome-map", type=Path)
    parser.add_argument("--firefox-map", type=Path)
    parser.add_argument("--safari-map", type=Path)
    args = parser.parse_args()

    reports = [
        ("Google Chrome", load_report(args.chrome)),
        ("Mozilla Firefox", load_report(args.firefox)),
        ("Apple Safari", load_report(args.safari)),
    ]

    if args.template:
        browser_files = {
            "chrome": (args.chrome, args.chrome_map),
            "firefox": (args.firefox, args.firefox_map),
            "safari": (args.safari, args.safari_map),
        }
        embedded = {}
        for browser, (report_path, map_path) in browser_files.items():
            embedded[browser] = {
                "testResults": load_report(report_path),
                "verified": load_report(report_path),
                "policyMap": load_policy_map(map_path),
            }
        template = args.template.read_text(encoding="utf-8")
        payload = json.dumps(embedded, ensure_ascii=True, separators=(",", ":"))
        document = template.replace("</head>", f"<script>window.__MACOS_DATA__={payload};</script></head>", 1)
        args.output.write_text(document, encoding="utf-8")
        return

    sections = "".join(render_browser(name, report) for name, report in reports)
    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ComplyBrowse macOS Security Report</title>
<style>
body {{ margin: 0; padding: 32px; background: #f4f1ea; color: #20231f; font: 15px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }}
main {{ max-width: 1400px; margin: auto; }}
h1 {{ margin-bottom: 4px; }} .meta,.summary {{ color: #66695f; }}
section {{ background: #fffdf8; border: 1px solid #d9d3c7; margin: 24px 0; padding: 20px; overflow-x: auto; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 16px; }} th,td {{ border-bottom: 1px solid #e4dfd5; padding: 9px; text-align: left; vertical-align: top; }}
th {{ color: #63675d; font-size: 12px; text-transform: uppercase; }}
.pills {{ display: flex; flex-wrap: wrap; gap: 8px; }} .pill {{ border-radius: 999px; padding: 5px 9px; background: #ece9e0; font-size: 12px; }}
.pass {{ background: #d9f1df; }} .fail {{ background: #f7d9d5; }} .not_assessed {{ background: #eee9d7; }} .pass_not_enforced {{ background: #dce7f5; }}
</style></head><body><main><h1>ComplyBrowse macOS Security Report</h1>
<p class="meta">Generated locally. Source files and endpoint evidence remain outside the repository.</p>
{sections}
</main></body></html>"""
    args.output.write_text(document, encoding="utf-8")


if __name__ == "__main__":
    main()