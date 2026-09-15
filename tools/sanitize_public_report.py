import argparse
import json
import re
from pathlib import Path


EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
WIN_PATH_RE = re.compile(r"[A-Za-z]:\\[^\s\"']+")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HOST_RE = re.compile(r"\b(?:PC|LAPTOP|DESKTOP)-[A-Za-z0-9_-]+\b", re.IGNORECASE)
MAC_PATH_RE = re.compile(r"/Users/[^\r\n\"']+", re.IGNORECASE)
UUID_RE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b", re.IGNORECASE)
SERIAL_RE = re.compile(r"(?i)(?:serial(?:\s+number)?|hardware\s+uuid)\s*[:=]\s*[^,;\s]+")
EXTENSION_ID_RE = re.compile(r"(?<![A-Za-z0-9])[a-p]{32}(?![A-Za-z0-9])")


SENSITIVE_TOP_LEVEL_KEYS = {
    "organization": "Sample Organization",
}


def mask_text(value: str) -> str:
    text = value
    text = MAC_PATH_RE.sub("REDACTED_PATH", text)
    text = EMAIL_RE.sub("REDACTED_EMAIL", text)
    text = WIN_PATH_RE.sub("REDACTED_PATH", text)
    text = IPV4_RE.sub("REDACTED_IP", text)
    text = HOST_RE.sub("REDACTED_HOST", text)
    text = UUID_RE.sub("REDACTED_UUID", text)
    text = SERIAL_RE.sub("REDACTED_DEVICE_ID", text)
    text = EXTENSION_ID_RE.sub("REDACTED_EXTENSION_ID", text)
    return text


def sanitize_obj(obj):
    if isinstance(obj, dict):
        out = {}
        for key, value in obj.items():
            if key in SENSITIVE_TOP_LEVEL_KEYS and isinstance(value, str):
                out[key] = SENSITIVE_TOP_LEVEL_KEYS[key]
                continue

            # Force anonymized hostname if present.
            if key.lower() == "hostname":
                out[key] = "REDACTED_HOST"
                continue

            out[key] = sanitize_obj(value)
        return out

    if isinstance(obj, list):
        return [sanitize_obj(item) for item in obj]

    if isinstance(obj, str):
        return mask_text(obj)

    return obj


PUBLIC_RESULT_KEYS = (
    "browser",
    "platform",
    "control_id",
    "expected_value",
    "observed_value",
    "verdict",
    "evidence_type",
    "source_type",
)


def _result_list(data):
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get("results"), list):
        return data["results"]
    return []


def _first_control_id(result):
    if result.get("control_id"):
        return result["control_id"]
    for key in ("cis_controls", "cis_control"):
        values = result.get(key)
        if isinstance(values, list) and values:
            return values[0]
        if isinstance(values, str) and values:
            return values
    return result.get("test_id", "")


def _public_value(value):
    if isinstance(value, (dict, list)):
        return "REDACTED_VALUE"
    if value is None:
        return ""
    text = str(value)
    if re.search(r"(?i)<\/?plist|profile(?:_name|_path| directory)?\s*[:=]|mdm[_ -]?enrollment|hardware\s+uuid|serial(?:\s+number)?", text):
        return "REDACTED_VALUE"
    return mask_text(text)


def _verdict(result):
    value = result.get("verdict") or result.get("runner_verdict") or result.get("verification_status") or result.get("status") or "NOT_ASSESSED"
    return {"PASSED": "PASS", "FAILED": "FAIL", "UNKNOWN": "NOT_ASSESSED"}.get(str(value).upper(), str(value).upper())


def _source_type(result):
    source = str(result.get("evidence_source_label") or result.get("evidence_type") or "").lower()
    if "managed" in source or "mdm" in source or "policy" in source:
        return "managed_policy"
    if "profile" in source or "user" in source or "pref" in source:
        return "user_preference"
    if "runtime" in source or "process" in source:
        return "runtime_process"
    if "bundle" in source or "json" in source:
        return "browser_bundle"
    if "system" in source:
        return "system_preference"
    return "sanitized_source"


def build_public_report(data):
    """Build a strict public schema instead of recursively exposing evidence."""
    top_browser = data.get("browser", "") if isinstance(data, dict) else ""
    top_platform = data.get("platform", "") if isinstance(data, dict) else ""
    results = []
    for raw in _result_list(data):
        if not isinstance(raw, dict):
            continue
        result = {
            "browser": _public_value(raw.get("browser", top_browser)),
            "platform": _public_value(raw.get("platform", top_platform or "Windows")),
            "control_id": _public_value(_first_control_id(raw)),
            "expected_value": _public_value(raw.get("expected_value", "")),
            "observed_value": _public_value(raw.get("observed_value", "")),
            "verdict": _verdict(raw),
            "evidence_type": _public_value(raw.get("evidence_type", "")),
            "source_type": _source_type(raw),
        }
        results.append(result)

    browsers = {item["browser"] for item in results if item["browser"]}
    platforms = {item["platform"] for item in results if item["platform"]}
    return {
        "browser": next(iter(browsers)) if len(browsers) == 1 else "mixed",
        "platform": next(iter(platforms)) if len(platforms) == 1 else "mixed",
        "results": results,
    }


def main():
    parser = argparse.ArgumentParser(description="Sanitize report JSON for public sharing")
    parser.add_argument("--input", required=True, help="Input JSON report path")
    parser.add_argument("--output", required=True, help="Output sanitized JSON path")
    args = parser.parse_args()

    in_path = Path(args.input)
    out_path = Path(args.output)

    data = json.loads(in_path.read_text(encoding="utf-8-sig"))
    sanitized = build_public_report(data)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(sanitized, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"Sanitized report written: {out_path}")


if __name__ == "__main__":
    main()
