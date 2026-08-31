import argparse
import json
import re
from pathlib import Path


EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
WIN_PATH_RE = re.compile(r"[A-Za-z]:\\[^\s\"']+")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HOST_RE = re.compile(r"\b(?:PC|LAPTOP|DESKTOP)-[A-Za-z0-9_-]+\b", re.IGNORECASE)


SENSITIVE_TOP_LEVEL_KEYS = {
    "organization": "Sample Organization",
}


def mask_text(value: str) -> str:
    text = value
    text = EMAIL_RE.sub("REDACTED_EMAIL", text)
    text = WIN_PATH_RE.sub("REDACTED_PATH", text)
    text = IPV4_RE.sub("REDACTED_IP", text)
    text = HOST_RE.sub("REDACTED_HOST", text)
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


def main():
    parser = argparse.ArgumentParser(description="Sanitize report JSON for public sharing")
    parser.add_argument("--input", required=True, help="Input JSON report path")
    parser.add_argument("--output", required=True, help="Output sanitized JSON path")
    args = parser.parse_args()

    in_path = Path(args.input)
    out_path = Path(args.output)

    data = json.loads(in_path.read_text(encoding="utf-8-sig"))
    sanitized = sanitize_obj(data)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(sanitized, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"Sanitized report written: {out_path}")


if __name__ == "__main__":
    main()
