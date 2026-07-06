"""
Load the four jsonl log types. Each record gets a `_ts` (parsed datetime)
and `_source` (log type name) attached so downstream code doesn't need to
know per-schema field names for time or origin.
"""

import json
from utils import parse_ts


def _load_jsonl(path, source_name, ts_field="datetime"):
    records = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue  # skip malformed lines silently; consider logging
                rec["_source"] = source_name
                rec["_ts"] = parse_ts(rec.get(ts_field))
                rec["_line"] = lineno
                records.append(rec)
    except FileNotFoundError:
        print(f"[warn] {source_name} log not found at {path}, skipping")
    return records


def load_all(auth_path, auditd_path, ufw_path, waf_path):
    return {
        "auth": _load_jsonl(auth_path, "auth"),
        "auditd": _load_jsonl(auditd_path, "auditd"),
        "ufw": _load_jsonl(ufw_path, "ufw"),
        "waf": _load_jsonl(waf_path, "waf"),
    }
