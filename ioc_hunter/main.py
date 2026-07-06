#!/usr/bin/env python3
"""
Daily IOC hunter - run once/day after logs rotate.

Usage:
    python main.py \\
        --auth auth_parsed.jsonl \\
        --auditd auditd_parsed.jsonl \\
        --ufw ufw_parsed.jsonl \\
        --waf safeline_parsed.jsonl \\
        --outdir ioc_output \\
        --db actors.db

All args are optional and fall back to config.py defaults.
"""

import argparse
import json
import os
from datetime import datetime, timezone

import config
from loaders import load_all
from actor_db import ActorDB
from correlator import build_bundles, combined_timeline, filter_local_flags

from detectors import auth as auth_detectors
from detectors import auditd as auditd_detectors
from detectors import ufw as ufw_detectors
from detectors import waf as waf_detectors


def _json_default(o):
    # datetimes in records (_ts) aren't natively JSON-serializable
    if isinstance(o, datetime):
        return o.isoformat()
    return str(o)


def run(auth_path, auditd_path, ufw_path, waf_path, outdir, db_path):
    run_date = datetime.now(timezone.utc).isoformat()

    print(f"[info] loading logs...")
    records = load_all(auth_path, auditd_path, ufw_path, waf_path)
    for k, v in records.items():
        print(f"[info]   {k}: {len(v)} records")

    db = ActorDB(db_path)

    print("[info] running detectors...")
    flags = []
    flags += auth_detectors.run_all(records["auth"])
    flags += auditd_detectors.run_all(records["auditd"])
    flags += ufw_detectors.run_all(records["ufw"], db, run_date=run_date)
    flags += waf_detectors.run_all(records["waf"])

    flags = filter_local_flags(flags)
    print(f"[info] {len(flags)} flags raised (after filtering local IPs)")

    # update the running actor list
    for flag in flags:
        db.upsert_actor(flag.indicator, flag.indicator_type, flag.category, run_date=run_date)

    bundles = build_bundles(flags, records)
    timeline = combined_timeline(bundles)

    os.makedirs(outdir, exist_ok=True)
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    out_path = os.path.join(outdir, f"ioc_report_{date_str}.json")

    report = {
        "run_date": run_date,
        "summary": {
            "total_flags": len(flags),
            "unique_indicators": len({(f.indicator, f.indicator_type) for f in flags}),
            "categories": sorted({f.category for f in flags}),
        },
        "flagged_indicators": [
            {
                "indicator": b["indicator"],
                "type": b["type"],
                "categories": b["categories"],
                "reasons": b["reasons"],
                "related_event_count": b["related_event_count"],
            }
            for b in bundles
        ],
        "timeline": timeline,
    }

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=_json_default)

    print(f"[info] wrote combined report: {out_path}")
    print(f"[info] running actor list now has {len(db.all_actors())} entries in {db_path}")

    db.close()
    return out_path


def main():
    p = argparse.ArgumentParser(description="Daily IOC hunter across auth/auditd/ufw/safeline-waf logs")
    p.add_argument("--auth", default=config.AUTH_LOG_PATH)
    p.add_argument("--auditd", default=config.AUDITD_LOG_PATH)
    p.add_argument("--ufw", default=config.UFW_LOG_PATH)
    p.add_argument("--waf", default=config.WAF_LOG_PATH)
    p.add_argument("--outdir", default=config.OUTPUT_DIR)
    p.add_argument("--db", default=config.DB_PATH)
    args = p.parse_args()

    run(args.auth, args.auditd, args.ufw, args.waf, args.outdir, args.db)


if __name__ == "__main__":
    main()
