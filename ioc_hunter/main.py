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
import time
from datetime import datetime, timezone

import config
from loaders import load_all
from actor_db import ActorDB
from correlator import build_bundles, combined_timeline, filter_local_flags
import audit_merge
import enrich_intel

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
    t0 = time.time()
    run_date = datetime.now(timezone.utc).isoformat()

    print(f"[info] loading logs...")
    records = load_all(auth_path, auditd_path, ufw_path, waf_path)
    for k, v in records.items():
        print(f"[info]   {k}: {len(v)} records")
    print(f"[info] load complete ({time.time() - t0:.1f}s elapsed)")

    db = ActorDB(db_path)

    t1 = time.time()
    print("[info] merging auditd SYSCALL+EXECVE events and backfilling src_ip via session lookup...")
    merged_auditd = audit_merge.merge_events(records["auditd"], run_date=run_date)
    records["auditd_merged"] = merged_auditd
    attributed = sum(1 for e in merged_auditd if e.get("src_ip"))
    ambiguous = sum(1 for e in merged_auditd if e.get("src_ip_ses_reuse_ambiguous"))
    print(f"[info]   {len(merged_auditd)} exec events merged, {attributed} attributed to a src_ip"
          f" ({ambiguous} with ambiguous session reuse) ({time.time() - t1:.1f}s elapsed)")

    t2 = time.time()
    print("[info] running detectors...")
    flags = []
    flags += auth_detectors.run_all(records["auth"])
    flags += auditd_detectors.run_all(records["auditd"], merged_auditd)
    flags += ufw_detectors.run_all(records["ufw"], db, run_date=run_date)
    flags += waf_detectors.run_all(records["waf"])

    flags = filter_local_flags(flags)
    unique_indicators = len({(f.indicator, f.indicator_type) for f in flags})
    print(f"[info] {len(flags)} flags raised across {unique_indicators} unique indicators"
          f" (after filtering local IPs) ({time.time() - t2:.1f}s elapsed)")

    # --- actor history enrichment (BEFORE upserting this run's flags, so
    # history reflects prior runs only): "first time ever seen" vs "flagged
    # 14 of the last 20 days, previously for SQLi" is the cheapest, most
    # deterministic triage signal available - never make the LLM infer what
    # Python can look up.
    unique_keys = {(f.indicator, f.indicator_type) for f in flags}
    history = {}
    for indicator, itype in unique_keys:
        h = db.get_actor(indicator, itype)
        history[(indicator, itype)] = h  # None = never seen before

    # update the running actor list (single commit at the end - see
    # actor_db.py docstring on why per-call commits were the real bottleneck)
    t2b = time.time()
    for flag in flags:
        db.upsert_actor(flag.indicator, flag.indicator_type, flag.category, run_date=run_date)
    db.increment_days_seen(unique_keys)
    db.commit()
    print(f"[info] actor DB updated ({time.time() - t2b:.1f}s elapsed)")

    t3 = time.time()
    print(f"[info] correlating {unique_indicators} indicators against {sum(len(v) for v in records.values())} total records...")
    bundles = build_bundles(flags, records)
    for b in bundles:
        h = history.get((b["indicator"], b["type"]))
        b["known_actor"] = h is not None
        b["actor_history"] = h  # None if first time ever seen
        # tag signal level so enrichment can skip the noise table (conserving
        # the scarce GreyNoise weekly quota). Mirrors the chunker's routing.
        cats = set(b.get("categories", []))
        b["_low_signal"] = bool(cats) and cats.issubset(config.LOW_SIGNAL_ONLY_CATEGORIES)

    # threat-intel enrichment (read-only) of high-signal indicators
    if config.INTEL_ENABLED:
        t_intel = time.time()
        print("[info] enriching high-signal indicators with threat intel...")
        try:
            bundles, n_enriched = enrich_intel.enrich_bundles(
                bundles, db, high_signal_only=config.INTEL_ONLY_HIGH_SIGNAL)
            print(f"[info]   enriched {n_enriched} indicator(s) ({time.time() - t_intel:.1f}s elapsed)")
        except Exception as e:
            # enrichment must never break the run
            print(f"[warn]   threat-intel enrichment failed, continuing without it: {e}")

    timeline = combined_timeline(bundles)
    print(f"[info] correlation complete ({time.time() - t3:.1f}s elapsed)")

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
                "reason_count": b["reason_count"],
                "reasons_truncated": b["reasons_truncated"],
                "related_event_count": b["related_event_count"],
                "related_events_truncated": b["related_events_truncated"],
                "related_events_stats": b.get("related_events_stats"),
                "known_actor": b["known_actor"],
                "actor_history": b["actor_history"],
                "threat_intel": b.get("threat_intel"),
            }
            for b in bundles
        ],
        "timeline": timeline,
    }

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, default=_json_default, separators=(",", ":"))

    print(f"[info] wrote combined report: {out_path}")
    print(f"[info] running actor list now has {len(db.all_actors())} entries in {db_path}")
    print(f"[info] total run time: {time.time() - t0:.1f}s")

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
