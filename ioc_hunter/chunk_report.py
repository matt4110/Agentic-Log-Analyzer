#!/usr/bin/env python3
"""
Split a large ioc_report_*.json into LLM-sized pieces without ever
splitting one flagged indicator's correlated events across two files -
that would defeat the point of correlating them in the first place.

Produces, in an output directory:
  summary.json          - every flagged indicator + reasons, NO raw events.
                           Small enough to always load in full; use it to
                           decide which detail chunk(s) are worth reading.
  chunk_0001.json, ...   - each holds one or more complete actor bundles
                           (indicator + all its related events across all
                           4 log sources), packed greedily up to --max-bytes.

Usage:
    python3 chunk_report.py ioc_output/ioc_report_2026-07-07.json \\
        --outdir ioc_output/chunks --max-bytes 300000
"""

import argparse
import json
import os


def _bundle_size(bundle):
    return len(_dumps(bundle))


def _dumps(obj):
    """Compact JSON - no indentation. This matters twice here: it makes
    the size estimate used for packing match what actually gets written
    (indent=2 was inflating real chunk sizes ~50-80% past what packing
    targeted), and it avoids burning LLM context tokens on whitespace
    that carries no information for machine consumption."""
    return json.dumps(obj, default=str, separators=(",", ":"))


def build_bundles_from_report(report):
    """
    The combined report's `timeline` is deduplicated across indicators (one
    event can be tagged with multiple indicators). Rebuild one bundle per
    indicator so each chunk can be self-contained; an event touching two
    indicators that land in different chunks will appear in both - a small,
    deliberate duplication in exchange for never truncating an actor's
    context.
    """
    indicator_meta = {f["indicator"]: f for f in report["flagged_indicators"]}
    events_by_indicator = {ind: [] for ind in indicator_meta}

    for entry in report["timeline"]:
        for tag in entry["indicators"]:
            # tag format is "1.2.3.4 (ip)" or "evil.com (domain)"
            indicator = tag.rsplit(" (", 1)[0]
            if indicator in events_by_indicator:
                events_by_indicator[indicator].append(entry["event"])

    bundles = []
    for indicator, meta in indicator_meta.items():
        bundles.append({
            "indicator": indicator,
            "type": meta["type"],
            "categories": meta["categories"],
            "reasons": meta["reasons"],
            "reason_count": meta.get("reason_count"),
            "reasons_truncated": meta.get("reasons_truncated"),
            "related_event_count": meta["related_event_count"],
            "related_events_truncated": meta.get("related_events_truncated"),
            "related_events_stats": meta.get("related_events_stats"),
            "events": events_by_indicator.get(indicator, []),
        })
    return bundles


def pack_chunks(bundles, max_bytes):
    """Greedy bin-packing: fill each chunk up to max_bytes, never split a
    single bundle. A bundle bigger than max_bytes on its own gets its own
    oversized chunk (rare - e.g. a very noisy single scanning IP) rather
    than being silently truncated.

    Includes a per-bundle overhead estimate for the `indicators_in_chunk`
    wrapper list the final file also carries - without it, chunks with
    many small bundles packed together consistently ran ~1-2% over
    max_bytes once that wrapper was added at write time.
    """
    OVERHEAD_PER_BUNDLE = 40  # covers the indicator string + JSON list punctuation in the wrapper
    bundles_sorted = sorted(bundles, key=_bundle_size, reverse=True)
    chunks = []
    current, current_size = [], 0

    for bundle in bundles_sorted:
        size = _bundle_size(bundle) + OVERHEAD_PER_BUNDLE
        if current and current_size + size > max_bytes:
            chunks.append(current)
            current, current_size = [], 0
        current.append(bundle)
        current_size += size

    if current:
        chunks.append(current)
    return chunks


def run(report_path, outdir, max_bytes):
    with open(report_path, "r", encoding="utf-8") as f:
        report = json.load(f)

    os.makedirs(outdir, exist_ok=True)

    summary = {
        "run_date": report.get("run_date"),
        "summary": report.get("summary"),
        "flagged_indicators": report.get("flagged_indicators"),
    }
    summary_path = os.path.join(outdir, "summary.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write(_dumps(summary))
    print(f"[info] wrote {summary_path} ({os.path.getsize(summary_path)} bytes)")

    bundles = build_bundles_from_report(report)
    chunks = pack_chunks(bundles, max_bytes)

    for i, chunk in enumerate(chunks, 1):
        chunk_path = os.path.join(outdir, f"chunk_{i:04d}.json")
        payload = {"indicators_in_chunk": [b["indicator"] for b in chunk], "bundles": chunk}
        with open(chunk_path, "w", encoding="utf-8") as f:
            f.write(_dumps(payload))
        size = os.path.getsize(chunk_path)
        if size > max_bytes:
            flag = " [OVERSIZED - single bundle larger than target]" if len(chunk) == 1 else " [OVERSIZED - unexpected, investigate]"
        else:
            flag = ""
        print(f"[info] wrote {chunk_path}: {len(chunk)} indicator(s), {size} bytes{flag}")

    print(f"[info] {len(bundles)} indicators packed into {len(chunks)} chunk(s) "
          f"(target max {max_bytes} bytes/chunk)")


def main():
    p = argparse.ArgumentParser(description="Split a large ioc_report JSON into LLM-sized chunks")
    p.add_argument("report", help="path to ioc_report_*.json")
    p.add_argument("--outdir", default=None, help="defaults to <report_dir>/chunks")
    p.add_argument("--max-bytes", type=int, default=300_000,
                    help="target max size per chunk file, in bytes (default 300000 ~ roughly 75-100k tokens)")
    args = p.parse_args()

    outdir = args.outdir or os.path.join(os.path.dirname(args.report) or ".", "chunks")
    run(args.report, outdir, args.max_bytes)


if __name__ == "__main__":
    main()
