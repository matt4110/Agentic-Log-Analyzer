#!/usr/bin/env python3
"""
Split a large ioc_report_*.json into LLM-sized pieces for local analysis.

Two things happen here, both tuned for a small locally-hosted model:

  1. Signal routing. Indicators whose categories are ENTIRELY low-signal
     (port scans, blocked connections, new outbound - internet background
     noise) are NOT given per-indicator analysis. They go into one compact
     aggregate table the model scans for anomalies. Only high-signal
     indicators (SQLi, reverse shell, privesc, malware, exfil, etc.) get
     full per-bundle chunks. This stops a 20B model from dutifully writing
     "this is a port scan" 2,800 times and burning your inference budget.

  2. Compact text rendering (--format text, the default). Events are
     rendered as one line each instead of verbose JSON - ~4-6x fewer
     tokens, and easier for a small model to read. Use --format json to
     keep the original JSON bundle structure for archival/programmatic use.

Outputs, in the chunk directory:
  low_signal_table.txt   - aggregate table of all noise indicators
  chunk_0001.txt, ...    - high-signal bundles, packed under --max-bytes
  (or .json equivalents with --format json)

Usage:
    python3 chunk_report.py ioc_output/ioc_report_2026-07-07.json
    python3 chunk_report.py report.json --max-bytes 48000 --format text
"""

import argparse
import json
import os

import config
from render import render_bundle, render_low_signal_row


def _dumps(obj):
    return json.dumps(obj, default=str, separators=(",", ":"))


def build_bundles_from_report(report):
    """
    Rebuild one bundle per indicator from the report's deduplicated
    timeline. An event touching two indicators that land in different
    chunks appears in both - deliberate duplication so each chunk is
    self-contained.
    """
    indicator_meta = {f["indicator"]: f for f in report["flagged_indicators"]}
    events_by_indicator = {ind: [] for ind in indicator_meta}

    for entry in report.get("timeline", []):
        for tag in entry["indicators"]:
            indicator = tag.rsplit(" (", 1)[0]
            if indicator in events_by_indicator:
                events_by_indicator[indicator].append(entry["event"])

    bundles = []
    for indicator, meta in indicator_meta.items():
        b = dict(meta)
        b["events"] = events_by_indicator.get(indicator, [])
        bundles.append(b)
    return bundles


def is_low_signal(bundle):
    cats = set(bundle.get("categories", []))
    return bool(cats) and cats.issubset(config.LOW_SIGNAL_ONLY_CATEGORIES)


def _bundle_text(bundle):
    return render_bundle(bundle)


def pack_text_chunks(bundles, max_bytes):
    """Greedy pack rendered-text bundles under max_bytes, never splitting
    a bundle. Oversized single bundles get their own chunk."""
    rendered = [(b, _bundle_text(b)) for b in bundles]
    rendered.sort(key=lambda p: len(p[1]), reverse=True)

    chunks, current, current_size = [], [], 0
    SEP = "\n\n"
    for b, text in rendered:
        size = len(text) + len(SEP)
        if current and current_size + size > max_bytes:
            chunks.append(current)
            current, current_size = [], 0
        current.append((b, text))
        current_size += size
    if current:
        chunks.append(current)
    return chunks


def pack_json_chunks(bundles, max_bytes):
    OVERHEAD = 40
    bundles_sorted = sorted(bundles, key=lambda b: len(_dumps(b)), reverse=True)
    chunks, current, current_size = [], [], 0
    for b in bundles_sorted:
        size = len(_dumps(b)) + OVERHEAD
        if current and current_size + size > max_bytes:
            chunks.append(current)
            current, current_size = [], 0
        current.append(b)
        current_size += size
    if current:
        chunks.append(current)
    return chunks


def run(report_path, outdir, max_bytes, fmt):
    with open(report_path, "r", encoding="utf-8") as f:
        report = json.load(f)

    os.makedirs(outdir, exist_ok=True)
    bundles = build_bundles_from_report(report)

    high = [b for b in bundles if not is_low_signal(b)]
    low = [b for b in bundles if is_low_signal(b)]

    # --- low-signal aggregate table (always compact text) ---------------
    table_path = os.path.join(outdir, "low_signal_table.txt")
    with open(table_path, "w", encoding="utf-8") as f:
        f.write("# Low-signal indicators (presumed internet background noise).\n")
        f.write("# Scan for anomalies: unusually high port/dst counts, high event volume,\n")
        f.write("# known repeat actors, or activity clustered oddly in time.\n")
        f.write("# Network rows:  indicator | categories | events | distinct_ports | distinct_dsts | time_range | actor\n")
        f.write("# Auth rows:     indicator | categories | events | time_range | actor\n\n")
        for b in sorted(low, key=lambda x: x.get("related_event_count", 0), reverse=True):
            f.write(render_low_signal_row(b) + "\n")
    print(f"[info] wrote {table_path}: {len(low)} low-signal indicators, {os.path.getsize(table_path)} bytes")

    # --- high-signal per-bundle chunks ----------------------------------
    ext = "txt" if fmt == "text" else "json"
    if fmt == "text":
        chunks = pack_text_chunks(high, max_bytes)
        for i, chunk in enumerate(chunks, 1):
            path = os.path.join(outdir, f"chunk_{i:04d}.{ext}")
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n\n".join(text for _, text in chunk))
            size = os.path.getsize(path)
            note = " [OVERSIZED - single large bundle]" if size > max_bytes and len(chunk) == 1 else ""
            print(f"[info] wrote {path}: {len(chunk)} indicator(s), {size} bytes{note}")
    else:
        chunks = pack_json_chunks(high, max_bytes)
        for i, chunk in enumerate(chunks, 1):
            path = os.path.join(outdir, f"chunk_{i:04d}.{ext}")
            payload = {"indicators_in_chunk": [b["indicator"] for b in chunk], "bundles": chunk}
            with open(path, "w", encoding="utf-8") as f:
                f.write(_dumps(payload))
            size = os.path.getsize(path)
            note = " [OVERSIZED - single large bundle]" if size > max_bytes and len(chunk) == 1 else ""
            print(f"[info] wrote {path}: {len(chunk)} indicator(s), {size} bytes{note}")

    print(f"[info] {len(high)} high-signal indicators in {len(chunks)} chunk(s), "
          f"{len(low)} low-signal in 1 aggregate table (target {max_bytes} bytes/chunk, format={fmt})")


def main():
    p = argparse.ArgumentParser(description="Split an ioc_report into LLM-sized chunks with signal routing")
    p.add_argument("report", help="path to ioc_report_*.json")
    p.add_argument("--outdir", default=None, help="defaults to <report_dir>/chunks")
    p.add_argument("--max-bytes", type=int, default=config.CHUNK_MAX_BYTES_DEFAULT,
                   help=f"target max size per chunk (default {config.CHUNK_MAX_BYTES_DEFAULT}, sized for a local 20B model)")
    p.add_argument("--format", choices=["text", "json"], default="text",
                   help="text = compact one-line events for LLM (default); json = original structure for archival")
    args = p.parse_args()

    outdir = args.outdir or os.path.join(os.path.dirname(args.report) or ".", "chunks")
    run(args.report, outdir, args.max_bytes, args.format)


if __name__ == "__main__":
    main()
