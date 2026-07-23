#!/usr/bin/env python3
"""
Feed chunked IOC data to a locally-hosted LLM (via Ollama's OpenAI-compatible
API) and produce a daily analyst report.

Design is map-reduce:
  MAP    - one call per high-signal chunk -> structured JSON findings
  REDUCE - one final call over all findings + the low-signal table summary
           -> the human-readable daily report

Guards, because a 20B local model needs them more than a frontier model:
  - Every indicator the model cites in a finding is validated against the
    actual indicators present in that chunk. Invented or mutated IPs are
    dropped and logged, never passed through to the final report.
  - Strict JSON schema expected from the MAP step; invalid output triggers
    a retry, then a skip (with the raw output saved for inspection) rather
    than crashing the run or silently losing the chunk.
  - Low temperature, explicit instructions against attribution/CVE/threat-
    actor-naming from vibes - small models confabulate those readily.

Usage:
    python3 llm_analyze.py ioc_output/chunks \\
        --out ioc_output/daily_report_2026-07-07.md
    python3 llm_analyze.py ioc_output/chunks --model gpt-oss:20b \\
        --base-url http://localhost:11434/v1
"""

import argparse
import glob
import json
import os
import re
import sys
import time
import urllib.request

import config


IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
INDICATOR_HEADER_RE = re.compile(r"^### INDICATOR:\s*(\S+)", re.MULTILINE)


# ---------------------------------------------------------------------------
# LLM transport (Ollama OpenAI-compatible endpoint)
# ---------------------------------------------------------------------------
def call_llm(base_url, model, messages, temperature, timeout, retries, force_json=False):
    """
    POST to /chat/completions with a full messages list. Returns the
    assistant message text, or raises after exhausting retries. No API key
    needed for local Ollama.

    Sends gpt-oss reasoning-model controls (num_predict, reasoning_effort).
    force_json enables Ollama's JSON-object mode - use for the MAP step
    (structured findings) but NOT the REDUCE step (which emits markdown).
    Falls back to the `reasoning` field if `content` comes back empty - a
    reasoning model that hits its token ceiling may leave the answer only
    in reasoning.
    """
    url = base_url.rstrip("/") + "/chat/completions"
    payload = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "stream": False,
        "max_tokens": config.LLM_NUM_PREDICT,   # OpenAI-compat name for num_predict
    }
    # gpt-oss reasoning-effort control (Ollama passes this through)
    if getattr(config, "LLM_REASONING_EFFORT", None):
        payload["reasoning_effort"] = config.LLM_REASONING_EFFORT
    # Ollama structured-output: constrain to valid JSON (MAP step only)
    if force_json and getattr(config, "LLM_FORCE_JSON", False):
        payload["response_format"] = {"type": "json_object"}

    data = json.dumps(payload).encode("utf-8")

    last_err = None
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                msg = body["choices"][0]["message"]
                content = msg.get("content") or ""
                # fallback: reasoning models sometimes leave the answer only
                # in the reasoning channel when content is empty/truncated
                if not content.strip():
                    content = msg.get("reasoning") or ""
                finish = body["choices"][0].get("finish_reason")
                if finish == "length":
                    print(f"[warn]   model hit token limit (finish_reason=length) - "
                          f"answer may be truncated; consider raising LLM_NUM_PREDICT or "
                          f"shrinking chunks")
                return content
        except Exception as e:  # noqa - transport errors are varied; we retry all
            last_err = e
            if attempt < retries:
                time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"LLM call failed after {retries + 1} attempts: {last_err}")


# ---------------------------------------------------------------------------
# MAP step
# ---------------------------------------------------------------------------
MAP_SYSTEM = (
    "You are a SOC analyst assistant reviewing correlated security log data for one "
    "or more flagged indicators. For EACH indicator, decide whether it warrants "
    "investigation and why, reasoning ONLY from the evidence shown. "
    "Rules you must follow:\n"
    "- Do NOT name specific threat actors, malware families, or CVE numbers unless "
    "that exact string appears in the evidence. Reason from behavior, not attribution.\n"
    "- Do NOT invent IP addresses, timestamps, or events not present in the input.\n"
    "- If evidence is thin or ambiguous, say so and rate confidence low.\n"
    "Respond with ONLY a JSON object, no markdown, no prose outside the JSON, in "
    "exactly this schema:\n"
    '{"findings":[{"indicator":"<ip or domain from the input>",'
    '"severity":"low|medium|high|critical",'
    '"confidence":"low|medium|high",'
    '"summary":"<2-3 sentence plain-English assessment>",'
    '"recommended_action":"<what a human should do next>"}]}'
)

MAP_FEWSHOT_USER = (
    "### INDICATOR: EXAMPLE_IP_DO_NOT_ECHO (ip)\n"
    "NEW ACTOR (never flagged before)\n"
    "categories: sql_injection, scanner_tool\n"
    "why flagged (2 total triggering events):\n"
    "  - [sql_injection] SQLi-pattern match in request path from EXAMPLE_IP_DO_NOT_ECHO\n"
    "  - [scanner_tool] Known scanner user agent from EXAMPLE_IP_DO_NOT_ECHO: 'sqlmap/1.6'\n"
    "correlated events (2 total):\n"
    "  2026-07-07 04:12:00 waf GET EXAMPLE_IP_DO_NOT_ECHO \"/p?id=1' UNION SELECT ...\" 200 900b ua=\"sqlmap/1.6\""
)

MAP_FEWSHOT_ASSISTANT = (
    '{"findings":[{"indicator":"EXAMPLE_IP_DO_NOT_ECHO","severity":"high","confidence":"high",'
    '"summary":"Automated SQL injection attempts using the sqlmap tool against a '
    'query parameter, returning HTTP 200 which suggests the endpoint processed the '
    'request. First time this source has been seen.",'
    '"recommended_action":"Confirm the endpoint is not vulnerable, review DB logs for '
    'this source, and consider blocking the IP at the WAF."}]}'
)


def extract_indicators_from_chunk(chunk_text):
    """The set of indicators legitimately present in a text chunk - used to
    validate the model didn't invent or mutate any."""
    return set(INDICATOR_HEADER_RE.findall(chunk_text))


def split_chunk_into_indicators(chunk_text):
    """
    Split a chunk's text back into individual indicator blocks, each starting
    at a '### INDICATOR:' header. Used for the per-indicator fallback when a
    packed chunk fails as a whole - we retry each indicator alone so only the
    actual offender (e.g. one that loops the model) is lost, not its
    chunk-mates. Returns a list of (indicator_id, block_text).
    """
    blocks = []
    # split keeping the delimiter by using a lookahead
    parts = re.split(r"(?=^### INDICATOR:)", chunk_text, flags=re.MULTILINE)
    for part in parts:
        part = part.strip()
        if not part.startswith("### INDICATOR:"):
            continue
        m = INDICATOR_HEADER_RE.search(part)
        if m:
            blocks.append((m.group(1), part))
    return blocks


def parse_map_output(raw):
    """Extract the JSON object from model output, tolerating stray prose or
    ```json fences that small models sometimes add despite instructions."""
    cleaned = raw.strip()
    # strip code fences if present
    cleaned = re.sub(r"^```(?:json)?", "", cleaned).strip()
    cleaned = re.sub(r"```$", "", cleaned).strip()
    # find the outermost JSON object
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("no JSON object found in output")
    return json.loads(cleaned[start:end + 1])


def analyze_chunk(chunk_text, args):
    valid_indicators = extract_indicators_from_chunk(chunk_text)
    # Proper conversation roles: system rules, a real user/assistant few-shot
    # exchange, then the actual data as a fresh user turn. This stops the
    # model reading the example as part of the task text (which produced
    # essay-style output when everything was crammed into one user message).
    messages = [
        {"role": "system", "content": MAP_SYSTEM},
        {"role": "user", "content": MAP_FEWSHOT_USER},
        {"role": "assistant", "content": MAP_FEWSHOT_ASSISTANT},
        {"role": "user", "content": chunk_text},
    ]
    raw = call_llm(args.base_url, args.model, messages,
                   args.temperature, args.timeout, args.retries, force_json=True)
    parsed = parse_map_output(raw)

    findings = parsed.get("findings", [])
    kept, dropped = [], []
    for f in findings:
        ind = f.get("indicator", "")
        if ind in valid_indicators:
            kept.append(f)
        else:
            dropped.append(ind)
    return kept, dropped, raw


# ---------------------------------------------------------------------------
# REPORT GENERATION - deterministic, built in Python from the validated
# findings. NOT written by the LLM.
#
# Rationale: an LLM asked to write a report over structured data will invent
# aggregate statistics, dates, and whole sections - it cannot reliably count,
# and it has no way to check itself. Observed failure: a run producing 47
# findings from ~2,800 records generated a report claiming "3,452,127 HTTP
# requests" and a date two years off, with severity tables unrelated to the
# actual findings.
#
# The division of labour that works: the LLM writes the per-finding SUMMARY
# (reading a request path and describing it in English - genuinely useful,
# and it did that accurately), while Python does every count, every grouping,
# every total, and the document structure. Nothing in this report exists that
# was not computed from the findings list.
# ---------------------------------------------------------------------------
SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def _sev_rank(f):
    return SEVERITY_ORDER.index(f.get("severity", "low").lower()) \
        if f.get("severity", "low").lower() in SEVERITY_ORDER else 99


def build_report(all_findings, low_signal_count, failed_indicators,
                 dropped_indicators, run_date, chunk_count):
    """Generate the daily markdown report deterministically from findings."""
    lines = []
    counts = {}
    for f in all_findings:
        sev = (f.get("severity") or "unknown").lower()
        counts[sev] = counts.get(sev, 0) + 1

    total = len(all_findings)
    lines.append(f"# Daily IOC Report — {run_date}")
    lines.append("")
    lines.append("*Counts and structure generated deterministically from validated "
                 "findings. Per-finding summaries were written by the analysis model "
                 "from the evidence in each bundle.*")
    lines.append("")

    # --- Summary (computed, not narrated) ---
    lines.append("## Summary")
    lines.append("")
    if total == 0:
        lines.append("No high-signal findings today.")
    else:
        sev_parts = [f"{counts[s]} {s}" for s in SEVERITY_ORDER if counts.get(s)]
        lines.append(f"- **Findings:** {total} ({', '.join(sev_parts)})")
        lines.append(f"- **Analyzed in:** {chunk_count} chunk(s)")
    lines.append(f"- **Low-signal indicators (background noise):** {low_signal_count}")
    if failed_indicators:
        lines.append(f"- **⚠️ Unanalyzed (pipeline degraded):** {len(failed_indicators)} "
                     f"— {', '.join(failed_indicators[:10])}")
    if dropped_indicators:
        lines.append(f"- **⚠️ Dropped (model cited indicators not in input):** "
                     f"{len(dropped_indicators)}")
    lines.append("")

    # --- Findings by severity ---
    ordered = sorted(all_findings, key=_sev_rank)
    for sev in SEVERITY_ORDER:
        group = [f for f in ordered if (f.get("severity") or "").lower() == sev]
        if not group:
            continue
        lines.append(f"## {sev.capitalize()} ({len(group)})")
        lines.append("")
        for f in group:
            ind = f.get("indicator", "?")
            conf = f.get("confidence", "?")
            lines.append(f"### {ind}")
            lines.append(f"*confidence: {conf}*")
            lines.append("")
            lines.append(f.get("summary", "").strip() or "_(no summary)_")
            action = (f.get("recommended_action") or "").strip()
            if action:
                lines.append("")
                lines.append(f"**Recommended action:** {action}")
            lines.append("")

    # --- Honest caveats, always present ---
    lines.append("---")
    lines.append("")
    lines.append("## Caveats")
    lines.append("")
    lines.append("- Severity and confidence values are the analysis model's judgement "
                 "of each bundle's evidence, not a calibrated score.")
    lines.append("- Indicators on the admin allowlist are routed to the low-signal "
                 "table; if an expected admin source is missing from that list, its "
                 "normal activity may appear here as a finding.")
    lines.append("- A finding means a detector matched and the evidence was reviewed. "
                 "It does not by itself mean an attack succeeded — check the response "
                 "codes and evidence in the linked chunk before acting.")
    if failed_indicators:
        lines.append("- **This run was partially degraded**: some indicators could not "
                     "be analyzed. A reduced finding count does NOT mean a quiet day.")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------
def _record_failure(blocks, chunk_text, chunk_dir, chunk_num, failed_indicators):
    """Record a chunk that failed and can't be split further (0 or 1
    indicator). Saves the text to llm_debug/ and notes the indicator id."""
    debug_dir = os.path.join(chunk_dir, "llm_debug")
    os.makedirs(debug_dir, exist_ok=True)
    if blocks:
        ind_id = blocks[0][0]
        failed_indicators.append(ind_id)
        safe = ind_id.replace("/", "_").replace(":", "_")
        fname = f"failed_{safe}.txt"
    else:
        failed_indicators.append(f"chunk_{chunk_num:04d}")
        fname = f"failed_chunk_{chunk_num:04d}.txt"
    with open(os.path.join(debug_dir, fname), "w") as f:
        f.write(chunk_text)


def run(chunk_dir, out_path, args):
    chunk_paths = sorted(glob.glob(os.path.join(chunk_dir, "chunk_*.txt")))
    if not chunk_paths:
        # fall back to json chunks if text wasn't generated
        json_chunks = sorted(glob.glob(os.path.join(chunk_dir, "chunk_*.json")))
        if json_chunks:
            print("[error] found JSON chunks but this analyzer expects text chunks.")
            print("        Re-run chunk_report.py with --format text (the default).")
            sys.exit(1)
        print(f"[warn] no chunks found in {chunk_dir}")

    low_table_path = os.path.join(chunk_dir, "low_signal_table.txt")
    low_signal_count = 0
    low_signal_note = "none"
    if os.path.exists(low_table_path):
        with open(low_table_path) as f:
            rows = [l for l in f if l.strip() and not l.startswith("#")]
        low_signal_count = len(rows)
        low_signal_note = (f"{low_signal_count} low-signal indicators (port scans / "
                           f"blocked connections / new outbound) treated as background noise")

    all_findings = []
    all_dropped = []
    debug_dir = os.path.join(chunk_dir, "llm_debug")

    print(f"[info] analyzing {len(chunk_paths)} high-signal chunk(s) with {args.model}...")
    failed_indicators = []
    for i, cp in enumerate(chunk_paths, 1):
        with open(cp) as f:
            chunk_text = f.read()
        t0 = time.time()
        try:
            kept, dropped, raw = analyze_chunk(chunk_text, args)
            all_findings.extend(kept)
            all_dropped.extend(dropped)
            msg = f"[info]   chunk {i}/{len(chunk_paths)}: {len(kept)} finding(s)"
            if dropped:
                msg += f", {len(dropped)} hallucinated indicator(s) dropped"
            msg += f" ({time.time() - t0:.0f}s)"
            print(msg)
        except Exception as e:
            # Option A: don't discard the whole chunk. Retry each indicator in
            # it individually so only the genuine offender (e.g. one that
            # loops the model) is lost - its chunk-mates still get analyzed.
            blocks = split_chunk_into_indicators(chunk_text)
            print(f"[warn]   chunk {i}/{len(chunk_paths)} failed as a whole ({e}); "
                  f"retrying its {len(blocks)} indicator(s) individually...")
            if len(blocks) <= 1:
                # nothing to isolate - a single indicator that fails is just lost
                _record_failure(blocks, chunk_text, chunk_dir, i, failed_indicators)
                continue
            for ind_id, block_text in blocks:
                t1 = time.time()
                try:
                    kept, dropped, raw = analyze_chunk(block_text, args)
                    all_findings.extend(kept)
                    all_dropped.extend(dropped)
                    print(f"[info]     - {ind_id}: {len(kept)} finding(s) ({time.time() - t1:.0f}s)")
                except Exception as e2:
                    print(f"[warn]     - {ind_id}: failed individually ({e2}) - skipped")
                    failed_indicators.append(ind_id)
                    os.makedirs(debug_dir, exist_ok=True)
                    safe = ind_id.replace("/", "_").replace(":", "_")
                    with open(os.path.join(debug_dir, f"failed_{safe}.txt"), "w") as f:
                        f.write(block_text)

    if failed_indicators:
        print(f"[warn] {len(failed_indicators)} indicator(s) could not be analyzed even "
              f"individually (saved to llm_debug/): {failed_indicators}")

    if all_dropped:
        print(f"[warn] dropped {len(all_dropped)} findings citing indicators not in their chunk: "
              f"{sorted(set(all_dropped))[:10]}{'...' if len(set(all_dropped)) > 10 else ''}")

    # Report is BUILT, not generated: every count and section comes from the
    # findings list. No LLM call here, so there is nothing to hallucinate and
    # nothing to fall back from.
    run_date = os.path.basename(out_path).replace("daily_report_", "").replace(".md", "")
    if not run_date or len(run_date) != 10:
        run_date = time.strftime("%Y-%m-%d", time.gmtime())
    print(f"[info] building report from {len(all_findings)} validated finding(s)...")
    report_md = build_report(
        all_findings,
        low_signal_count=low_signal_count,
        failed_indicators=failed_indicators,
        dropped_indicators=sorted(set(all_dropped)),
        run_date=run_date,
        chunk_count=len(chunk_paths),
    )

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(report_md)
        # always append the machine-readable findings for auditability
        f.write("\n\n<!-- validated_findings_json\n")
        f.write(json.dumps({"findings": all_findings,
                            "dropped_indicators": sorted(set(all_dropped)),
                            "failed_indicators": failed_indicators},
                           default=str))
        f.write("\n-->\n")

    print(f"[info] wrote {out_path}")


def main():
    p = argparse.ArgumentParser(description="Analyze chunked IOC data with a local LLM (Ollama)")
    p.add_argument("chunk_dir", help="directory of chunk_*.txt files from chunk_report.py")
    p.add_argument("--out", default=None, help="output report path (default <chunk_dir>/../daily_report.md)")
    p.add_argument("--base-url", default=config.LLM_BASE_URL)
    p.add_argument("--model", default=config.LLM_MODEL)
    p.add_argument("--temperature", type=float, default=config.LLM_TEMPERATURE)
    p.add_argument("--timeout", type=int, default=config.LLM_TIMEOUT_SECONDS)
    p.add_argument("--retries", type=int, default=config.LLM_MAX_RETRIES)
    args = p.parse_args()

    out_path = args.out or os.path.join(
        os.path.dirname(args.chunk_dir.rstrip("/")) or ".", "daily_report.md")
    run(args.chunk_dir, out_path, args)


if __name__ == "__main__":
    main()
