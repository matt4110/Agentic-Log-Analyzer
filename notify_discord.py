#!/usr/bin/env python3
"""
notify_discord.py - send the daily IOC run result to a Discord webhook.

Called by run_daily.sh in two modes:

  success:  notify_discord.py success --report <daily_report.md>
  failure:  notify_discord.py failure --step "<step name>" --logfile <run.log>

The success message is built from the VALIDATED FINDINGS JSON that
llm_analyze.py embeds at the bottom of the report (inside an HTML comment),
NOT from the LLM's prose - so the headline counts are deterministic and
can't be hallucinated. The full markdown report is attached as a file, since
it will usually exceed Discord's 2000-char message limit.

The webhook URL comes from the DISCORD_WEBHOOK_URL environment variable
(set it in the cron entry or a sourced env file - do NOT hardcode it here,
a webhook URL is a credential).
"""

import argparse
import json
import os
import re
import sys
import urllib.request


FINDINGS_RE = re.compile(r"<!--\s*validated_findings_json\s*(\{.*?\})\s*-->", re.DOTALL)

SEVERITY_ORDER = ["critical", "high", "medium", "low"]
SEVERITY_EMOJI = {
    "critical": "\U0001F534",  # red circle
    "high": "\U0001F7E0",      # orange circle
    "medium": "\U0001F7E1",    # yellow circle
    "low": "\U0001F7E2",       # green circle
}


def _post(webhook, payload=None, files=None):
    """POST to the Discord webhook. If files given, send multipart; else JSON."""
    if files:
        # multipart/form-data with a file attachment + JSON payload
        boundary = "----ioc-hunter-boundary"
        body = b""
        if payload is not None:
            body += (f"--{boundary}\r\n"
                     f'Content-Disposition: form-data; name="payload_json"\r\n'
                     f"Content-Type: application/json\r\n\r\n"
                     f"{json.dumps(payload)}\r\n").encode()
        for i, (fname, fcontent) in enumerate(files):
            body += (f"--{boundary}\r\n"
                     f'Content-Disposition: form-data; name="file{i}"; filename="{fname}"\r\n'
                     f"Content-Type: text/markdown\r\n\r\n").encode()
            body += fcontent
            body += b"\r\n"
        body += f"--{boundary}--\r\n".encode()
        headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
        req = urllib.request.Request(webhook, data=body, headers=headers)
    else:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(webhook, data=data,
                                     headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.status


def _extract_findings(report_text):
    """Pull the validated-findings JSON out of the report's HTML comment.
    Returns (findings_list, dropped_list) or (None, None) if not present."""
    m = FINDINGS_RE.search(report_text)
    if not m:
        return None, None
    try:
        obj = json.loads(m.group(1))
        return obj.get("findings", []), obj.get("dropped_indicators", [])
    except json.JSONDecodeError:
        return None, None


def _summarize(findings):
    """Count findings by severity, return an ordered summary string."""
    counts = {}
    for f in findings:
        sev = (f.get("severity") or "unknown").lower()
        counts[sev] = counts.get(sev, 0) + 1
    parts = []
    for sev in SEVERITY_ORDER:
        if counts.get(sev):
            parts.append(f"{SEVERITY_EMOJI.get(sev,'')} {counts[sev]} {sev}")
    # any severities not in the standard order
    for sev, n in counts.items():
        if sev not in SEVERITY_ORDER:
            parts.append(f"{n} {sev}")
    return parts, counts


def _top_findings(findings, limit=5):
    """Highest-severity findings first, as short bullet lines for the message."""
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    ordered = sorted(findings, key=lambda f: rank.get((f.get("severity") or "").lower(), 99))
    lines = []
    for f in ordered[:limit]:
        sev = (f.get("severity") or "?").lower()
        emoji = SEVERITY_EMOJI.get(sev, "")
        ind = f.get("indicator", "?")
        summ = (f.get("summary") or "").strip()
        if len(summ) > 180:
            summ = summ[:177] + "..."
        lines.append(f"{emoji} **{ind}** — {summ}")
    return lines


def notify_success(webhook, report_path, run_date):
    try:
        with open(report_path, "r", encoding="utf-8") as f:
            report_text = f.read()
    except FileNotFoundError:
        # the run "succeeded" but no report file exists - treat as degraded
        content = (f"\u26A0\uFE0F **IOC run {run_date}**: completed but no report "
                   f"file found at `{report_path}`.")
        _post(webhook, {"content": content})
        return

    findings, dropped = _extract_findings(report_text)

    if findings is None:
        # report exists but has no findings block - the analysis likely failed
        # to produce structured output. Flag it rather than implying all-clear.
        content = (f"\u26A0\uFE0F **IOC run {run_date}**: report generated but no "
                   f"validated findings block was found. The LLM analysis step may "
                   f"have degraded - review the attached report manually.")
        header = {"content": content}
    else:
        parts, counts = _summarize(findings)
        total = len(findings)
        if total == 0:
            headline = f"\u2705 **IOC run {run_date}** — no high-signal findings today."
        else:
            headline = (f"**IOC run {run_date}** — {total} finding(s): "
                        + " · ".join(parts))
        body_lines = [headline]
        if findings:
            body_lines.append("")
            body_lines.extend(_top_findings(findings))
            if total > 5:
                body_lines.append(f"...and {total - 5} more (see attached report).")
        if dropped:
            body_lines.append("")
            body_lines.append(f"\u26A0\uFE0F {len(dropped)} indicator(s) could not be "
                              f"analyzed and were dropped - pipeline partially degraded.")
        content = "\n".join(body_lines)
        # Discord hard-caps message content at 2000 chars
        if len(content) > 1900:
            content = content[:1900] + "\n...(truncated, see attached report)"
        header = {"content": content}

    # attach the full markdown report
    fname = os.path.basename(report_path)
    _post(webhook, payload=header,
          files=[(fname, report_text.encode("utf-8"))])


def notify_failure(webhook, step, logfile, run_date):
    tail = ""
    if logfile and os.path.exists(logfile):
        try:
            with open(logfile, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
            tail = "".join(lines[-25:])
        except OSError:
            tail = "(could not read log file)"
    content = (f"\U0001F6A8 **IOC run {run_date} FAILED** at step: **{step}**\n"
               f"The pipeline stopped and did not produce a report. "
               f"A failed run is NOT an all-clear - investigate.\n")
    if tail:
        # keep the code block within the 2000-char limit
        snippet = tail[-1400:]
        content += f"```\n{snippet}\n```"
    _post(webhook, {"content": content})


def main():
    p = argparse.ArgumentParser(description="Send daily IOC result to Discord")
    sub = p.add_subparsers(dest="mode", required=True)

    ps = sub.add_parser("success")
    ps.add_argument("--report", required=True)
    ps.add_argument("--date", default="")

    pf = sub.add_parser("failure")
    pf.add_argument("--step", required=True)
    pf.add_argument("--logfile", default="")
    pf.add_argument("--date", default="")

    args = p.parse_args()

    webhook = os.environ.get("DISCORD_WEBHOOK_URL", "").strip()
    if not webhook:
        print("[notify] DISCORD_WEBHOOK_URL not set; skipping Discord notification",
              file=sys.stderr)
        # exit 0 so a missing webhook never fails the whole run
        sys.exit(0)

    try:
        if args.mode == "success":
            notify_success(webhook, args.report, args.date)
        else:
            notify_failure(webhook, args.step, args.logfile, args.date)
    except Exception as e:  # never let a notification problem crash the pipeline
        print(f"[notify] failed to send Discord notification: {e}", file=sys.stderr)
        sys.exit(0)


if __name__ == "__main__":
    main()
