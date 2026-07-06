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
| Privilege escalation | auth, auditd | sudo/su messages; uid≠auid; PAM ops against root |
| Persistence (new accounts, cron, ssh-keygen, etc.) | auth, auditd | account-management event types + binary blocklist |
| Malware | auditd | `exe` blocklist (nc, ncat, nmap, hydra, etc.) + execution from /tmp,/dev/shm — **coarse**, no argv available in this schema |
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
