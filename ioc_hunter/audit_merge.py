"""
Kernel auditd records for a single exec() arrive as multiple lines sharing
one audit_event_id: SYSCALL carries exe/uid/auid/ses, EXECVE carries the
actual argv. Neither carries a src_ip - that only appears on session/login
records (PAM-generated), tagged with the same `ses` (session ID) but a
different audit_event_id.

This module does two joins:
  1. Group SYSCALL + EXECVE (+ any other same-ID records) by audit_event_id
     into one merged record with exe + argv + cmdline together.
  2. Backfill src_ip onto that merged record by looking up the nearest-in-time
     record that shares the same `ses` and does carry a src_ip.

Session-ID reuse is a real risk (ses values do get recycled), so the
backfill never silently guesses: if a `ses` maps to more than one distinct
src_ip across the day, the merged record is marked ambiguous and lists all
candidates instead of picking one quietly.
"""

from collections import defaultdict
import config


MERGEABLE_TYPES = {"SYSCALL", "EXECVE", "PATH", "CWD", "PROCTITLE"}


def _valid_ip(val):
    return val not in (None, "", "?", "unset", "(none)")


def build_ses_ip_map(auditd_records):
    """ses -> sorted list of (timestamp, src_ip) for records that carry both."""
    m = defaultdict(list)
    for r in auditd_records:
        ses = r.get("ses")
        ip = r.get("src_ip")
        ts = r.get("_ts")
        if ses in (None, "", "-1") or not _valid_ip(ip) or ts is None:
            continue
        m[ses].append((ts, ip))
    for ses in m:
        m[ses].sort(key=lambda p: p[0])
    return m


def _nearest_ip_for_ses(ses, ts, ses_ip_map):
    """
    Returns (src_ip, time_delta_seconds, ambiguous, candidates) for the
    closest-in-time src_ip recorded against this ses, or
    (None, None, False, []) if this ses has no known src_ip at all.
    """
    entries = ses_ip_map.get(ses)
    if not entries or ts is None:
        return None, None, False, []

    distinct_ips = {ip for _, ip in entries}
    ambiguous = len(distinct_ips) > 1

    best_ip, best_delta = None, None
    for entry_ts, ip in entries:
        delta = abs((entry_ts - ts).total_seconds())
        if best_delta is None or delta < best_delta:
            best_delta, best_ip = delta, ip

    return best_ip, best_delta, ambiguous, sorted(distinct_ips)


def merge_events(auditd_records, run_date=None):
    """
    Returns a list of merged synthetic records, one per audit_event_id
    group that contains at least one SYSCALL or EXECVE record. Each merged
    record is tagged _source="auditd_merged" so it flows through the
    existing correlator/timeline machinery like any other log source.
    """
    ses_ip_map = build_ses_ip_map(auditd_records)

    groups = defaultdict(list)
    for r in auditd_records:
        if r.get("type") in MERGEABLE_TYPES and r.get("audit_event_id"):
            groups[r["audit_event_id"]].append(r)

    merged = []
    for event_id, recs in groups.items():
        has_syscall_or_execve = any(r.get("type") in ("SYSCALL", "EXECVE") for r in recs)
        if not has_syscall_or_execve:
            continue

        syscall_rec = next((r for r in recs if r.get("type") == "SYSCALL"), None)
        execve_rec = next((r for r in recs if r.get("type") == "EXECVE"), None)

        exe = (syscall_rec or {}).get("exe")
        comm = (syscall_rec or {}).get("comm")
        pid = (syscall_rec or {}).get("pid")
        ppid = (syscall_rec or {}).get("ppid")
        uid = (syscall_rec or {}).get("uid")
        auid = (syscall_rec or {}).get("auid")
        ses = (syscall_rec or {}).get("ses")
        success = (syscall_rec or {}).get("success")
        syscall = (syscall_rec or {}).get("syscall")
        ts = (syscall_rec or {}).get("_ts") or (execve_rec or {}).get("_ts")

        argv = (execve_rec or {}).get("argv")
        cmdline = (execve_rec or {}).get("cmdline")

        # direct src_ip on any constituent record (rare for exec events,
        # but don't discard it if present)
        direct_ip = next((r.get("src_ip") for r in recs if _valid_ip(r.get("src_ip"))), None)

        src_ip = direct_ip
        backfilled = False
        ambiguous = False
        candidates = []
        backfill_delta = None
        low_confidence = False

        if not src_ip and ses:
            best_ip, delta, amb, cands = _nearest_ip_for_ses(ses, ts, ses_ip_map)
            if best_ip:
                src_ip = best_ip
                backfilled = True
                ambiguous = amb
                candidates = cands
                backfill_delta = delta
                if delta is not None and delta > config.SES_BACKFILL_LOW_CONFIDENCE_SECONDS:
                    low_confidence = True

        merged.append({
            "_source": "auditd_merged",
            "_ts": ts,
            "_line": event_id,
            "datetime": (syscall_rec or execve_rec or {}).get("datetime"),
            "audit_event_id": event_id,
            "exe": exe,
            "comm": comm,
            "argv": argv,
            "cmdline": cmdline,
            "pid": pid,
            "ppid": ppid,
            "uid": uid,
            "auid": auid,
            "ses": ses,
            "success": success,
            "syscall": syscall,
            "src_ip": src_ip,
            "src_ip_backfilled": backfilled,
            "src_ip_backfill_delta_seconds": backfill_delta,
            "src_ip_backfill_low_confidence": low_confidence,
            "src_ip_ses_reuse_ambiguous": ambiguous,
            "src_ip_ses_candidates": candidates if ambiguous else [],
            "_constituent_types": sorted({r.get("type") for r in recs}),
        })

    return merged
