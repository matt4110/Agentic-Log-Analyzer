"""
Detectors for the auditd schema:
{datetime, hostname, type, audit_timestamp, audit_event_id, pid, uid, auid,
 ses, op, acct, exe, src_hostname, src_ip, terminal, res,
 uid_resolved, auid_resolved}

Caveat: this schema has no argv/command-line, so malware and reverse-shell
detection here is a coarse binary-name/path blocklist, not true behavioral
detection. Treat auditd-derived "malware" flags as lower-confidence leads.
"""

import os
from detectors import Flag
import config


def _basename(exe):
    if not exe:
        return None
    return os.path.basename(exe.strip())


def detect_privilege_escalation(auditd_records):
    """
    Flags anomalous root-privilege events, not routine sudo/login activity.
    A bare uid != auid mismatch is normal for nearly every login, cron job,
    and sudo call, so it isn't used alone. This looks for:

      A. Failed attempts to become/authenticate as root (brute-forcing sudo/su)
      B. A root-targeted PAM op (setcred/session_open/etc.) claimed by a
         binary that ISN'T a standard privilege tool (sudo/su/pkexec/doas)
      C. A process running as uid=0 with no traceable auid at all, from a
         binary that isn't a known system daemon - i.e. root with no audit
         trail behind it, a common signature of an exploited SUID binary

    These operate on raw auditd_records because PAM-generated records
    (login/session/auth events) reliably carry a direct src_ip. Case D -
    a direct setuid-family syscall landing at root - is handled separately
    in detect_setuid_escalation() against merged events instead, since bare
    SYSCALL records almost never carry src_ip directly and need the
    session-based backfill from audit_merge.py to be attributable at all.
    """
    flags = []
    for r in auditd_records:
        uid, auid = r.get("uid"), r.get("auid")
        acct = (r.get("acct") or "").lower()
        op = r.get("op") or ""
        res = (r.get("res") or "").lower()
        exe_base = _basename(r.get("exe"))
        exe_base_lower = (exe_base or "").lower()
        src_ip = r.get("src_ip")

        reason = None

        # A. failed root escalation/auth attempt
        if acct == "root" and res == "failed":
            reason = "failed attempt to authenticate/escalate as root"

        # B. root PAM op via a non-standard tool
        elif op in config.PRIVESC_OPS and acct == "root" and exe_base_lower not in config.KNOWN_PRIVESC_TOOLS:
            reason = f"root privilege operation ({op}) claimed by non-standard tool '{exe_base}'"

        # C. root with no traceable auid, from something other than a known daemon
        elif (
            str(uid) == "0"
            and str(auid) in ("-1", "4294967295", "unset", "None")
            and exe_base_lower not in config.KNOWN_SYSTEM_DAEMONS
            and exe_base_lower not in config.KNOWN_PRIVESC_TOOLS
        ):
            reason = f"process '{exe_base}' running as root with no traceable authenticated user (auid unset)"

        if reason and src_ip:
            flags.append(Flag(
                indicator=src_ip,
                indicator_type="ip",
                category="privilege_escalation",
                description=f"{reason} (src_ip {src_ip})",
                evidence=[r],
            ))
    return flags


def detect_setuid_escalation(merged_events):
    """
    Case D: a direct setuid-family syscall resulting in uid=0 from a binary
    that isn't a standard privilege tool or daemon. Runs against merged
    events (see audit_merge.py) so src_ip can come from the session-based
    backfill - bare SYSCALL records essentially never carry src_ip directly.
    """
    flags = []
    for ev in merged_events:
        syscall = ev.get("syscall")
        if syscall not in config.SETUID_SYSCALL_NUMBERS:
            continue
        exe_base = _basename(ev.get("exe"))
        exe_base_lower = (exe_base or "").lower()
        if exe_base_lower in config.KNOWN_PRIVESC_TOOLS or exe_base_lower in config.KNOWN_SYSTEM_DAEMONS:
            continue
        if str(ev.get("uid")) != "0":
            continue
        src_ip = ev.get("src_ip")
        if not src_ip:
            continue

        note = _attribution_note(ev)
        flags.append(Flag(
            indicator=src_ip,
            indicator_type="ip",
            category="privilege_escalation",
            description=(
                f"setuid-family syscall ({syscall}) resulted in root for unexpected "
                f"binary '{exe_base}' from {src_ip}{note}"
            ),
            evidence=[ev],
        ))
    return flags


def detect_malware_exe(auditd_records):
    flags = []
    for r in auditd_records:
        exe = r.get("exe")
        base = _basename(exe)
        src_ip = r.get("src_ip")
        if not exe:
            continue

        flagged_reason = None
        if base and base.lower() in config.MALWARE_EXE_BASENAMES:
            flagged_reason = f"blocklisted binary executed: {base}"
        elif any(exe.startswith(d) for d in config.SUSPICIOUS_EXE_DIRS):
            flagged_reason = f"binary executed from suspicious location: {exe}"

        if flagged_reason and src_ip:
            flags.append(Flag(
                indicator=src_ip,
                indicator_type="ip",
                category="malware",
                description=flagged_reason + f" (associated src_ip {src_ip})",
                evidence=[r],
            ))
    return flags


def detect_persistence(auditd_records):
    flags = []
    for r in auditd_records:
        exe_base = _basename(r.get("exe"))
        rtype = r.get("type")
        src_ip = r.get("src_ip")

        reason = None
        if rtype in config.PERSISTENCE_AUDIT_TYPES:
            reason = f"account-management event type={rtype}"
        elif exe_base and exe_base.lower() in config.PERSISTENCE_EXE_BASENAMES:
            reason = f"persistence-related binary executed: {exe_base}"

        if reason and src_ip:
            flags.append(Flag(
                indicator=src_ip,
                indicator_type="ip",
                category="persistence",
                description=reason + f" (associated src_ip {src_ip})",
                evidence=[r],
            ))
    return flags


def detect_reverse_shell_argv(merged_events):
    """
    Runs against merged SYSCALL+EXECVE events (see audit_merge.py), which
    is what makes this possible at all: raw exe alone (e.g. /bin/bash)
    tells you nothing, but the reconstructed argv/cmdline does.
    """
    flags = []
    for ev in merged_events:
        cmdline = ev.get("cmdline")
        if not cmdline:
            continue
        src_ip = ev.get("src_ip")
        if not src_ip:
            continue  # no attribution possible (no direct or ses-backfilled IP)

        matched_category = None
        if any(p.search(cmdline) for p in config.compiled("reverse_shell")):
            matched_category = "reverse_shell"
        elif any(p.search(cmdline) for p in config.compiled("suspicious_cmd")):
            matched_category = "suspicious_command"

        if matched_category:
            note = _attribution_note(ev)
            flags.append(Flag(
                indicator=src_ip,
                indicator_type="ip",
                category=matched_category,
                description=(
                    f"{matched_category.replace('_', ' ')} pattern in command line "
                    f"from {src_ip}: `{cmdline}`{note}"
                ),
                evidence=[ev],
            ))
    return flags


def _attribution_note(ev):
    """Human-readable caveat appended when src_ip came from ses-backfill
    rather than being directly recorded on the exec event itself."""
    if not ev.get("src_ip_backfilled"):
        return ""
    parts = [" [src_ip backfilled via session lookup"]
    if ev.get("src_ip_backfill_delta_seconds") is not None:
        parts.append(f", {ev['src_ip_backfill_delta_seconds']:.0f}s from nearest session record")
    if ev.get("src_ip_backfill_low_confidence"):
        parts.append(", LOW CONFIDENCE - large time gap")
    if ev.get("src_ip_ses_reuse_ambiguous"):
        parts.append(
            f", AMBIGUOUS - session id reused by multiple IPs: {ev.get('src_ip_ses_candidates')}"
        )
    parts.append("]")
    return "".join(parts)


def run_all(auditd_records, merged_events=None):
    flags = []
    flags += detect_privilege_escalation(auditd_records)
    flags += detect_malware_exe(auditd_records)
    flags += detect_persistence(auditd_records)
    if merged_events:
        flags += detect_reverse_shell_argv(merged_events)
        flags += detect_setuid_escalation(merged_events)
    return flags
