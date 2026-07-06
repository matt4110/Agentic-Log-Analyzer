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
    flags = []
    for r in auditd_records:
        uid, auid = r.get("uid"), r.get("auid")
        acct = (r.get("acct") or "").lower()
        op = r.get("op") or ""
        src_ip = r.get("src_ip")

        suspicious = False
        reason = None

        if uid is not None and auid is not None and str(uid) != str(auid) and str(auid) not in ("-1", "4294967295", "unset"):
            suspicious = True
            reason = f"uid ({uid}) differs from auid ({auid})"

        if acct == "root" and auid and str(auid) not in ("0", "-1", "4294967295"):
            suspicious = True
            reason = f"root account action initiated by non-root auid ({auid})"

        if op in config.PRIVESC_OPS and acct == "root":
            suspicious = True
            reason = f"{op} for root account"

        if suspicious and src_ip:
            flags.append(Flag(
                indicator=src_ip,
                indicator_type="ip",
                category="privilege_escalation",
                description=f"Privilege escalation indicator: {reason} (src_ip {src_ip})",
                evidence=[r],
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


def run_all(auditd_records):
    flags = []
    flags += detect_privilege_escalation(auditd_records)
    flags += detect_malware_exe(auditd_records)
    flags += detect_persistence(auditd_records)
    return flags
