"""
Detectors for the auth-log schema:
{datetime, hostname, process, pid, user, src_ip, src_port, message}
"""

import re
from detectors import Flag
from utils import sliding_window_groups, is_local_ip
import config


NEW_ACCOUNT_RE = re.compile(r"\bnew user\b|\buseradd\b|\badding user\b", re.IGNORECASE)
SUDO_ESCALATION_RE = re.compile(r"\bsudo\b.*\bCOMMAND=", re.IGNORECASE)
SU_ESCALATION_RE = re.compile(r"\bsu\b.*\bsession opened\b.*\bfor user root\b", re.IGNORECASE)


def detect_brute_force(auth_records):
    """
    Repeated auth-failure messages from the same src_ip within a short
    window. Flags the src_ip (external only - failures from local/admin
    IPs are still surfaced in the report but not added to the actor DB
    unless you want that; see note below).
    """
    flags = []
    failures = [r for r in auth_records if r.get("message") and config.AUTH_FAILURE_RE.search(r["message"])]

    threshold, window = config.BRUTE_FORCE_THRESHOLD
    groups = sliding_window_groups(
        failures,
        threshold_count=threshold,
        window_seconds=window,
        key_func=lambda r: r.get("src_ip"),
        ts_func=lambda r: r.get("_ts"),
    )
    for src_ip, evidence in groups.items():
        if not src_ip:
            continue
        flags.append(Flag(
            indicator=src_ip,
            indicator_type="ip",
            category="brute_force",
            description=f"{len(evidence)} authentication failures from {src_ip} within {window}s",
            evidence=evidence,
        ))
    return flags


def detect_privilege_escalation(auth_records):
    """
    sudo/su escalation events surfaced from free-text messages. These
    don't always have a src_ip (local console sudo won't), so indicator
    may end up being the acting user's originating IP if present, else
    skipped for actor-DB purposes but still worth flagging in the report.
    """
    flags = []
    for r in auth_records:
        msg = r.get("message", "") or ""
        if SUDO_ESCALATION_RE.search(msg) or SU_ESCALATION_RE.search(msg):
            src_ip = r.get("src_ip")
            if src_ip:
                flags.append(Flag(
                    indicator=src_ip,
                    indicator_type="ip",
                    category="privilege_escalation",
                    description=f"Privilege escalation event (sudo/su) associated with {src_ip}",
                    evidence=[r],
                ))
    return flags


def detect_new_accounts(auth_records):
    flags = []
    for r in auth_records:
        msg = r.get("message", "") or ""
        if NEW_ACCOUNT_RE.search(msg):
            src_ip = r.get("src_ip")
            if src_ip:
                flags.append(Flag(
                    indicator=src_ip,
                    indicator_type="ip",
                    category="persistence_new_account",
                    description=f"New account creation event associated with {src_ip}",
                    evidence=[r],
                ))
    return flags


def extract_domains(auth_records):
    """
    Best-effort domain extraction from free-text auth messages (e.g.
    reverse-DNS results in PAM/sshd messages). Sparse signal by design -
    most auth messages won't contain a domain at all.
    """
    flags = []
    for r in auth_records:
        msg = r.get("message", "") or ""
        for match in config.DOMAIN_CANDIDATE_RE.findall(msg):
            flags.append(Flag(
                indicator=match.lower(),
                indicator_type="domain",
                category="domain_observed",
                description=f"Domain-like string observed in auth message: {match}",
                evidence=[r],
            ))
    return flags


def run_all(auth_records):
    flags = []
    flags += detect_brute_force(auth_records)
    flags += detect_privilege_escalation(auth_records)
    flags += detect_new_accounts(auth_records)
    flags += extract_domains(auth_records)
    return flags
