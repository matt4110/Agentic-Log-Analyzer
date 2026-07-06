"""
Detectors for the ufw schema:
{datetime, action, src_ip, src_port, dst_ip, dst_port, protocol, in_iface,
 out_iface, mac, total_len, tos, ttl, tcp_flags, ip_flags}
"""

from detectors import Flag
from utils import distinct_count_window, sliding_window_groups, is_local_ip
import config


def detect_port_scanning(ufw_records):
    threshold, window = config.PORT_SCAN_THRESHOLD
    groups = distinct_count_window(
        ufw_records,
        threshold_count=threshold,
        window_seconds=window,
        key_func=lambda r: r.get("src_ip"),
        ts_func=lambda r: r.get("_ts"),
        distinct_func=lambda r: r.get("dst_port"),
    )
    flags = []
    for src_ip, evidence in groups.items():
        if not src_ip:
            continue
        distinct_ports = {e.get("dst_port") for e in evidence if e.get("dst_port")}
        flags.append(Flag(
            indicator=src_ip,
            indicator_type="ip",
            category="port_scan",
            description=f"{src_ip} hit {len(distinct_ports)} distinct destination ports within {window}s",
            evidence=evidence,
        ))
    return flags


def detect_repeated_blocked_connections(ufw_records):
    """
    A single blocked packet is normal internet background noise. Repeated
    blocked attempts from the same src_ip in a short window is worth a
    look even if it's not a classic multi-port scan (e.g. hammering one
    closed port, or several attempts spread across few ports).
    """
    blocked = [r for r in ufw_records if (r.get("action") or "").upper() in ("BLOCK", "DENY", "DROP")]
    threshold, window = config.PORT_SCAN_THRESHOLD  # reuse same cadence
    groups = sliding_window_groups(
        blocked,
        threshold_count=threshold,
        window_seconds=window,
        key_func=lambda r: r.get("src_ip"),
        ts_func=lambda r: r.get("_ts"),
    )
    flags = []
    for src_ip, evidence in groups.items():
        if not src_ip:
            continue
        flags.append(Flag(
            indicator=src_ip,
            indicator_type="ip",
            category="repeated_blocked_connections",
            description=f"{len(evidence)} blocked connection attempts from {src_ip} within {window}s",
            evidence=evidence,
        ))
    return flags


def detect_unusual_outbound(ufw_records, actor_db, run_date=None):
    """
    Outbound traffic (out_iface populated, i.e. this host initiated the
    connection) to a destination never seen before in the persisted
    baseline. First-ever contact with a new external destination is
    flagged once, then remembered so it isn't repeatedly re-flagged on
    every subsequent day just because it's still in use.
    """
    flags = []
    for r in ufw_records:
        dst_ip = r.get("dst_ip")
        if not dst_ip or is_local_ip(dst_ip):
            continue
        if not r.get("out_iface"):
            continue  # not outbound-initiated traffic
        if actor_db.is_known_outbound(dst_ip):
            continue
        flags.append(Flag(
            indicator=dst_ip,
            indicator_type="ip",
            category="unusual_outbound",
            description=f"New outbound destination never seen before: {dst_ip}",
            evidence=[r],
        ))
        actor_db.record_outbound(dst_ip, run_date=run_date)
    return flags


def run_all(ufw_records, actor_db, run_date=None):
    flags = []
    flags += detect_port_scanning(ufw_records)
    flags += detect_repeated_blocked_connections(ufw_records)
    flags += detect_unusual_outbound(ufw_records, actor_db, run_date=run_date)
    return flags
