"""
Shared helpers: timestamp parsing, local/private IP detection, sliding-window
velocity checks, and URL decoding for evasion-resistant matching.
"""

import ipaddress
import urllib.parse
from datetime import datetime, timezone
from dateutil import parser as dateparser


def parse_ts(raw):
    """
    Parse a timestamp field from any of the four log schemas into an
    aware (or naive, consistently) datetime. Returns None if unparseable
    so callers can skip/flag the record instead of crashing.
    """
    if raw is None:
        return None
    if isinstance(raw, (int, float)):
        try:
            return datetime.fromtimestamp(raw, tz=timezone.utc)
        except (ValueError, OSError, OverflowError):
            return None
    if isinstance(raw, str):
        try:
            return dateparser.parse(raw)
        except (ValueError, OverflowError):
            return None
    return None


def is_local_ip(ip_str):
    """
    True if the address is any flavor of local/private/reserved:
    RFC1918, loopback, link-local, multicast, unspecified - covers IPv4
    and IPv6. Anything that isn't cleanly "local" is treated as external.
    """
    if not ip_str:
        return True  # no address = nothing to flag as external
    try:
        ip = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return True  # not a real IP (hostname, empty, malformed) - don't treat as external IOC
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
    )


def double_decode(path):
    """Decode a URL path twice to catch single- and double-encoded payloads."""
    if not path:
        return ""
    try:
        once = urllib.parse.unquote(path)
        twice = urllib.parse.unquote(once)
        return twice
    except Exception:
        return path


def sliding_window_groups(events, threshold_count, window_seconds, key_func, ts_func):
    """
    Generic velocity detector.

    events: iterable of records
    key_func: record -> grouping key (e.g. src_ip)
    ts_func: record -> datetime
    Returns: dict[key] -> list of event-groups (each group is a list of
             records) where >= threshold_count events for that key occurred
             within any window_seconds span.
    """
    from collections import defaultdict

    grouped = defaultdict(list)
    for e in events:
        k = key_func(e)
        ts = ts_func(e)
        if k is None or ts is None:
            continue
        grouped[k].append((ts, e))

    results = {}
    for k, pairs in grouped.items():
        pairs.sort(key=lambda p: p[0])
        timestamps = [p[0] for p in pairs]
        n = len(pairs)
        left = 0
        flagged_group = None
        for right in range(n):
            while (timestamps[right] - timestamps[left]).total_seconds() > window_seconds:
                left += 1
            if right - left + 1 >= threshold_count:
                flagged_group = [p[1] for p in pairs[left:right + 1]]
                break
        if flagged_group:
            results[k] = flagged_group
    return results


def distinct_count_window(events, threshold_count, window_seconds, key_func, ts_func, distinct_func):
    """
    Like sliding_window_groups, but the threshold is on the count of
    *distinct* values of distinct_func within the window (e.g. distinct
    dst_port per src_ip) rather than raw event count. Used for port scans.
    """
    from collections import defaultdict

    grouped = defaultdict(list)
    for e in events:
        k = key_func(e)
        ts = ts_func(e)
        if k is None or ts is None:
            continue
        grouped[k].append((ts, e))

    results = {}
    for k, pairs in grouped.items():
        pairs.sort(key=lambda p: p[0])
        n = len(pairs)
        left = 0
        for right in range(n):
            while (pairs[right][0] - pairs[left][0]).total_seconds() > window_seconds:
                left += 1
            window_events = [p[1] for p in pairs[left:right + 1]]
            distinct_vals = {distinct_func(ev) for ev in window_events if distinct_func(ev) is not None}
            if len(distinct_vals) >= threshold_count:
                results[k] = window_events
                break
    return results
