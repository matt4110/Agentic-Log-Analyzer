"""
Given a set of flagged indicators, pull every record across all four log
sources that references that indicator (as src_ip or dst_ip for IPs; as a
substring match in free-text fields for domains), then combine everything
into one timeline sorted by datetime for LLM analysis.
"""

from utils import is_local_ip
import config


IP_FIELDS_BY_SOURCE = {
    "auth": ["src_ip"],
    "auditd": ["src_ip"],
    "auditd_merged": ["src_ip"],
    "ufw": ["src_ip", "dst_ip"],
    "waf": ["src_ip"],
}


def _record_matches_domain(record, domain):
    # Domains only ever showed up in free-text auth messages in this
    # pipeline; extend here if other sources gain a domain field later.
    msg = (record.get("message") or "")
    return domain.lower() in msg.lower()


def _build_ip_index(flat_records):
    """
    One pass over every record, bucketed by every IP value it carries.
    Turns correlation from O(records x unique_indicators) into O(records)
    total - the difference between finishing in seconds and grinding for
    hours once you have thousands of flagged indicators.
    """
    index = {}
    for r in flat_records:
        source = r.get("_source")
        fields = IP_FIELDS_BY_SOURCE.get(source, [])
        seen_values = set()
        for f in fields:
            v = r.get(f)
            if v and v not in seen_values:
                index.setdefault(v, []).append(r)
                seen_values.add(v)
    return index


def _cap_reasons(reasons, cap):
    """
    Dedupe exact-duplicate reason strings (common when the same payload is
    retried many times), then cap to a first/last sample. Total count is
    preserved separately so nothing is silently hidden.
    """
    total = len(reasons)
    deduped = list(dict.fromkeys(reasons))  # order-preserving dedupe
    if len(deduped) <= cap:
        return deduped, total, len(deduped) < total
    head = cap // 2
    tail = cap - head
    capped = deduped[:head] + deduped[-tail:]
    return capped, total, True


def _sample_events(related_sorted, cap):
    """
    If under cap, return everything. Otherwise keep a first-half/last-half
    split so the sample still shows both when the activity started and
    what was most recent, rather than just truncating to the earliest N
    events and silently dropping everything after.
    """
    total = len(related_sorted)
    if total <= cap:
        return related_sorted, False
    head = cap // 2
    tail = cap - head
    sampled = related_sorted[:head] + related_sorted[-tail:]
    return sampled, True


def _aggregate_stats(related_sorted):
    """
    Cheap aggregate stats computed from the FULL related-event list before
    sampling, so low-signal bundles don't lose all analytical value just
    because we're not shipping every raw event. Distinct ports/destinations
    are what actually distinguish "one blocked probe" from "hammered 40
    different ports" - that signal shouldn't disappear just because we
    stopped including all 40 individual packets.
    """
    if not related_sorted:
        return {}
    first_ts = related_sorted[0].get("_ts") or related_sorted[0].get("datetime")
    last_ts = related_sorted[-1].get("_ts") or related_sorted[-1].get("datetime")
    distinct_dst_ports = {r.get("dst_port") for r in related_sorted if r.get("dst_port")}
    distinct_dst_ips = {r.get("dst_ip") for r in related_sorted if r.get("dst_ip")}
    return {
        "first_seen": str(first_ts) if first_ts else None,
        "last_seen": str(last_ts) if last_ts else None,
        "distinct_dst_ports": len(distinct_dst_ports),
        "distinct_dst_ips": len(distinct_dst_ips),
    }


def build_bundles(flags, all_records):
    """
    flags: list of detectors.Flag
    all_records: dict[source_name] -> list of records (from loaders.load_all)

    Returns: list of bundle dicts, one per unique (indicator, type):
        {
            "indicator": ..., "type": "ip"|"domain",
            "categories": [...],            # every detector category that fired
            "reasons": [...],               # human-readable description per flag
            "trigger_evidence": [...],      # the specific records that caused the flag(s)
            "related_events": [...]         # every record touching this indicator, all sources
        }
    """
    flat_records = [r for recs in all_records.values() for r in recs]
    ip_index = _build_ip_index(flat_records)
    # domains only ever show up in auth free-text messages - restrict the
    # (rare) substring scan to that subset instead of every record
    auth_records = all_records.get("auth", [])

    by_key = {}
    for flag in flags:
        key = (flag.indicator, flag.indicator_type)
        if key not in by_key:
            by_key[key] = {
                "indicator": flag.indicator,
                "type": flag.indicator_type,
                "categories": [],
                "reasons": [],
                "trigger_evidence": [],
            }
        entry = by_key[key]
        if flag.category not in entry["categories"]:
            entry["categories"].append(flag.category)
        entry["reasons"].append(f"[{flag.category}] {flag.description}")
        entry["trigger_evidence"].extend(flag.evidence)

    bundles = []
    for (indicator, itype), entry in by_key.items():
        raw_reason_count = len(entry["reasons"])
        capped_reasons, total_reasons, reasons_truncated = _cap_reasons(
            entry["reasons"], config.MAX_REASONS_PER_INDICATOR
        )
        entry["reasons"] = capped_reasons
        entry["reason_count"] = total_reasons  # true total, always uncapped
        entry["reasons_truncated"] = reasons_truncated
        if reasons_truncated:
            entry["reasons_note"] = (
                f"showing {len(capped_reasons)} of {total_reasons} triggering events "
                f"(deduped + first/last sample)"
            )

        if itype == "ip":
            related = ip_index.get(indicator, [])
        else:
            related = [r for r in auth_records if _record_matches_domain(r, indicator)]

        related_sorted = sorted(
            related,
            key=lambda r: r.get("_ts") or r.get("datetime") or "",
        )

        is_low_signal_only = bool(entry["categories"]) and set(entry["categories"]).issubset(config.LOW_SIGNAL_ONLY_CATEGORIES)
        cap = config.MAX_RELATED_EVENTS_LOW_SIGNAL if is_low_signal_only else config.MAX_RELATED_EVENTS_HIGH_SIGNAL
        sampled, truncated = _sample_events(related_sorted, cap)

        entry["related_events"] = sampled
        entry["related_event_count"] = len(related_sorted)  # TOTAL, not sample size
        entry["related_events_truncated"] = truncated
        if is_low_signal_only:
            entry["related_events_stats"] = _aggregate_stats(related_sorted)
        if truncated:
            entry["related_events_note"] = (
                f"showing {len(sampled)} of {len(related_sorted)} total related events "
                f"(first/last split - see related_event_count for the true total"
                + (", related_events_stats for aggregate detail)" if is_low_signal_only else ")")
            )
        bundles.append(entry)

    return bundles


def filter_local_flags(flags):
    """Drop flags whose indicator is a local/private IP - not useful as an
    external threat indicator, and shouldn't pollute the actor DB."""
    kept = []
    for f in flags:
        if f.indicator_type == "ip" and is_local_ip(f.indicator):
            continue
        kept.append(f)
    return kept


def combined_timeline(bundles):
    """
    Flatten every bundle's related events into one big list sorted by
    datetime, each event tagged with which indicator bundle(s) it belongs
    to, for the single combined output file the user asked for.
    """
    merged = {}
    for bundle in bundles:
        for event in bundle["related_events"]:
            eid = (event.get("_source"), event.get("_line"))
            if eid not in merged:
                merged[eid] = {
                    "indicators": [],
                    "categories": [],
                    "event": event,
                }
            entry = merged[eid]
            tag = f"{bundle['indicator']} ({bundle['type']})"
            if tag not in entry["indicators"]:
                entry["indicators"].append(tag)
            for cat in bundle["categories"]:
                if cat not in entry["categories"]:
                    entry["categories"].append(cat)

    timeline = list(merged.values())
    timeline.sort(key=lambda e: e["event"].get("_ts") or e["event"].get("datetime") or "")
    return timeline
