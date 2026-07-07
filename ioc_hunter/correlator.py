"""
Given a set of flagged indicators, pull every record across all four log
sources that references that indicator (as src_ip or dst_ip for IPs; as a
substring match in free-text fields for domains), then combine everything
into one timeline sorted by datetime for LLM analysis.
"""

from utils import is_local_ip


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
        if itype == "ip":
            related = ip_index.get(indicator, [])
        else:
            related = [r for r in auth_records if _record_matches_domain(r, indicator)]

        related_sorted = sorted(
            related,
            key=lambda r: r.get("_ts") or r.get("datetime") or "",
        )
        entry["related_events"] = related_sorted
        entry["related_event_count"] = len(related_sorted)
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
