"""
Render log records and bundles as compact, LLM-friendly text instead of
verbose JSON. A 20B local model reads "12:00:03 ufw BLOCK 1.2.3.4:5000 ->
10.0.0.5:22/TCP SYN" far more easily than the equivalent 18-key JSON object,
and it costs ~4-6x fewer tokens - which on CPU inference is the difference
between a chunk taking seconds vs minutes of prompt processing.

Fields with no analytical value to an LLM (mac, tos, ttl, ip_flags,
total_len, in_iface, _line) are dropped entirely.
"""

import config


def _t(rec):
    """Short timestamp: drop date when it's obvious from context, keep time."""
    ts = rec.get("datetime") or ""
    # keep full ISO but trim microseconds/timezone noise for readability
    return str(ts).replace("T", " ")[:19]


def render_event(rec):
    """One line per record, formatted per source type."""
    src = rec.get("_source", "?")

    if src == "ufw":
        out = "->OUT " if rec.get("out_iface") else ""
        return (f"{_t(rec)} ufw {rec.get('action','?')} {out}"
                f"{rec.get('src_ip','?')}:{rec.get('src_port','?')} -> "
                f"{rec.get('dst_ip','?')}:{rec.get('dst_port','?')}/"
                f"{rec.get('protocol','?')} {rec.get('tcp_flags') or ''}".rstrip())

    if src == "auth":
        return (f"{_t(rec)} auth {rec.get('process','?')} "
                f"user={rec.get('user','?')} src={rec.get('src_ip','?')} "
                f"| {rec.get('message','')}".rstrip())

    if src == "auditd":
        parts = [f"{_t(rec)} auditd {rec.get('type','?')}"]
        if rec.get("exe"): parts.append(f"exe={rec['exe']}")
        if rec.get("acct"): parts.append(f"acct={rec['acct']}")
        if rec.get("op"): parts.append(f"op={rec['op']}")
        if rec.get("uid") is not None: parts.append(f"uid={rec['uid']}")
        if rec.get("auid") is not None: parts.append(f"auid={rec['auid']}")
        if rec.get("res"): parts.append(f"res={rec['res']}")
        if rec.get("src_ip"): parts.append(f"src={rec['src_ip']}")
        return " ".join(parts)

    if src == "auditd_merged":
        parts = [f"{_t(rec)} auditd_exec"]
        if rec.get("exe"): parts.append(f"exe={rec['exe']}")
        if rec.get("cmdline"): parts.append(f"cmd=[{rec['cmdline']}]")
        if rec.get("uid") is not None: parts.append(f"uid={rec['uid']}")
        if rec.get("src_ip"):
            tag = rec["src_ip"]
            if rec.get("src_ip_backfilled"):
                tag += "(backfilled"
                if rec.get("src_ip_ses_reuse_ambiguous"):
                    tag += ",AMBIGUOUS"
                tag += ")"
            parts.append(f"src={tag}")
        return " ".join(parts)

    if src == "waf":
        return (f"{_t(rec)} waf {rec.get('method','?')} "
                f"{rec.get('src_ip','?')} \"{rec.get('req_path','')}\" "
                f"{rec.get('response','?')} {rec.get('size','?')}b "
                f"ua=\"{rec.get('user_agent','')}\"".rstrip())

    # unknown source - fall back to key=value
    skip = {"_source", "_ts", "_line", "mac", "tos", "ttl", "ip_flags", "total_len"}
    return f"{_t(rec)} {src} " + " ".join(
        f"{k}={v}" for k, v in rec.items() if k not in skip and v is not None
    )


def render_history(h):
    """One-line actor history summary, or a 'first seen' note."""
    if h is None:
        return "NEW ACTOR (never flagged before)"
    cats = ",".join(h.get("historical_categories", []))
    return (f"KNOWN ACTOR: seen {h.get('days_seen','?')} prior day(s), "
            f"first {str(h.get('first_seen',''))[:10]}, "
            f"last {str(h.get('last_seen',''))[:10]}, "
            f"prior categories: {cats or 'none'}")


def render_bundle(bundle):
    """
    Full text rendering of one high-signal indicator bundle: header +
    history + why-flagged + evidence events, all as compact lines.
    """
    lines = []
    lines.append(f"### INDICATOR: {bundle['indicator']} ({bundle['type']})")
    lines.append(render_history(bundle.get("actor_history")))
    lines.append(f"categories: {', '.join(bundle.get('categories', []))}")

    rc = bundle.get("reason_count")
    reasons = bundle.get("reasons", [])
    hdr = f"why flagged ({rc} total triggering events" if rc else "why flagged"
    if bundle.get("reasons_truncated"):
        hdr += f", showing {len(reasons)}"
    hdr += "):"
    lines.append(hdr)
    for r in reasons:
        lines.append(f"  - {r}")

    events = bundle.get("events", [])
    ec = bundle.get("related_event_count", len(events))
    ehdr = f"correlated events ({ec} total"
    if bundle.get("related_events_truncated"):
        ehdr += f", showing {len(events)}"
    ehdr += "):"
    lines.append(ehdr)
    for ev in events:
        lines.append(f"  {render_event(ev)}")

    return "\n".join(lines)


def render_low_signal_row(bundle):
    """
    One compact row for the aggregate low-signal table - no per-event
    detail, just the stats that distinguish noise from something worth a
    second look. Network categories (port scans, blocked connections) show
    port/destination spread; auth-based categories (brute force) show
    failure volume instead, since ports/dsts are meaningless there.
    """
    stats = bundle.get("related_events_stats") or {}
    h = bundle.get("actor_history")
    known = "KNOWN" if bundle.get("known_actor") else "new"
    cats = ",".join(bundle.get("categories", []))
    time_range = f"{str(stats.get('first_seen',''))[11:19]}-{str(stats.get('last_seen',''))[11:19]}"
    actor = known + (f" ({h.get('days_seen')}d)" if h else "")

    network_cats = {"port_scan", "repeated_blocked_connections", "unusual_outbound"}
    is_network = bool(set(bundle.get("categories", [])) & network_cats)

    if is_network:
        return (f"{bundle['indicator']} | {cats} | "
                f"{bundle.get('related_event_count','?')} events | "
                f"{stats.get('distinct_dst_ports','?')} ports | "
                f"{stats.get('distinct_dst_ips','?')} dsts | "
                f"{time_range} | {actor}")
    else:
        return (f"{bundle['indicator']} | {cats} | "
                f"{bundle.get('related_event_count','?')} events | "
                f"{time_range} | {actor}")
