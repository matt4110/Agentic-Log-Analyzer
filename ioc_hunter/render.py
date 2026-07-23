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
import re


# Matches control chars and raw hex-escape sequences that show up when the
# WAF logs non-HTTP traffic (TLS handshakes, port scans) as if it were a
# request. This binary garbage in a prompt can send a small reasoning model
# into non-terminating loops, so we scrub it before rendering.
_HEX_ESCAPE_RE = re.compile(r"(?:\\x[0-9A-Fa-f]{2})+")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


def _sanitize(value, max_len=300):
    """
    Make a field safe and compact for an LLM prompt: collapse runs of hex
    escapes to a marker, strip control characters, and truncate very long
    values (obfuscated attack payloads can be enormous). Returns a short,
    printable string.
    """
    if value is None:
        return ""
    s = str(value)
    # collapse hex-escape runs (e.g. \x16\x03\x01...) to a compact marker
    s = _HEX_ESCAPE_RE.sub("<binary>", s)
    # drop any remaining raw control bytes
    s = _CONTROL_RE.sub("", s)
    if len(s) > max_len:
        s = s[:max_len] + "...<truncated>"
    return s


def _is_binary_noise(rec):
    """
    True if a WAF record is clearly non-HTTP garbage (TLS handshake bytes,
    malformed method) rather than a real request. These carry no analytical
    value and destabilize the model, so they're dropped from rendering.
    """
    if rec.get("_source") != "waf":
        return False
    method = str(rec.get("method") or "")
    path = str(rec.get("req_path") or "")
    # real HTTP methods are short and alphabetic
    if method and not re.fullmatch(r"[A-Z]{3,10}", method):
        return True
    if "\\x" in method or "\\x" in path[:20]:
        return True
    return False


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
                f"| {_sanitize(rec.get('message',''))}".rstrip())

    if src == "auditd":
        parts = [f"{_t(rec)} auditd {rec.get('type','?')}"]
        if rec.get("exe"): parts.append(f"exe={_sanitize(rec['exe'], 120)}")
        if rec.get("acct"): parts.append(f"acct={_sanitize(rec['acct'], 60)}")
        if rec.get("op"): parts.append(f"op={rec['op']}")
        if rec.get("uid") is not None: parts.append(f"uid={rec['uid']}")
        if rec.get("auid") is not None: parts.append(f"auid={rec['auid']}")
        if rec.get("res"): parts.append(f"res={rec['res']}")
        if rec.get("src_ip"): parts.append(f"src={rec['src_ip']}")
        return " ".join(parts)

    if src == "auditd_merged":
        parts = [f"{_t(rec)} auditd_exec"]
        if rec.get("exe"): parts.append(f"exe={_sanitize(rec['exe'], 120)}")
        if rec.get("cmdline"): parts.append(f"cmd=[{_sanitize(rec['cmdline'])}]")
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
        return (f"{_t(rec)} waf {_sanitize(rec.get('method','?'), 10)} "
                f"{rec.get('src_ip','?')} \"{_sanitize(rec.get('req_path',''))}\" "
                f"{rec.get('response','?')} {rec.get('size','?')}b "
                f"ua=\"{_sanitize(rec.get('user_agent',''), 120)}\"".rstrip())

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
    if bundle.get("is_admin_source"):
        lines.append("NOTE: this indicator is on the ADMIN ALLOWLIST (known "
                     "authorized source). Activity here is expected admin work "
                     "unless it is clearly inconsistent with normal admin behavior.")
    lines.append(render_history(bundle.get("actor_history")))
    ti = bundle.get("threat_intel")
    if ti and ti.get("summary"):
        risk = ti.get("risk", "unknown")
        marker = "\u26A0\uFE0F " if risk == "flagged-malicious" else ""
        lines.append(f"threat intel [{risk}]: {marker}{ti['summary']}")
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
    # drop binary/non-HTTP garbage events (TLS handshakes logged as requests)
    clean_events = [ev for ev in events if not _is_binary_noise(ev)]
    dropped_noise = len(events) - len(clean_events)

    ec = bundle.get("related_event_count", len(events))
    ehdr = f"correlated events ({ec} total"
    if bundle.get("related_events_truncated"):
        ehdr += f", showing {len(clean_events)}"
    elif dropped_noise:
        ehdr += f", showing {len(clean_events)} ({dropped_noise} binary/non-HTTP events omitted)"
    ehdr += "):"
    lines.append(ehdr)
    for ev in clean_events:
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
