#!/usr/bin/env python3
"""
Multi-provider threat-intel enrichment (Tier 1: read-only).

For each high-signal indicator, look up reputation across GreyNoise,
AbuseIPDB, and ThreatFox, cache the combined result in actors.db, and attach
a compact summary to the bundle so the LLM (and you) see reputation context
next to the evidence.

Design principles:
  - Read-only. No action is ever taken; this only annotates. (Tier 1 keeps
    the injection-vulnerable LLM out of any actuation path.)
  - Providers are independent. One being down/keyless/rate-limited never
    breaks the others or the run - it just contributes nothing.
  - Aggressive caching. Each indicator is looked up at most once per
    INTEL_CACHE_TTL_DAYS, which is what keeps usage under GreyNoise's tight
    weekly limit (repeat scanners are already cached from earlier runs).
  - Keys from env only. A provider with no key in the environment is silently
    skipped, so you can enable them one at a time as you make accounts.
  - Third-party responses are sanitized before they ever reach the LLM prompt.
"""

import json
import os
import re
import time
import urllib.request
import urllib.error
import urllib.parse

import config


# strip control chars / hex-escape runs from any third-party text before it
# reaches an LLM prompt (defense-in-depth even though this data isn't
# attacker-controlled the way logs are)
_CLEAN_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_HEX_RE = re.compile(r"(?:\\x[0-9A-Fa-f]{2})+")


def _clean(s, max_len=200):
    if s is None:
        return ""
    s = _HEX_RE.sub("", str(s))
    s = _CLEAN_RE.sub("", s)
    return s[:max_len]


def _http_json(url, headers=None, data=None, method=None, timeout=None):
    """Minimal JSON HTTP helper. Returns parsed dict or raises."""
    timeout = timeout or config.INTEL_REQUEST_TIMEOUT
    hdrs = {"User-Agent": "ioc-hunter-enrich/1.0"}
    if headers:
        hdrs.update(headers)
    body = None
    if data is not None:
        if isinstance(data, (dict, list)):
            body = json.dumps(data).encode()
            hdrs.setdefault("Content-Type", "application/json")
        else:
            body = data.encode() if isinstance(data, str) else data
    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


# ---------------------------------------------------------------------------
# Providers. Each returns a small normalized dict, or {"available": False,...}
# on any error so a single provider failure is contained.
# ---------------------------------------------------------------------------
def _greynoise(indicator, itype, key):
    # Community API: GET /v3/community/<ip>, header 'key'
    if itype != "ip":
        return {"available": False, "reason": "greynoise: IP-only"}
    try:
        url = f"https://api.greynoise.io/v3/community/{urllib.parse.quote(indicator)}"
        data = _http_json(url, headers={"key": key})
        # fields: noise, riot, classification, name, last_seen
        return {
            "available": True,
            "noise": data.get("noise"),
            "riot": data.get("riot"),
            "classification": _clean(data.get("classification"), 40),
            "name": _clean(data.get("name"), 80),
            "last_seen": _clean(data.get("last_seen"), 30),
        }
    except urllib.error.HTTPError as e:
        # 404 = IP simply not in GreyNoise's data (common, not an error state)
        if e.code == 404:
            return {"available": True, "seen": False}
        return {"available": False, "reason": f"greynoise HTTP {e.code}"}
    except Exception as e:
        return {"available": False, "reason": f"greynoise: {e}"}


def _abuseipdb(indicator, itype, key):
    if itype != "ip":
        return {"available": False, "reason": "abuseipdb: IP-only"}
    try:
        qs = urllib.parse.urlencode({"ipAddress": indicator, "maxAgeInDays": 90})
        url = f"https://api.abuseipdb.com/api/v2/check?{qs}"
        data = _http_json(url, headers={"Key": key, "Accept": "application/json"})
        d = data.get("data", {})
        return {
            "available": True,
            "abuse_confidence": d.get("abuseConfidenceScore"),
            "total_reports": d.get("totalReports"),
            "country": _clean(d.get("countryCode"), 8),
            "isp": _clean(d.get("isp"), 80),
            "domain": _clean(d.get("domain"), 80),
            "is_tor": d.get("isTor"),
            "usage_type": _clean(d.get("usageType"), 60),
        }
    except Exception as e:
        return {"available": False, "reason": f"abuseipdb: {e}"}


def _threatfox(indicator, itype, key):
    try:
        url = "https://threatfox-api.abuse.ch/api/v1/"
        headers = {"Auth-Key": key} if key else {}
        payload = {"query": "search_ioc", "search_term": indicator}
        data = _http_json(url, headers=headers, data=payload, method="POST")
        status = data.get("query_status")
        if status == "no_result":
            return {"available": True, "matched": False}
        if status == "ok":
            rows = data.get("data", []) or []
            first = rows[0] if rows else {}
            return {
                "available": True,
                "matched": True,
                "malware": _clean(first.get("malware_printable"), 80),
                "threat_type": _clean(first.get("threat_type"), 40),
                "confidence": first.get("confidence_level"),
                "first_seen": _clean(first.get("first_seen"), 30),
                "match_count": len(rows),
            }
        return {"available": False, "reason": f"threatfox: {status}"}
    except Exception as e:
        return {"available": False, "reason": f"threatfox: {e}"}


_PROVIDER_FUNCS = {
    "greynoise": _greynoise,
    "abuseipdb": _abuseipdb,
    "threatfox": _threatfox,
}


def _summarize(results):
    """Build a short, LLM-friendly one-line verdict from the provider results,
    plus a coarse risk hint. Deterministic - not an LLM judgement."""
    bits = []
    risk = "unknown"

    gn = results.get("greynoise", {})
    if gn.get("available"):
        if gn.get("seen") is False:
            pass  # not in greynoise, say nothing
        elif gn.get("classification"):
            cls = gn["classification"]
            tag = f"GreyNoise: {cls}"
            if gn.get("name"):
                tag += f" ({gn['name']})"
            if gn.get("riot"):
                tag += " [common business service]"
            bits.append(tag)
            if cls == "benign" or gn.get("riot"):
                risk = "likely-benign-noise"
            elif cls == "malicious":
                risk = "flagged-malicious"

    ab = results.get("abuseipdb", {})
    if ab.get("available") and ab.get("abuse_confidence") is not None:
        score = ab["abuse_confidence"]
        bits.append(f"AbuseIPDB: {score}% abuse confidence "
                    f"({ab.get('total_reports', 0)} reports, {ab.get('country','?')})")
        if score >= 75:
            risk = "flagged-malicious"
        elif score <= 10 and risk == "unknown":
            risk = "low-reputation-risk"

    tf = results.get("threatfox", {})
    if tf.get("available") and tf.get("matched"):
        bits.append(f"ThreatFox MATCH: {tf.get('malware','?')} "
                    f"({tf.get('threat_type','?')}, confidence {tf.get('confidence','?')}%)")
        risk = "flagged-malicious"  # a ThreatFox IOC match is strong

    if not bits:
        summary = "no threat-intel matches (not in any queried source)"
    else:
        summary = " | ".join(bits)

    return {"summary": summary, "risk": risk}


def _load_keys():
    keys = {}
    for name, cfg in config.INTEL_PROVIDERS.items():
        if not cfg.get("enabled"):
            continue
        k = os.environ.get(cfg["env_key"], "").strip()
        if k:
            keys[name] = k
        # ThreatFox may work keyless on some accounts; allow empty-key attempt
        elif name == "threatfox":
            keys[name] = ""
    return keys


def enrich_indicator(indicator, itype, db):
    """
    Look up one indicator across all configured providers, using the DB cache.
    Returns the combined result dict (also cached). Never raises - provider
    errors are captured inside the result.
    """
    cached = db.get_intel(indicator, itype, config.INTEL_CACHE_TTL_DAYS)
    if cached is not None:
        cached["_cached"] = True
        return cached

    keys = _load_keys()
    results = {}
    for name in ("greynoise", "abuseipdb", "threatfox"):
        if name not in keys:
            continue
        func = _PROVIDER_FUNCS[name]
        results[name] = func(indicator, itype, keys[name])
        time.sleep(config.INTEL_INTER_CALL_DELAY)

    combined = {"providers": results, **_summarize(results), "_cached": False}
    db.set_intel(indicator, itype, combined)
    return combined


def enrich_bundles(bundles, db, high_signal_only=True):
    """
    Enrich a list of bundles in place. Each bundle gains a `threat_intel` key.
    Skips low-signal bundles when high_signal_only (default) to conserve the
    scarce GreyNoise weekly quota.

    `high_signal_only` here means: caller has already tagged each bundle with
    b['_low_signal'] (bool). If that tag isn't present, all bundles are
    enriched. The caller (main.py) sets it based on config routing.
    """
    if not config.INTEL_ENABLED:
        return bundles

    enriched = 0
    for b in bundles:
        if high_signal_only and b.get("_low_signal"):
            continue
        ind = b.get("indicator")
        itype = b.get("type", "ip")
        if not ind:
            continue
        b["threat_intel"] = enrich_indicator(ind, itype, db)
        enriched += 1
    return bundles, enriched
