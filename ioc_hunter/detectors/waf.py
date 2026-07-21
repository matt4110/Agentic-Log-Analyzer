"""
Detectors for the safeline-waf schema:
{datetime, src_ip, method, req_path, response, user_agent, size}

Only req_path + user_agent are available (no separated query string or
body), so payload-based detectors match against the full req_path as
delivered, decoded once and twice to catch encoding evasion. This means
body-based injection attempts (e.g. POST form fields) will be missed -
worth knowing as a coverage gap.
"""

import re
from collections import defaultdict
from detectors import Flag
from utils import double_decode, sliding_window_groups
import config


NUMERIC_ID_RE = re.compile(r"(\d+)")


def _match_any(patterns, text):
    return any(p.search(text) for p in patterns)


def _decoded_variants(req_path):
    if not req_path:
        return [""]
    once = double_decode(req_path)
    return list({req_path, once})


def detect_injection_and_xss(waf_records):
    flags = []
    for r in waf_records:
        path = r.get("req_path") or ""
        variants = _decoded_variants(path)
        src_ip = r.get("src_ip")
        if not src_ip:
            continue

        for variant in variants:
            if _match_any(config.compiled("sqli"), variant):
                flags.append(Flag(
                    indicator=src_ip, indicator_type="ip", category="sql_injection",
                    description=f"SQLi-pattern match in request path from {src_ip}: {path}",
                    evidence=[r],
                ))
                break
        for variant in variants:
            if _match_any(config.compiled("cmdi"), variant):
                flags.append(Flag(
                    indicator=src_ip, indicator_type="ip", category="command_injection",
                    description=f"Command-injection pattern match in request path from {src_ip}: {path}",
                    evidence=[r],
                ))
                break
        for variant in variants:
            if _match_any(config.compiled("xss"), variant):
                flags.append(Flag(
                    indicator=src_ip, indicator_type="ip", category="xss",
                    description=f"XSS pattern match in request path from {src_ip}: {path}",
                    evidence=[r],
                ))
                break
        for variant in variants:
            if _match_any(config.compiled("traversal"), variant):
                flags.append(Flag(
                    indicator=src_ip, indicator_type="ip", category="directory_traversal",
                    description=f"Directory-traversal pattern match in request path from {src_ip}: {path}",
                    evidence=[r],
                ))
                break
    return flags


def detect_scanner_user_agents(waf_records):
    flags = []
    for r in waf_records:
        ua = (r.get("user_agent") or "").lower()
        src_ip = r.get("src_ip")
        if not ua or not src_ip:
            continue
        for tool in config.SCANNER_USER_AGENTS:
            if tool in ua:
                flags.append(Flag(
                    indicator=src_ip, indicator_type="ip", category="scanner_tool",
                    description=f"Known scanner/attack-tool user agent from {src_ip}: '{r.get('user_agent')}'",
                    evidence=[r],
                ))
                break
    return flags


def _path_template(path):
    """Collapse numeric segments so /api/user/123 and /api/user/456 group together."""
    if not path:
        return path
    return NUMERIC_ID_RE.sub("{id}", path)


def detect_idor_heuristic(waf_records):
    """
    Low-confidence heuristic: the same src_ip requesting many distinct
    numeric IDs against the same path template in a short window, with
    successful (2xx) responses. This is NOT proof of IDOR (no session/
    ownership data available) - it flags a pattern worth a human/LLM look.
    """
    threshold, window = config.IDOR_SEQUENTIAL_THRESHOLD
    by_key = defaultdict(list)
    for r in waf_records:
        resp = str(r.get("response") or "")
        if not resp.startswith("2"):
            continue
        path = r.get("req_path") or ""
        ids = NUMERIC_ID_RE.findall(path)
        if not ids:
            continue
        key = (r.get("src_ip"), _path_template(path))
        by_key[key].append(r)

    flags = []
    for (src_ip, template), records in by_key.items():
        if not src_ip:
            continue
        groups = sliding_window_groups(
            records, threshold_count=threshold, window_seconds=window,
            key_func=lambda r: (r.get("src_ip"), _path_template(r.get("req_path") or "")),
            ts_func=lambda r: r.get("_ts"),
        )
        for _, evidence in groups.items():
            distinct_ids = {tuple(NUMERIC_ID_RE.findall(e.get("req_path") or "")) for e in evidence}
            if len(distinct_ids) >= threshold:
                flags.append(Flag(
                    indicator=src_ip, indicator_type="ip", category="idor_heuristic",
                    description=(
                        f"{src_ip} requested {len(distinct_ids)} distinct numeric IDs against "
                        f"pattern '{template}' within {window}s, all with 2xx responses "
                        f"(low-confidence heuristic - no session/ownership data available)"
                    ),
                    evidence=evidence,
                ))
    return flags


def detect_large_responses(waf_records):
    """
    Flat-ceiling large response flag, plus a relative check against the
    median size seen for that path template in this run (catches unusual
    dumps even on paths that are normally small).
    """
    flags = []

    sizes_by_template = defaultdict(list)
    parsed_sizes = {}
    for r in waf_records:
        try:
            size = int(r.get("size") or 0)
        except (TypeError, ValueError):
            size = 0
        parsed_sizes[id(r)] = size
        sizes_by_template[_path_template(r.get("req_path") or "")].append(size)

    medians = {}
    for template, sizes in sizes_by_template.items():
        sorted_sizes = sorted(sizes)
        n = len(sorted_sizes)
        medians[template] = sorted_sizes[n // 2] if n else 0

    for r in waf_records:
        size = parsed_sizes[id(r)]
        src_ip = r.get("src_ip")
        if not src_ip or size <= 0:
            continue

        reason = None
        if size >= config.LARGE_RESPONSE_BYTES:
            reason = f"response size {size} bytes exceeds flat ceiling of {config.LARGE_RESPONSE_BYTES}"
        elif config.LARGE_RESPONSE_RELATIVE_MULTIPLIER:
            template = _path_template(r.get("req_path") or "")
            median = medians.get(template, 0)
            if median > 0 and size >= median * config.LARGE_RESPONSE_RELATIVE_MULTIPLIER:
                reason = (
                    f"response size {size} bytes is {size / median:.1f}x the median "
                    f"({median} bytes) for path pattern '{template}'"
                )

        if reason:
            flags.append(Flag(
                indicator=src_ip, indicator_type="ip", category="large_response_possible_exfil",
                description=f"{reason} - request from {src_ip} to {r.get('req_path')}",
                evidence=[r],
            ))
    return flags


def detect_login_bruteforce_success(waf_records):
    """
    Failed logins (POST to a login path -> LOGIN_FAIL_STATUS, typically 200
    re-rendering the login page) followed by a success (POST -> 302 redirect)
    from the same IP within the window. High-signal: a successful login after
    repeated failures is exactly the "brute force that got in" case.

    Caveat baked into the threshold, not the code: this cannot tell a real
    attacker from an admin who mistyped a few times. The count threshold is
    what separates them - a human fumbles a handful of times, a brute-force
    makes many attempts.
    """
    threshold, window = config.LOGIN_BRUTEFORCE_THRESHOLD

    def _is_login_path(r):
        return (r.get("req_path") in config.LOGIN_PATHS
                and (r.get("method") or "").upper() == "POST")

    def _host_ok(r):
        if config.LOGIN_HOST is None:
            return True
        # host field may be absent in older parsed logs; if so, don't exclude
        h = r.get("host")
        return h is None or h == config.LOGIN_HOST

    # group candidate login events by src_ip, sorted by time
    by_ip = defaultdict(list)
    for r in waf_records:
        if not _is_login_path(r) or not _host_ok(r):
            continue
        ip = r.get("src_ip")
        ts = r.get("_ts")
        if ip and ts is not None:
            by_ip[ip].append((ts, r))

    flags = []
    for ip, pairs in by_ip.items():
        pairs.sort(key=lambda p: p[0])
        # walk chronologically; count failures, and when a success appears,
        # check whether >= threshold failures preceded it within the window
        for i, (ts_success, rec_success) in enumerate(pairs):
            if str(rec_success.get("response")) not in config.LOGIN_SUCCESS_STATUS:
                continue
            # count failures before this success, inside the window
            preceding_failures = [
                r for (ts, r) in pairs[:i]
                if str(r.get("response")) in config.LOGIN_FAIL_STATUS
                and (ts_success - ts).total_seconds() <= window
            ]
            if len(preceding_failures) >= threshold:
                evidence = preceding_failures + [rec_success]
                flags.append(Flag(
                    indicator=ip, indicator_type="ip",
                    category="login_bruteforce_success",
                    description=(
                        f"POSSIBLE SUCCESSFUL LOGIN BRUTE FORCE: {ip} made "
                        f"{len(preceding_failures)} failed login attempts (POST "
                        f"{'/'.join(config.LOGIN_PATHS)} -> {'/'.join(config.LOGIN_FAIL_STATUS)}) "
                        f"then a successful login (-> {'/'.join(config.LOGIN_SUCCESS_STATUS)}) "
                        f"within {window}s - investigate; note this also matches an "
                        f"authorized user who mistyped their password repeatedly"
                    ),
                    evidence=evidence,
                ))
                break  # one flag per IP is enough; evidence already gathered
    return flags


def run_all(waf_records):
    flags = []
    flags += detect_injection_and_xss(waf_records)
    flags += detect_scanner_user_agents(waf_records)
    flags += detect_idor_heuristic(waf_records)
    flags += detect_large_responses(waf_records)
    flags += detect_login_bruteforce_success(waf_records)
    return flags
