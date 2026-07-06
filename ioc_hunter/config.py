"""
Central configuration for the IOC hunter.

Tune thresholds here as you see real traffic. Nothing here is sacred -
these are reasonable starting points for a small web server.
"""

import re

# ---------------------------------------------------------------------------
# Paths (override via CLI args in main.py if you'd rather not edit this file)
# ---------------------------------------------------------------------------
AUTH_LOG_PATH = "auth_parsed.jsonl"
AUDITD_LOG_PATH = "auditd_parsed.jsonl"
UFW_LOG_PATH = "ufw_parsed.jsonl"
WAF_LOG_PATH = "safeline_parsed.jsonl"

OUTPUT_DIR = "ioc_output"
DB_PATH = "actors.db"

# ---------------------------------------------------------------------------
# Velocity thresholds (count, window_seconds)
# ---------------------------------------------------------------------------
BRUTE_FORCE_THRESHOLD = (5, 600)          # 5 auth failures / 10 min / src_ip or user
PORT_SCAN_THRESHOLD = (15, 300)           # 15 distinct dst_ports / 5 min / src_ip
IDOR_SEQUENTIAL_THRESHOLD = (8, 120)      # 8 sequential numeric IDs / 2 min / src_ip

# ---------------------------------------------------------------------------
# WAF response size (bytes) - flag unusually large responses (possible exfil)
# ---------------------------------------------------------------------------
LARGE_RESPONSE_BYTES = 5_000_000          # 5 MB flat ceiling
# also flag if a response is this many times larger than that path's median
# size seen so far in the same run (set to None to disable relative check)
LARGE_RESPONSE_RELATIVE_MULTIPLIER = 10

# ---------------------------------------------------------------------------
# Known scanner / attack-tool user agents (substring match, case-insensitive)
# ---------------------------------------------------------------------------
SCANNER_USER_AGENTS = [
    "sqlmap", "nikto", "nmap", "masscan", "gobuster", "dirbuster", "dirb",
    "wpscan", "acunetix", "nessus", "zgrab", "nuclei", "wfuzz", "burpsuite",
    "havij", "w3af", "arachni", "skipfish", "openvas",
]

# ---------------------------------------------------------------------------
# Web attack signatures - matched against the *decoded* request path
# (decoded once and twice, to catch double-encoding evasion)
# ---------------------------------------------------------------------------
SQLI_PATTERNS = [
    r"\bunion\b[^a-z]{0,10}\bselect\b",
    r"\bselect\b.{0,60}\bfrom\b",
    r"\bor\b\s+['\"]?1['\"]?\s*=\s*['\"]?1",
    r"'\s*--",
    r"\bdrop\s+table\b",
    r"\bxp_cmdshell\b",
    r"\bsleep\(\s*\d+\s*\)",
    r"\bbenchmark\(",
    r"\binformation_schema\b",
    r"\bupdatexml\(",
    r"\bwaitfor\s+delay\b",
]

CMD_INJECTION_PATTERNS = [
    r"[;&|`]\s*(cat|wget|curl|chmod|bash|/bin/sh|nc|ncat|python|perl|id|whoami)\b",
    r"\$\(\s*(cat|wget|curl|id|whoami)\b",
    r"\b(cat|wget|curl)\s+/etc/(passwd|shadow)\b",
    r"%0a|%0d",  # injected newlines/CR
    r"\|\|\s*(cat|id|whoami)\b",
]

XSS_PATTERNS = [
    r"<script\b",
    r"onerror\s*=",
    r"onload\s*=",
    r"javascript:",
    r"document\.cookie",
    r"<img[^>]+src\s*=",
    r"<svg[^>]*onload",
    r"<iframe\b",
]

DIR_TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"\.\.\\",
    r"%2e%2e%2f",
    r"%2e%2e/",
    r"\.\.%2f",
    r"/etc/passwd\b",
    r"/etc/shadow\b",
    r"\bwin\.ini\b",
]

# Compile everything once
_COMPILED = {}
def _compile_group(name, patterns):
    _COMPILED[name] = [re.compile(p, re.IGNORECASE) for p in patterns]

_compile_group("sqli", SQLI_PATTERNS)
_compile_group("cmdi", CMD_INJECTION_PATTERNS)
_compile_group("xss", XSS_PATTERNS)
_compile_group("traversal", DIR_TRAVERSAL_PATTERNS)

def compiled(name):
    return _COMPILED[name]

# ---------------------------------------------------------------------------
# auditd: binaries considered inherently suspicious if they show up as `exe`
# (no argv available in this schema, so this is a coarse blocklist, not
# behavioral detection)
# ---------------------------------------------------------------------------
MALWARE_EXE_BASENAMES = [
    "nc", "ncat", "netcat", "socat", "nmap", "masscan", "zmap",
    "hydra", "medusa", "john", "hashcat", "mimikatz", "empire",
    "msfconsole", "meterpreter",
]

# exe paths running from these directories are suspicious regardless of name
SUSPICIOUS_EXE_DIRS = ["/tmp/", "/var/tmp/", "/dev/shm/", "/dev/shm", "/tmp"]

# binaries whose presence in auditd usually indicates persistence attempts
PERSISTENCE_EXE_BASENAMES = [
    "useradd", "usermod", "userdel", "crontab", "ssh-keygen", "visudo",
    "chpasswd", "passwd",
]

PERSISTENCE_AUDIT_TYPES = ["ADD_USER", "USER_ACCT", "ADD_GROUP", "DEL_USER"]

# ---------------------------------------------------------------------------
# auth log: substrings/regex indicating authentication failure vs success
# ---------------------------------------------------------------------------
AUTH_FAILURE_PATTERNS = [
    r"failed password",
    r"authentication failure",
    r"invalid user",
    r"failure password",
    r"pam_unix\(.*\):\s*auth\s*failure",
]
AUTH_FAILURE_RE = re.compile("|".join(AUTH_FAILURE_PATTERNS), re.IGNORECASE)

# crude hostname/domain extraction from free-text auth messages
DOMAIN_CANDIDATE_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|io|co|info|biz|ru|cn|xyz|top|club|online|site|info|gov|edu)\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Privilege escalation (auditd)
# ---------------------------------------------------------------------------
PRIVESC_OPS = [
    "PAM:setcred", "PAM:session_open", "PAM:session_close", "PAM:acct_mgmt",
]
