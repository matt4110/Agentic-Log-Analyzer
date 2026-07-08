"""
Central configuration for the IOC hunter.

Tune thresholds here as you see real traffic. Nothing here is sacred -
these are reasonable starting points for a small web server.
"""
from datetime import date
import re

# ---------------------------------------------------------------------------
# Paths (override via CLI args in main.py if you'd rather not edit this file)
# ---------------------------------------------------------------------------

current_date = date.today().isoformat()

AUTH_LOG_PATH = f"/var/log/parsed/auth-{current_date}.jsonl"
AUDITD_LOG_PATH = f"/var/log/parsed/auditd-{current_date}.jsonl"
UFW_LOG_PATH = f"/var/log/parsed/ufw-{current_date}.jsonl"
WAF_LOG_PATH = f"/var/log/parsed/safeline-{current_date}.jsonl"

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
# Reverse-shell / malicious-command patterns matched against reconstructed
# EXECVE argv (joined as `cmdline`). This is where actual command-line
# content lets us catch things an exe-name blocklist can't - e.g. a plain
# /bin/bash spawning a reverse shell via redirected file descriptors.
# ---------------------------------------------------------------------------
REVERSE_SHELL_ARGV_PATTERNS = [
    r"/dev/tcp/",
    r"/dev/udp/",
    r"\bnc\s+.*-e\s+/bin/(ba)?sh",
    r"\bmkfifo\b.*\|\s*/bin/(ba)?sh",
    r"\bbash\s+-i\b",
    r"\bsh\s+-i\b",
    r"\bpython[23]?\s+-c\s+.*socket",
    r"\bperl\s+-e\s+.*socket",
    r"\bruby\s+-rsocket\b",
    r"\bphp\s+-r\s+.*fsockopen",
    r"\bsocat\b.*exec",
]

SUSPICIOUS_COMMAND_PATTERNS = [
    r"\bcurl\b.*\|\s*(ba)?sh\b",
    r"\bwget\b.*-O-.*\|\s*(ba)?sh\b",
    r"\bwget\b.*\|\s*(ba)?sh\b",
    r"\bbase64\s+-d\b.*\|\s*(ba)?sh\b",
    r"\bchmod\s+\+x\b.*&&",
    r"\becho\b.*\|\s*base64\s+-d\b",
    r">\s*/etc/(passwd|shadow|cron\.d)",
]

_compile_group("reverse_shell", REVERSE_SHELL_ARGV_PATTERNS)
_compile_group("suspicious_cmd", SUSPICIOUS_COMMAND_PATTERNS)

# ---------------------------------------------------------------------------
# Related-event caps for the correlator/report - a single noisy scanning IP
# can generate hundreds of near-identical blocked-packet log lines in a day.
# Dumping all of them into the report bloats file size without adding
# analytical value - an LLM doesn't need to see 200 individual SYN packets,
# it needs "blocked 200x across these ports" plus a few examples. High-signal
# categories (actual attack indicators) get a much higher ceiling since
# completeness matters more there and they're rarely this voluminous anyway.
# ---------------------------------------------------------------------------
LOW_SIGNAL_ONLY_CATEGORIES = {
    "port_scan", "repeated_blocked_connections", "unusual_outbound",
}
# Low-signal bundles keep only a handful of EXAMPLE events plus aggregate
# stats (total count, time span, distinct ports/destinations) - at scale,
# thousands of routine scanning IPs each contributing even 20 raw events
# adds up to tens of thousands of entries that don't add analytical value
# an LLM needs. High-signal categories (actual attack indicators) keep a
# much larger cap since completeness matters more there and they're
# rarely voluminous anyway.
MAX_RELATED_EVENTS_LOW_SIGNAL = 3
MAX_RELATED_EVENTS_HIGH_SIGNAL = 100

# Several detectors (WAF injection/XSS/traversal, scanner UA, reverse-shell
# argv, setuid escalation) emit one Flag PER matching record with no
# grouping - an attacker retrying the same payload hundreds of times in a
# day produces hundreds of near-identical reason strings for one indicator,
# completely unbounded by the related_events cap above. Cap and dedupe
# separately.
MAX_REASONS_PER_INDICATOR = 15

# ---------------------------------------------------------------------------
# ses -> src_ip backfill sanity limits
# ---------------------------------------------------------------------------
# If the nearest ses-tagged src_ip record is farther than this from the
# exec event being backfilled, still use it but mark low_confidence=True
# in the merged record so the LLM/analyst can weigh it accordingly.
SES_BACKFILL_LOW_CONFIDENCE_SECONDS = 3600  # 1 hour

# ---------------------------------------------------------------------------
# Privilege escalation (auditd) - tightened ruleset
# ---------------------------------------------------------------------------
PRIVESC_OPS = [
    "PAM:setcred", "PAM:session_open", "PAM:session_close", "PAM:acct_mgmt",
]

# Standard, expected tools for gaining elevated privileges. A PAM root
# escalation op via one of these is routine admin activity, not an IOC.
# Anything else claiming a root PAM op is worth a look.
KNOWN_PRIVESC_TOOLS = {"sudo", "su", "pkexec", "doas"}

# System processes that legitimately run as uid=0 with no traceable auid
# (no interactive login behind them - started at boot / by init / by cron).
KNOWN_SYSTEM_DAEMONS = {
    "sshd", "systemd", "cron", "crond", "init", "auditd", "rsyslogd",
    "systemd-logind", "dbus-daemon", "networkd-dispatcher",
}

# x86_64 syscall numbers for the setuid/setgid family. A process outside
# KNOWN_PRIVESC_TOOLS/KNOWN_SYSTEM_DAEMONS directly invoking one of these
# to become uid=0 is a stronger signal than a bare uid/auid mismatch.
SETUID_SYSCALL_NUMBERS = {"105", "106", "113", "114", "117", "119", "126"}
