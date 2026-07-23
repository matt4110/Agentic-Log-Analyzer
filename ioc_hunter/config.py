"""
Central configuration for the IOC hunter.

Tune thresholds here as you see real traffic. Nothing here is sacred -
these are reasonable starting points for a small web server.
"""

from datetime import date
import re

current_date = date.today().isoformat()

# ---------------------------------------------------------------------------
# Paths (override via CLI args in main.py if you'd rather not edit this file)
# ---------------------------------------------------------------------------
AUTH_LOG_PATH = f"/var/log/parsed/{current_date}-auth.jsonl"
AUDITD_LOG_PATH = f"/var/log/parsed/{current_date}-auditd.jsonl"
UFW_LOG_PATH = f"/var/log/parsed/{current_date}-ufw.jsonl"
WAF_LOG_PATH = f"/var/log/parsed/{current_date}-safeline.jsonl"

OUTPUT_DIR = f"/opt/Agentic-Log-Analyzer/ioc_output/{current_date}"
DB_PATH = "actors.db"

# ---------------------------------------------------------------------------
# Velocity thresholds (count, window_seconds)
# ---------------------------------------------------------------------------
BRUTE_FORCE_THRESHOLD = (5, 600)          # 5 auth failures / 10 min / src_ip or user
PORT_SCAN_THRESHOLD = (15, 300)           # 15 distinct dst_ports / 5 min / src_ip
IDOR_SEQUENTIAL_THRESHOLD = (8, 120)      # 8 sequential numeric IDs / 2 min / src_ip

# ---------------------------------------------------------------------------
# Admin allowlist - YOUR OWN access.
# At the host and WAF layer, an authorized admin session and a compromised
# one are byte-identical: same successful SSH login, same root commands, same
# POST-then-302. No threshold can separate them, because there is nothing in
# the data to separate. The only fix is telling the pipeline which IPs and
# accounts are yours.
#
# Flags whose indicator is an allowlisted IP are DOWNGRADED, not discarded -
# they still appear (an attacker on your admin IP, or your own credentials
# used from elsewhere, is exactly what you'd want to see), but they are
# routed to the low-signal table instead of generating critical findings.
#
# Keep this current. A stale allowlist is how you end up with a "CRITICAL:
# attacker established persistence" alert about yourself patching the box.
# ---------------------------------------------------------------------------
ADMIN_IPS = {
    # "68.43.58.246",     # <- your home IP; uncomment/edit with your real values
}
ADMIN_ACCOUNTS = {
    # "cammo",            # <- your admin username(s)
}
# If True, allowlisted indicators are downgraded to low-signal rather than
# dropped entirely. Strongly recommended: never blind yourself to your own IP.
ADMIN_DOWNGRADE_NOT_DROP = True

# WAF login brute-force-success detection. On this app, a failed login
# re-renders the login page (POST / -> 200); a successful login redirects
# (POST / -> 302). So N failed POSTs to the login path followed by a 302
# from the same IP within the window = a login that succeeded after repeated
# failures. NOTE: this cannot distinguish a real attacker from an admin who
# mistyped their password several times - both produce identical requests.
# The threshold is the separator: a human fumbles 2-3 times, a brute-force
# makes many attempts. Tune LOGIN_BRUTEFORCE_THRESHOLD up if your own logins
# trip it.
LOGIN_BRUTEFORCE_THRESHOLD = (5, 600)     # 5 failed POSTs / 10 min before a success
LOGIN_PATHS = {"/"}                        # request paths treated as the login endpoint
LOGIN_HOST = "matt4110.com"                # host to match; set to None to match any host
LOGIN_FAIL_STATUS = {"200"}                # status(es) that mean "login failed / page re-served"
LOGIN_SUCCESS_STATUS = {"302"}             # status(es) that mean "login succeeded / redirect"

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

# Successful authentication - used to detect the dangerous case: a source
# that failed repeatedly (brute force) and THEN succeeded, i.e. a likely
# credential compromise, which is a real incident rather than background
# noise.
AUTH_SUCCESS_PATTERNS = [
    r"accepted password",
    r"accepted publickey",
    r"session opened for user",
]
AUTH_SUCCESS_RE = re.compile("|".join(AUTH_SUCCESS_PATTERNS), re.IGNORECASE)

# crude hostname/domain extraction from free-text auth messages
DOMAIN_CANDIDATE_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|io|co|info|biz|ru|cn|xyz|top|club|online|site|info|gov|edu)\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# LLM analysis settings (llm_analyze.py)
# Defaults target a locally hosted model behind an OpenAI-compatible API
# (Ollama, llama.cpp server, LM Studio all expose /v1/chat/completions).
# ---------------------------------------------------------------------------
LLM_BASE_URL = "http://localhost:11434/v1"   # Ollama default
LLM_MODEL = "gpt-oss:20b"
LLM_TEMPERATURE = 0.2       # low - we want consistent, schema-conformant output
LLM_MAX_RETRIES = 2         # per-chunk retries on invalid JSON output
LLM_TIMEOUT_SECONDS = 600   # CPU inference is slow; don't time out prematurely

# gpt-oss is a REASONING model: left unconstrained it spends its entire
# output budget "thinking" and never emits the answer (finish_reason:
# length with empty/truncated content). Three controls prevent that:
#  - num_predict: raise the hard output-token ceiling so there's room for
#    both reasoning AND the JSON answer.
#  - reasoning_effort low: tell gpt-oss to think briefly, not exhaustively.
#  - format json: Ollama constrains output to valid JSON, which also
#    suppresses the essay-style rambling we saw.
LLM_NUM_PREDICT = 8192
LLM_REASONING_EFFORT = "low"   # gpt-oss-specific: low|medium|high
LLM_FORCE_JSON = True          # use Ollama's structured-output JSON mode

# ---------------------------------------------------------------------------
# Threat-intel enrichment (enrich_intel.py)
# Read-only lookups that annotate high-signal indicators with reputation from
# external providers. API keys come from environment variables (set them in
# your .env, sourced by run_daily.sh) - never hardcode credentials here.
#
# Provider notes / free-tier limits (verify against current provider docs):
#   - GreyNoise Community: ~50 lookups/WEEK (tight) - answers "is this internet
#     background noise vs targeted?". Best used to DOWNGRADE noisy scanners.
#     Env: GREYNOISE_API_KEY
#   - AbuseIPDB: ~1000 checks/day (generous) - crowdsourced abuse confidence
#     score 0-100. The volume workhorse. Env: ABUSEIPDB_API_KEY
#   - ThreatFox (abuse.ch): IOC match against known malware infra (C2/botnet/
#     payload). A hit is high-signal; most opportunistic scanners won't match.
#     Env: THREATFOX_API_KEY
#
# Aggressive caching in actors.db means each IP is looked up at most once per
# CACHE_TTL window - critical for staying under GreyNoise's weekly limit, since
# repeat scanners are already cached from prior runs.
# ---------------------------------------------------------------------------
INTEL_ENABLED = True
INTEL_CACHE_TTL_DAYS = 7           # re-query an indicator only after this many days
INTEL_ONLY_HIGH_SIGNAL = True      # never spend lookups on the low-signal noise table
INTEL_REQUEST_TIMEOUT = 15         # seconds per provider call
INTEL_INTER_CALL_DELAY = 1.0       # seconds between calls (be a good API citizen)

# Per-provider toggles + which env var holds each key. A provider with no key
# in the environment is silently skipped, so you can enable them one at a time
# as you create accounts.
INTEL_PROVIDERS = {
    "greynoise": {"enabled": True,  "env_key": "GREYNOISE_API_KEY"},
    "abuseipdb": {"enabled": True,  "env_key": "ABUSEIPDB_API_KEY"},
    "threatfox": {"enabled": True,  "env_key": "THREATFOX_API_KEY"},
}


# Default chunk size target, in bytes. ~4 chars/token, so 48000 bytes is
# roughly 12k tokens - sized for a local 20B model where (a) CPU prompt
# processing at 75k+ tokens takes minutes per chunk and (b) small models
# degrade on long-context retrieval, conflating details between bundles.
# Frontier API models can handle 300000+; local models should stay small.
# Default chunk size target, in bytes. Kept small deliberately: gpt-oss:20b
# on CPU reasons about every indicator in a chunk before answering, and a
# dense multi-indicator chunk can make it loop without converging. ~6000
# bytes keeps each chunk to roughly 1-2 indicators so each call stays small
# enough for the model to finish. Raise only if your model handles bigger
# chunks reliably.
CHUNK_MAX_BYTES_DEFAULT = 6_000

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
    # plain brute force (all-failed auth floods) is constant background noise
    # on any internet-facing box. Note: brute_force_success is deliberately
    # NOT here - a success after failures is a real compromise lead and stays
    # high-signal for full per-indicator analysis.
    "brute_force",
}

# Web-attack categories that are only worth deep analysis if something
# actually succeeded (a 2xx response). When a bundle's categories are all
# within this set AND every request got a 4xx/5xx, the chunker routes it to
# the low-signal table instead of a full chunk - a blocked/404'd attack
# accomplished nothing and is just internet background noise. A 2xx on any
# of these keeps the indicator high-signal.
WEB_ATTACK_CATEGORIES = {
    "sql_injection", "command_injection", "xss", "directory_traversal",
    "scanner_tool", "idor_heuristic",
}
# Low-signal bundles keep only a handful of EXAMPLE events plus aggregate
# stats (total count, time span, distinct ports/destinations) - at scale,
# thousands of routine scanning IPs each contributing even 20 raw events
# adds up to tens of thousands of entries that don't add analytical value
# an LLM needs. High-signal categories (actual attack indicators) keep a
# much larger cap since completeness matters more there and they're
# rarely voluminous anyway.
MAX_RELATED_EVENTS_LOW_SIGNAL = 3
MAX_RELATED_EVENTS_HIGH_SIGNAL = 20

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
    "sshd", "sshd-session", "sshd-auth", "systemd", "cron", "crond", "init",
    "auditd", "rsyslogd", "systemd-logind", "dbus-daemon", "networkd-dispatcher",
    "login", "gdm", "lightdm", "polkitd", "agetty",
}

# x86_64 syscall numbers for the setuid/setgid family. A process outside
# KNOWN_PRIVESC_TOOLS/KNOWN_SYSTEM_DAEMONS directly invoking one of these
# to become uid=0 is a stronger signal than a bare uid/auid mismatch.
SETUID_SYSCALL_NUMBERS = {"105", "106", "113", "114", "117", "119", "126"}
