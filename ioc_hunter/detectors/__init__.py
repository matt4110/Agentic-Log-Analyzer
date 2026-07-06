"""
Each detector function takes a list of records for its log type (plus
sometimes shared context like the ActorDB) and returns a list of Flag
objects. A Flag identifies WHY an indicator was flagged and WHICH raw
records are the direct evidence - the correlator later pulls in every
OTHER record touching that same indicator across all four log sources.
"""

from dataclasses import dataclass, field


@dataclass
class Flag:
    indicator: str          # the IP or domain
    indicator_type: str     # 'ip' or 'domain'
    category: str           # e.g. 'port_scan', 'sqli', 'privilege_escalation'
    description: str        # human-readable reason
    evidence: list = field(default_factory=list)  # the specific record(s) that triggered this
