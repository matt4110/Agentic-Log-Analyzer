from datetime import date
import json
import re

current_date = date.today().isoformat()
auth_file = "/var/log/auth.log.1"

# Looking for regex patterns in the free-text part of the log to find user, ip, and port
user_patterns = [
    re.compile(r'invalid user (\S+)'),
    re.compile(r'authenticating user (\S+)'),
    re.compile(r'for (\S+) from'),   # "Failed password for root from ..."
    re.compile(r'\buser (\S+)'),     # last-resort generic catch
]
ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
port_pattern = re.compile(r'\bport (\d+)')

# "process[pid]:" -> ("process", "pid")
proc_pattern = re.compile(r'^([\w\-.]+)\[(\d+)\]:$')

with open(auth_file, "r") as logfile, \
     open(f"/var/log/auth-{current_date}.json", "a") as jfile:

    for line in logfile:
        if 'sshd' not in line:
            continue
        try:
            fields = line.split(maxsplit=6)
            if len(fields) < 7:
                continue

            outer_ts, outer_host, facility, inner_ts, inner_host, proc_id, rest = fields

            proc_match = proc_pattern.match(proc_id)
            if not proc_match:
                continue
            process, pid = proc_match.groups()

            # reset per-line so a miss doesn't inherit the previous line's values
            user = ip_address = port = None

            for pattern in user_patterns:
                user_match = pattern.search(rest)
                if user_match:
                    user = user_match.group(1)
                    break

            ip_match = ip_pattern.search(rest)
            if ip_match:
                ip_address = ip_match.group(0)

            port_match = port_pattern.search(rest)
            if port_match:
                port = port_match.group(1)

            parsedline = {
                "datetime": outer_ts,
                "hostname": outer_host,
                "process": process,
                "pid": pid,
                "user": user,
                "ip_address": ip_address,
                "port": port,
                "message": rest.rstrip(),
            }
            json.dump(parsedline, jfile)
            jfile.write('\n')

        except Exception as e:
            # Don't let one malformed line take down the whole run
            print(f"Skipping unparseable line: {line!r} ({e})")
            continue