from datetime import date
import json
import re

current_date = date.today().isoformat()
waf_file = "/var/log/safeline-waf.log.1"

log_pattern = re.compile(
    r'^(?P<iso_datetime>\S+)\s+'
    r'(?P<server>\S+)\s+'
    r'(?P<service>\S+)\s+'
    r'(?P<source_ip>\S+)\s*\|\s*'
    r'(?P<dash>\S+)\s*\|\s*'
    r'(?P<apache_datetime>[^|]+?)\s*\|\s*'
    r'"(?P<host>[^"]*)"\s*\|\s*'
    r'"(?P<request>[^"]*)"\s*\|\s*'
    r'(?P<status>\d+)\s*\|\s*'
    r'(?P<size>\d+)\s*\|\s*'
    r'"(?P<referrer>[^"]*)"\s*\|\s*'
    r'"(?P<user_agent>[^"]*)"\s*$'
)

with open(waf_file, "r") as logfile, \
     open(f"/var/log/safeline-{current_date}.json", "a") as jfile:
    
    for line in logfile:
        match = log_pattern.match(line)
        if not match:
            print(f"Skipping malformed line: {line.strip()}")
            continue

        try:
        # Split the request field into method, path, and protocol
            request = match.group("request")
            request_parts = request.split()
            method = request_parts[0] if len(request_parts) > 0 else None
            path = request_parts[1] if len(request_parts) > 1 else None
            protocol = request_parts[2] if len(request_parts) > 2 else None

            parsedline = {
                "datetime": match.group("iso_datetime"),
                "src_ip": match.group("source_ip"),
                "method": method,
                "req_path": path,
                "response": match.group("status"),
                "user_agent": match.group("user_agent"),
            }

            json.dump(parsedline, jfile)
            jfile.write('\n')

        except Exception as e:
            # Don't let one malformed line take down the whole run
            print(f"Skipping unparseable line: {line!r} ({e})")
            continue