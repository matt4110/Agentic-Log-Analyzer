from datetime import date
import json
import re

current_date = date.today().isoformat()
auditd_log = "/var/log/auditd.log.1"

with open(auditd_log, "r") as logfile, \
     open(f"/var/log/auditd-{current_date}.json", "a") as jfile:

    for line in logfile:
        if 'auditd' not in line:
            continue

        try:
            # Split off the #035 suffix (record separator + resolved UID/AUID fields)
            main_part, _, suffix = line.partition('#035')

            # Split off the inner msg='...' content
            pre_inner, _, inner_and_rest = main_part.partition("msg='")
            inner_content = inner_and_rest.rstrip("'\n")

            # Parse outer key=value tokens (datetime, hostname, type, audit ts, pid, uid, etc.)
            pre_inner_tokens = pre_inner.split()
            datetime_str = pre_inner_tokens[0]
            hostname     = pre_inner_tokens[1]

            outer_fields = {}
            for token in pre_inner_tokens[3:]:  # skip datetime, hostname, 'auditd'
                if '=' in token:
                    key, _, val = token.partition('=')
                    outer_fields[key] = val.rstrip(':')

            # Extract audit timestamp and event ID from msg=audit(TS:ID)
            audit_ts_match = re.match(r'audit\((\d+\.\d+):(\d+)\)', outer_fields.get('msg', ''))
            audit_timestamp = audit_ts_match.group(1) if audit_ts_match else None
            audit_event_id  = audit_ts_match.group(2) if audit_ts_match else None

            # Parse inner msg fields — values may be quoted or unquoted
            inner_fields = {}
            for m in re.finditer(r'(\w+)=("(?:[^"\\]|\\.)*"|[^\s]+)', inner_content):
                inner_fields[m.group(1)] = m.group(2).strip('"')

            # Parse suffix resolved fields: UID="root" AUID="unset"
            suffix_fields = {}
            for m in re.finditer(r'(\w+)="([^"]*)"', suffix):
                suffix_fields[m.group(1)] = m.group(2)

            parsedline = {
                "datetime":        datetime_str,
                "hostname":        hostname,
                "type":            outer_fields.get('type'),
                "audit_timestamp": audit_timestamp,
                "audit_event_id":  audit_event_id,
                "pid":             outer_fields.get('pid'),
                "uid":             outer_fields.get('uid'),
                "auid":            outer_fields.get('auid'),
                "ses":             outer_fields.get('ses'),
                "op":              inner_fields.get('op'),
                "acct":            inner_fields.get('acct'),
                "exe":             inner_fields.get('exe'),
                "src_hostname":    inner_fields.get('hostname'),
                "src_ip":            inner_fields.get('addr'),
                "terminal":        inner_fields.get('terminal'),
                "res":             inner_fields.get('res'),
                "uid_resolved":    suffix_fields.get('UID'),
                "auid_resolved":   suffix_fields.get('AUID'),
            }

            json.dump(parsedline, jfile)
            jfile.write('\n')

        except (ValueError, IndexError, AttributeError) as e:
            print(f"Skipping malformed line: {e}\n  {line.strip()}")