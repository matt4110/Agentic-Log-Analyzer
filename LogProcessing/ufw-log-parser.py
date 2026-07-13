from datetime import date
import json

current_date = date.today().isoformat()
ufw_file = "/var/log/ufw.log.1"

with open(ufw_file, "r") as logfile, \
     open(f"/var/log/parsed/{current_date}-ufw.jsonl", "a") as jfile:

    for line in logfile:
        if '[UFW' not in line:
            continue

        logentry = line.split()

        try:
            fields = dict(item.split('=', 1) for item in logentry if '=' in item)

            ufw_idx = next(i for i, token in enumerate(logentry) if '[UFW' in token)
            action  = logentry[ufw_idx + 1].rstrip(']')

            if action == 'AUDIT':
                continue

            tcp_flags = [f for f in ('SYN', 'ACK', 'FIN', 'PSH', 'URG', 'RST') if f in logentry]
            ip_flags  = [f for f in ('DF',) if f in logentry]

            parsedline = {
                "datetime":  logentry[0],
                "action":    action,
                "src_ip":    fields.get('SRC'),
                "src_port":  fields.get('SPT'),
                "dst_ip":    fields.get('DST'),
                "dst_port":  fields.get('DPT'),
                "protocol":  fields.get('PROTO'),
                "in_iface":  fields.get('IN'),
                "out_iface": fields.get('OUT') or None,
                "mac":       fields.get('MAC'),
                "total_len": fields.get('LEN'),
                "tos":       fields.get('TOS'),
                "ttl":       fields.get('TTL'),
                "tcp_flags": tcp_flags or None,
                "ip_flags":  ip_flags or None,
            }

            json.dump(parsedline, jfile)
            jfile.write('\n')

        except (ValueError, IndexError, StopIteration) as e:
            print(f"Skipping malformed line: {e}\n  {line.strip()}")