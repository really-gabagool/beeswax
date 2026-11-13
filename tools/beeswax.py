#!/usr/bin/env python3
"""Validate published lists, regenerate statistics, or process Cowrie JSONL offline."""
import argparse
import csv
import hashlib
import ipaddress
import json
import re
import statistics
import unicodedata
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = {'password': 'captured_passwords.txt', 'username': 'captured_usernames.txt'}
PROTOCOL = re.compile(r'^(?:GET |POST |HEAD |OPTIONS |CONNECT |PUT |DELETE |HTTP/|SSH-|command -v )', re.I)
HEX = re.compile(r'(?:\\x[0-9a-fA-F]{2})+')


def clean(value, exclusions=()):
    """Conservative candidate filtering; never trim or casefold a credential."""
    if not isinstance(value, str):
        return None, 'not_string'
    try:
        value = HEX.sub(lambda m: bytes.fromhex(m[0].replace('\\x', '')).decode('utf-8'), value)
    except UnicodeDecodeError:
        return None, 'invalid_utf8_escape'
    if not value:
        return None, 'empty'
    if any(unicodedata.category(c).startswith('C') or c in '\u2028\u2029' for c in value):
        return None, 'control_or_format_character'
    if PROTOCOL.match(value):
        return None, 'protocol_or_command_prefix'
    if any(token in value for token in exclusions):
        return None, 'operator_exclusion'
    try:
        ipaddress.ip_address(value)
        return None, 'ip_literal'
    except ValueError:
        pass
    return value, None


def read_list(path):
    data = path.read_bytes()
    value = data.decode('utf-8')
    if not data.endswith(b'\n') or b'\r' in data:
        raise ValueError(f'{path.name}: expected LF lines and final newline')
    entries = value[:-1].split('\n')
    if any(not x for x in entries) or len(entries) != len(set(entries)):
        raise ValueError(f'{path.name}: empty or duplicate entries')
    if any(any(unicodedata.category(c).startswith('C') or c in '\u2028\u2029' for c in x) for x in entries):
        raise ValueError(f'{path.name}: control/format characters')
    if any(HEX.search(x) for x in entries):
        raise ValueError(f'{path.name}: undecoded hex escapes')
    return entries


def stats(root):
    lists = {kind: read_list(root / name) for kind, name in FILES.items()}
    values = lists['password']
    n = len(values)
    pct = lambda count: f'{100 * count / n:.1f}%'
    lines = ['# Beeswax — generated statistics', '',
             'Generated with `python tools/beeswax.py stats`. All percentages describe **unique published passwords**, not login attempts.', '',
             f'- **Passwords:** {n:,} unique', f'- **Usernames:** {len(lists["username"]):,} unique', '',
             '## Password length', '', '| Length | Count | Share |', '|---|---:|---:|']
    for low, high, label in [(1,4,'1–4'),(5,6,'5–6'),(7,8,'7–8'),(9,10,'9–10'),(11,12,'11–12'),(13,float('inf'),'13+')]:
        count = sum(low <= len(x) <= high for x in values)
        lines.append(f'| {label} | {count:,} | {pct(count)} |')
    lines += ['', f'Median: **{statistics.median(map(len,values)):g}** characters. Range: **{min(map(len,values))}–{max(map(len,values))}** characters.', '',
              '## Password composition', '', '| Property | Count | Share |', '|---|---:|---:|']
    predicates = [('8 characters or fewer',lambda x:len(x)<=8),('Longer than 10 characters',lambda x:len(x)>10),
                  ('Digits only',str.isdigit),('Letters only',str.isalpha),('Lowercase letters only',lambda x:x.isalpha() and x.islower()),
                  ('Letters and digits, both present',lambda x:x.isalnum() and any(c.isalpha() for c in x) and any(c.isdigit() for c in x)),
                  ('Contains a special character',lambda x:any(not c.isalnum() for c in x)),
                  ('Contains an ASCII year (19xx / 20xx)',lambda x:bool(re.search(r'(?:19|20)[0-9]{2}',x)))]
    for label, predicate in predicates:
        count = sum(map(predicate,values)); lines.append(f'| {label} | {count:,} | {pct(count)} |')
    lines += ['', '## Definitions and limits', '',
              '- Length counts Unicode code points. Letter, digit and alphanumeric tests use Python Unicode predicates.',
              '- Special means any non-alphanumeric character, including spaces. Categories overlap.',
              '- Values are case-sensitive. Leading/trailing spaces are preserved.',
              '- Unique-entry statistics cannot establish traffic shares, successful compromises, or attacker intent.',
              '- The existing list order is inherited; frequency counts are unavailable for this snapshot.', '',
              '## File integrity', '', '| File | SHA-256 |', '|---|---|']
    for name in FILES.values():
        lines.append(f'| `{name}` | `{hashlib.sha256((root/name).read_bytes()).hexdigest()}` |')
    return '\n'.join(lines) + '\n'


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError('missing timestamp')
    dt = datetime.fromisoformat(value.replace('Z','+00:00'))
    if dt.tzinfo is None:
        raise ValueError('timestamp requires timezone')
    return dt.astimezone(timezone.utc).isoformat().replace('+00:00','Z')


def build(inputs, out, exclusions):
    if out.exists() and any(out.iterdir()):
        raise ValueError('Candidate output directory must be empty; use a new directory')
    out.mkdir(parents=True, exist_ok=True)
    records = {kind: {} for kind in FILES}
    audit = Counter()
    seen = set()
    for path in inputs:
        with path.open(encoding='utf-8') as stream:
            for line in stream:
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                    if not isinstance(event, dict):
                        raise ValueError('not object')
                except (ValueError, TypeError):
                    audit['malformed_json'] += 1; continue
                if event.get('eventid') not in ('cowrie.login.failed','cowrie.login.success'):
                    audit['non_login_events'] += 1; continue
                # Conservative exact-record deduplication, including sensor/session/timestamp fields.
                fingerprint = hashlib.sha256(json.dumps(event, sort_keys=True, ensure_ascii=True).encode()).digest()
                if fingerprint in seen:
                    audit['duplicate_records'] += 1; continue
                seen.add(fingerprint)
                try:
                    ts = timestamp(event.get('timestamp'))
                    source = str(ipaddress.ip_address(event['src_ip']))
                    sensor = event['sensor']
                    if not isinstance(sensor,str) or not sensor:
                        raise ValueError('missing sensor')
                except (ValueError, KeyError, TypeError):
                    audit['missing_or_invalid_metadata'] += 1; continue
                transport = str(event.get('protocol','unknown')).lower()
                transport = transport if transport in ('ssh','telnet') else 'unknown'
                audit['eligible_login_events'] += 1
                for kind in FILES:
                    value, reason = clean(event.get(kind), exclusions)
                    if reason:
                        audit[f'{kind}_excluded_{reason}'] += 1; continue
                    row = records[kind].setdefault(value, {'count':0,'first':ts,'last':ts,'sources':set(),'sensors':set(),'protocols':Counter()})
                    row['count'] += 1
                    # Compare actual instants, including variable fractional precision.
                    row['first'] = min((row['first'],ts), key=lambda s:datetime.fromisoformat(s.replace('Z','+00:00')))
                    row['last'] = max((row['last'],ts), key=lambda s:datetime.fromisoformat(s.replace('Z','+00:00')))
                    row['sources'].add(source); row['sensors'].add(sensor); row['protocols'][transport] += 1
    if not any(records.values()):
        raise ValueError('No publishable candidates; check input and required metadata')
    for kind, name in FILES.items():
        ordered = sorted(records[kind], key=lambda v:(-records[kind][v]['count'], v))
        (out/name).write_text(''.join(v+'\n' for v in ordered), encoding='utf-8', newline='\n')
        with (out/f'{kind}_metadata.csv').open('w', encoding='utf-8', newline='') as stream:
            writer = csv.writer(stream, lineterminator='\n')
            writer.writerow(['value','attempt_count','first_seen_utc','last_seen_utc','distinct_sources','distinct_sensors','ssh_attempts','telnet_attempts','unknown_protocol_attempts'])
            for value in ordered:
                row = records[kind][value]
                writer.writerow([value,row['count'],row['first'],row['last'],len(row['sources']),len(row['sensors']),*[row['protocols'][p] for p in ('ssh','telnet','unknown')]])
    # Aggregate counters only: no paths, raw identifiers, or rejected credentials.
    (out/'build_audit.json').write_text(json.dumps(dict(sorted(audit.items())),indent=2)+'\n',encoding='utf-8')
    return audit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    for command in ('validate','stats'):
        p = sub.add_parser(command); p.add_argument('--root',type=Path,default=ROOT)
        if command == 'stats': p.add_argument('--check',action='store_true')
    p = sub.add_parser('build',help='Produce LOCAL candidates; manual privacy review required before publishing')
    p.add_argument('inputs',nargs='+',type=Path)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--exclude-file',type=Path,required=True,help='Private UTF-8 file of literal substrings to exclude (one per line)')
    args = parser.parse_args()
    try:
        if args.command == 'build':
            if args.out.resolve() == ROOT:
                raise ValueError('Use a separate candidate directory, not the repository root')
            exclusions = [x for x in args.exclude_file.read_text(encoding='utf-8').splitlines() if x]
            audit = build(args.inputs,args.out,exclusions)
            print(json.dumps(dict(audit),indent=2)); print('Candidates only. Review for private identifiers, residual noise, and ambiguous escapes before publication.')
        else:
            for kind,name in FILES.items():
                values = read_list(args.root/name)
                print(f'{name}: {len(values):,} unique entries; {sum(x != x.strip() for x in values)} with edge whitespace (preserved)')
            if args.command == 'stats':
                content = stats(args.root); target = args.root/'stats.md'
                if args.check:
                    if not target.exists() or target.read_text(encoding='utf-8') != content:
                        raise ValueError('stats.md is stale; run the stats command')
                else: target.write_text(content,encoding='utf-8',newline='\n')
    except (OSError,ValueError) as exc:
        parser.exit(1, f'Error: {exc}\n')

if __name__ == '__main__':
    main()
