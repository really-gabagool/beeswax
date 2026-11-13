import csv
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('beeswax', Path(__file__).resolve().parents[1]/'tools/beeswax.py')
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)

class ProcessingTests(unittest.TestCase):
    def test_clean_preserves_credentials(self):
        self.assertEqual(b.clean(' pass '), (' pass ',None))
        self.assertEqual(b.clean(r'\xd0\xb9'), ('й',None))
        for value in ['bad\x00', 'bad\t', 'bad\u2028line', r'\xff', 'GET / HTTP/1.1', '192.0.2.1']:
            self.assertIsNone(b.clean(value)[0])
        self.assertIsNone(b.clean('private-host-admin',['private-host'])[0])
        self.assertEqual(b.clean('Admin'), ('Admin',None))

    def test_aggregation_overlap_and_privacy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); source = root/'events.json'; out = root/'out'
            e = dict(eventid='cowrie.login.failed',timestamp='2026-11-12T01:00:00Z',src_ip='192.0.2.1',sensor='private-sensor',protocol='ssh',username='root',password=' pass ')
            later = dict(e,timestamp='2026-11-12T01:00:00.5Z',src_ip='192.0.2.2',sensor='other-sensor',protocol='telnet')
            invalid = dict(e,timestamp='2026-11-12T01:00:00')
            noise = dict(e,password='GET / HTTP/1.1',timestamp='2026-11-12T02:00:00Z',protocol='other')
            source.write_text('\n'.join(map(json.dumps,[e,e,later,invalid,noise]))+'\n{bad\n',encoding='utf-8')
            audit = b.build([source,source],out,[])
            self.assertEqual(audit['malformed_json'],2)
            self.assertEqual(audit['eligible_login_events'],3)
            self.assertEqual((out/'captured_passwords.txt').read_text(),' pass \n')
            with (out/'password_metadata.csv').open(newline='') as stream:
                row = next(csv.DictReader(stream))
            self.assertEqual(row['attempt_count'],'2')
            self.assertEqual(row['distinct_sources'],'2')
            self.assertEqual(row['distinct_sensors'],'2')
            self.assertEqual(row['first_seen_utc'],'2026-11-12T01:00:00Z')
            self.assertEqual(row['last_seen_utc'],'2026-11-12T01:00:00.500000Z')
            self.assertEqual(row['ssh_attempts'],'1')
            self.assertEqual(row['telnet_attempts'],'1')
            for path in out.iterdir():
                text = path.read_text()
                self.assertNotIn('192.0.2.',text)
                self.assertNotIn('private-sensor',text)

    def test_counts_sorting_unknown_protocol_and_missing_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); source=root/'events.json'; out=root/'out'
            base=dict(eventid='cowrie.login.success',src_ip='192.0.2.1',sensor='sensor',username='root')
            events=[dict(base,password=value,timestamp=f'2026-11-12T00:00:0{i}Z') for i,value in enumerate(['z','a','z','b'])]
            events.append(dict(events[0],sensor=None))
            events.append(dict(events[0],eventid='cowrie.command.input'))
            source.write_text('\n'.join(map(json.dumps,events)),encoding='utf-8')
            audit=b.build([source],out,[])
            self.assertEqual((out/'captured_passwords.txt').read_text(),'z\na\nb\n')
            self.assertEqual(audit['missing_or_invalid_metadata'],1)
            self.assertEqual(audit['non_login_events'],1)
            with (out/'password_metadata.csv').open(newline='') as stream:
                rows=list(csv.DictReader(stream))
            self.assertEqual(rows[0]['unknown_protocol_attempts'],'2')
            with self.assertRaises(ValueError): b.build([source],out,[])

    def test_lists_reject_duplicates_and_crlf(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'list.txt'
            for data in [b'a\na\n',b'a\r\n',b'a\n\n',b'a',b'a\x00\n']:
                p.write_bytes(data)
                with self.assertRaises(ValueError): b.read_list(p)
            p.write_bytes(b' a \n')
            self.assertEqual(b.read_list(p),[' a '])

    def test_repository_links(self):
        import re
        for name in ['README.md','METHODOLOGY.md','CONTRIBUTING.md']:
            for link in re.findall(r'\]\(([^)]+)\)',(b.ROOT/name).read_text()):
                if not link.startswith(('https:','http:','#')):
                    self.assertTrue((b.ROOT/link).exists(),link)

if __name__ == '__main__': unittest.main()
