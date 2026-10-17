#!/usr/bin/env python3
"""Independent checks for stripped Office files (used by office-metadata.test.js).

Uses Python's own zip and XML parsers, not the stripper's. For each file it
prints one JSON object: sentinel and fixture-date counts across the raw bytes
and every decompressed entry (ASCII and UTF-16LE), plus zip-level leftovers
(entry times, extra fields, comments, creator OS), XML well-formedness,
leftover rsid attributes and whether the visible text survived.

    python3 check_office.py FILE...
"""
import json
import re
import sys
import zipfile
from xml.dom import minidom

S = b'ZQX7731'
DATE = b'2031-02-03'
VISIBLE = (b'Visible body text', b'Visible cell', b'Visible slide text')


def count(data, needle):
    return data.count(needle) + data.count(needle.decode().encode('utf-16-le'))


def check(path):
    raw = open(path, 'rb').read()
    res = {'file': path, 'raw_sentinel': count(raw, S), 'entry_sentinel': 0, 'entry_date': 0,
           'zip_times': 0, 'zip_extra': 0, 'zip_comments': 0, 'unix_creator': 0, 'xml_errors': [],
           'rsid_attrs': 0, 'visible': False, 'entries': [], 'bad_crc': None}
    with zipfile.ZipFile(path) as z:
        res['bad_crc'] = z.testzip()
        res['zip_comments'] += len(z.comment) > 0
        for info in z.infolist():
            data = z.read(info)
            res['entries'].append(info.filename)
            res['entry_sentinel'] += count(data, S)
            res['entry_date'] += count(data, DATE)
            res['zip_times'] += info.date_time != (1980, 1, 1, 0, 0, 0)
            res['zip_extra'] += len(info.extra) > 0
            res['zip_comments'] += len(info.comment) > 0
            res['unix_creator'] += info.create_system == 3 or info.external_attr != 0
            if info.filename.endswith(('.xml', '.rels')):
                try:
                    minidom.parseString(data)
                except Exception as e:  # noqa: BLE001 - report any parse failure
                    res['xml_errors'].append('%s: %s' % (info.filename, e))
                res['rsid_attrs'] += len(re.findall(rb'\s\w+:rsid\w*=', data))
            if any(v in data for v in VISIBLE):
                res['visible'] = True
    return res


if __name__ == '__main__':
    for p in sys.argv[1:]:
        print(json.dumps(check(p)))
