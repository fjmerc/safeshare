#!/usr/bin/env python3
"""Independent checks for stripped PDFs (used by pdf-metadata.test.js).

Doesn't share code with the stripper: finds every stream with a regex,
inflates the Flate ones with zlib, and counts the sentinel (as text and as
hex) and the fixture dates across the raw file and all inflated data. Also
reports leftover XMP packets (other than the empty one the stripper writes) and whether the visible text survived.

    python3 check_pdf.py FILE...
"""
import json
import re
import sys
import zlib

S = b'ZQX7731'
# The empty packet the stripper writes in place of XMP
EMPTY_XMP = (b'<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?><x:xmpmeta xmlns:x="adobe:ns:meta/">'
             b'<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"/></x:xmpmeta><?xpacket end="w"?>')
SH = S.hex().encode()


def count(data):
    return data.count(S) + data.lower().count(SH)


def check(path):
    raw = open(path, 'rb').read()
    inflated = []
    for m in re.finditer(rb'stream\r?\n', raw):
        body = raw[m.end():m.end() + 10_000_000]
        try:
            inflated.append(zlib.decompressobj().decompress(body))
        except zlib.error:
            pass
    allbytes = raw + b''.join(inflated)
    return {
        'file': path,
        'sentinel': count(allbytes),
        'dates': allbytes.count(b'D:2031') + allbytes.count(b'2031-02-03'),
        'xmp': len(re.findall(rb'<x:xmpmeta|<\?xpacket begin', allbytes.replace(EMPTY_XMP, b''))),
        'visible': b'Visible PDF text' in allbytes,
        'size': len(raw),
    }


if __name__ == '__main__':
    for p in sys.argv[1:]:
        print(json.dumps(check(p)))
