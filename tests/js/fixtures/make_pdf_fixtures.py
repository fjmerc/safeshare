#!/usr/bin/env python3
"""Generate the PDF fixtures for tests/js/pdf-metadata.test.js.

sample.pdf is built by hand (classic xref table) and plants the sentinel
ZQX7731 in every metadata location the browser stripper is meant to clear:
the Info dictionary (as literal, hex and indirect strings), an uncompressed
document XMP stream, a Flate-compressed image XMP stream, the trailer /ID,
a comment annotation's author and dates, and the EXIF of an embedded JPEG.
An incremental update then replaces the Info dictionary, so the original
stays in the file as an older revision. Dates use 2031-02-03.

sample-attach.pdf adds a file attachment, which can't be cleaned and must be
reported. The qpdf variants (object streams, linearized) are made with
make_pdf_variants.sh, which needs qpdf.

    python3 tests/js/fixtures/make_pdf_fixtures.py
"""
import os
import zlib

S = b'ZQX7731'
HERE = os.path.dirname(os.path.abspath(__file__))


def jpeg_with_exif():
    jpg = open(os.path.join(HERE, 'image.jpg'), 'rb').read()
    exif = b'Exif\x00\x00II*\x00\x08\x00\x00\x00\x00\x00' + b'Camera owner ' + S
    app1 = b'\xff\xe1' + (len(exif) + 2).to_bytes(2, 'big') + exif
    return jpg[:2] + app1 + jpg[2:]


def xmp(extra=b''):
    return (b'<?xpacket begin="\xef\xbb\xbf" id="W5M0MpCehiHzreSzNTczkc9d"?>\n'
            b'<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
            b'<rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/">'
            b'<dc:creator><rdf:Seq><rdf:li>' + S + extra + b'</rdf:li></rdf:Seq></dc:creator>'
            b'</rdf:Description></rdf:RDF></x:xmpmeta>\n' + b' ' * 200 + b'\n<?xpacket end="w"?>')


def stream(d, body, compress=False):
    if compress:
        body = zlib.compress(body, 9)
        d += b' /Filter /FlateDecode'
    return b'<< ' + d + b' /Length %d >>\nstream\n' % len(body) + body + b'\nendstream'


def build(attach=False):
    content = (b'BT /F1 24 Tf 72 720 Td (Visible PDF text) Tj ET\n'
               b'q 64 0 0 64 72 600 cm /Im1 Do Q\n')
    jpg = jpeg_with_exif()
    objs = {
        1: b'<< /Type /Catalog /Pages 2 0 R /Metadata 6 0 R' + (b' /Names << /EmbeddedFiles 13 0 R >>' if attach else b'') + b' >>',
        2: b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
        3: (b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R '
            b'/Resources << /Font << /F1 5 0 R >> /XObject << /Im1 7 0 R >> >> /Annots [8 0 R] >>'),
        4: stream(b'', content),
        5: b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
        6: stream(b'/Type /Metadata /Subtype /XML', xmp(b' document')),
        7: stream(b'/Type /XObject /Subtype /Image /Width 32 /Height 32 /ColorSpace /DeviceRGB '
                  b'/BitsPerComponent 8 /Filter /DCTDecode /Metadata 10 0 R', jpg).replace(b' /Length', b' /Length', 1),
        8: (b'<< /Type /Annot /Subtype /Text /Rect [300 700 320 720] /Contents (Visible note) '
            b'/T (Reviewer ' + S + b') /M (D:20310203040506Z) /CreationDate (D:20310203040506Z) '
            b'/NM (annot-1) /Popup 12 0 R >>'),
        9: (b'<< /Author (Author ' + S + b') /Creator <' + (b'Creator ' + S).hex().encode() + b'> '
            b'/Producer 11 0 R /Title (Title ' + S + b') /CreationDate (D:20310203040506Z) '
            b'/ModDate (D:20310203040506Z) /Custom (Custom \\(' + S + b'\\)) /Trapped /False >>'),
        10: stream(b'/Type /Metadata /Subtype /XML', xmp(b' image'), compress=True),
        11: b'(Producer ' + S + b')',
        12: b'<< /Type /Annot /Subtype /Popup /Rect [320 600 500 700] /Parent 8 0 R >>',
    }
    if attach:
        objs[13] = b'<< /Names [(notes.txt) 14 0 R] >>'
        objs[14] = b'<< /Type /Filespec /F (notes.txt) /EF << /F 15 0 R >> >>'
        objs[15] = stream(b'/Type /EmbeddedFile /Params << /ModDate (D:20310203040506Z) >>', b'attached ' + S)

    out = bytearray(b'%PDF-1.7\n%\xe2\xe3\xcf\xd3\n')
    offsets = {}
    for n in sorted(objs):
        offsets[n] = len(out)
        out += b'%d 0 obj\n' % n + objs[n] + b'\nendobj\n'
    size = max(objs) + 1
    xref = len(out)
    out += b'xref\n0 %d\n0000000000 65535 f \n' % size
    for n in range(1, size):
        out += b'%010d 00000 n \n' % offsets[n]
    ident = (b'ID ' + S).hex().encode()
    out += (b'trailer\n<< /Size %d /Root 1 0 R /Info 9 0 R /ID [<' % size + ident + b'> <' + ident + b'>] >>\n'
            b'startxref\n%d\n%%%%EOF\n' % xref)

    # Incremental update: a new Info dictionary; the old one stays as an older revision.
    first_xref = xref
    info_off = len(out)
    out += (b'9 0 obj\n<< /Author (Updated ' + S + b') /ModDate (D:20310203050506Z) >>\nendobj\n')
    xref = len(out)
    out += b'xref\n0 1\n0000000000 65535 f \n9 1\n%010d 00000 n \n' % info_off
    out += (b'trailer\n<< /Size %d /Root 1 0 R /Info 9 0 R /ID [<' % size + ident + b'> <' + ident + b'>] '
            b'/Prev %d >>\nstartxref\n%d\n%%%%EOF\n' % (first_xref, xref))
    return bytes(out)


if __name__ == '__main__':
    for name, attach in (('sample.pdf', False), ('sample-attach.pdf', True)):
        with open(os.path.join(HERE, name), 'wb') as f:
            f.write(build(attach))
        print('wrote', name)
