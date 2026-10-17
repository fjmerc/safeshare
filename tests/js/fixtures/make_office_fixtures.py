#!/usr/bin/env python3
"""Generate the Office fixtures for tests/js/office-metadata.test.js.

Each file plants the sentinel ZQX7731 in every metadata location the browser
stripper is meant to clear: document properties, custom XML, comment and
tracked-change authors, people/persons lists, the Excel save path and
shared-workbook users, a template path, printer names, an embedded image's
text chunk, and the zip's own entry/archive comments and extra fields. Dates
use 2031-02-03 so their removal can be checked too.

Hand-built because no Office suite is available here; the stripped and
unstripped files are also opened with LibreOffice (see the test file).

    python3 tests/js/fixtures/make_office_fixtures.py
"""
import os
import struct
import zipfile
import zlib

S = 'ZQX7731'
DATE = '2031-02-03T04:05:06Z'
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, '..', '..', '..'))
DECL = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'

CT_HEAD = DECL + ('<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                  '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                  '<Default Extension="xml" ContentType="application/xml"/>'
                  '<Default Extension="png" ContentType="image/png"/>'
                  '<Default Extension="bin" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.printerSettings"/>')
OV = '<Override PartName="/%s" ContentType="%s"/>'
CORE_CT = 'application/vnd.openxmlformats-package.core-properties+xml'
APP_CT = 'application/vnd.openxmlformats-officedocument.extended-properties+xml'
CUSTOM_CT = 'application/vnd.openxmlformats-officedocument.custom-properties+xml'
R = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships'
PKG_R = 'http://schemas.openxmlformats.org/package/2006/relationships'


def rels(items):
    body = ''.join('<Relationship Id="%s" Type="%s" Target="%s"%s/>' % i for i in items)
    return DECL + '<Relationships xmlns="%s">%s</Relationships>' % (PKG_R, body)


def root_rels(main_type, main_target):
    return rels([
        ('rId1', R + '/' + main_type, main_target, ''),
        ('rId2', PKG_R + '/metadata/core-properties', 'docProps/core.xml', ''),
        ('rId3', R + '/extended-properties', 'docProps/app.xml', ''),
        ('rId4', R + '/custom-properties', 'docProps/custom.xml', ''),
    ])


CORE = DECL + ('<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
               'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
               'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
               '<dc:title>Title %s</dc:title><dc:creator>Creator %s</dc:creator>'
               '<cp:lastModifiedBy>Editor %s</cp:lastModifiedBy>'
               '<dcterms:created xsi:type="dcterms:W3CDTF">%s</dcterms:created>'
               '</cp:coreProperties>') % (S, S, S, DATE)
APP = DECL + ('<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
              '<Template>C:\\Users\\%s\\Normal.dotm</Template><Company>Company %s</Company>'
              '<Manager>Manager %s</Manager></Properties>') % (S, S, S)
CUSTOM = DECL + ('<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties" '
                 'xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">'
                 '<property fmtid="{D5CDD505-2E9C-101B-9397-08002B2CF9AE}" pid="2" name="Owner">'
                 '<vt:lpwstr>%s@example.org</vt:lpwstr></property></Properties>') % S
CUSTOM_ITEM = DECL + '<p:properties xmlns:p="urn:x"><Owner><DisplayName>%s</DisplayName></Owner></p:properties>' % S


def png_with_text():
    with open(os.path.join(ROOT, 'internal/static/web/assets/favicon-16x16.png'), 'rb') as f:
        png = f.read()
    data = b'Author\x00' + S.encode()
    chunk = struct.pack('>I', len(data)) + b'tEXt' + data + struct.pack('>I', zlib.crc32(b'tEXt' + data))
    return png[:33] + chunk + png[33:]  # after the IHDR chunk


def printer_settings():
    # DEVMODEW: dmDeviceName is the first 32 UTF-16 characters
    name = ('Printer ' + S).encode('utf-16-le').ljust(64, b'\x00')
    return name + b'\x01\x04' + b'\x00' * 154


def write(path, parts):
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as z:
        z.comment = ('archive comment ' + S).encode()
        for name, data in parts:
            info = zipfile.ZipInfo(name, date_time=(2031, 2, 3, 4, 5, 6))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.comment = ('entry comment ' + S).encode()
            # A private extra field (header id 0xCAFE) carrying the sentinel
            payload = S.encode()
            info.extra = struct.pack('<HH', 0xCAFE, len(payload)) + payload
            info.create_system = 3  # Unix
            info.external_attr = 0o100644 << 16
            z.writestr(info, data.encode() if isinstance(data, str) else data)


def common(ct_main):
    return [
        ('docProps/core.xml', CORE),
        ('docProps/app.xml', APP),
        ('docProps/custom.xml', CUSTOM),
        ('customXml/item1.xml', CUSTOM_ITEM),
    ], (OV % ('docProps/core.xml', CORE_CT) + OV % ('docProps/app.xml', APP_CT) +
        OV % ('docProps/custom.xml', CUSTOM_CT) + ct_main)


W = 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'
W15 = 'http://schemas.microsoft.com/office/word/2012/wordml'
W14 = 'http://schemas.microsoft.com/office/word/2010/wordml'
WP = 'http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing'


def docx():
    doc = DECL + (
        '<w:document xmlns:w="%s" xmlns:r="%s"><w:body>'
        '<w:p w:rsidR="00A1B2C3" w:rsidRDefault="00A1B2C3"><w:r><w:t xml:space="preserve">Visible body text. </w:t></w:r>'
        '<w:ins w:id="1" w:author="Inserter %s" w:date="%s"><w:r><w:t>Inserted.</w:t></w:r></w:ins>'
        '<w:commentRangeStart w:id="0"/><w:r><w:t>Commented.</w:t></w:r><w:commentRangeEnd w:id="0"/>'
        '<w:r><w:commentReference w:id="0"/></w:r></w:p>'
        '<w:sectPr w:rsidR="00A1B2C3"/></w:body></w:document>') % (W, R, S, DATE)
    comments = DECL + ('<w:comments xmlns:w="%s"><w:comment w:id="0" w:author="Commenter %s" w:date="%s" w:initials="%s">'
                       '<w:p><w:r><w:t>Comment text</w:t></w:r></w:p></w:comment></w:comments>') % (W, S, DATE, S)
    people = DECL + ('<w15:people xmlns:w15="%s"><w15:person w15:author="Person %s">'
                     '<w15:presenceInfo w15:providerId="AD" w15:userId="S-1-5-21-%s"/></w15:person></w15:people>') % (W15, S, S)
    settings = DECL + ('<w:settings xmlns:w="%s" xmlns:w14="%s" xmlns:w15="%s" xmlns:r="%s">'
                       '<w:attachedTemplate r:id="rId1"/>'
                       '<w:rsids><w:rsidRoot w:val="00A1B2C3"/><w:rsid w:val="00A1B2C3"/></w:rsids>'
                       '<w14:docId w14:val="1A2B3C4D"/><w15:docId w15:val="{A1B2C3D4-0000-0000-0000-000000000000}"/>'
                       '</w:settings>') % (W, W14, W15, R)
    settings_rels = rels([('rId1', R + '/attachedTemplate',
                           'file:///C:/Users/%s/AppData/Roaming/Microsoft/Templates/Normal.dotm' % S,
                           ' TargetMode="External"')])
    doc_rels = rels([
        ('rId1', R + '/comments', 'comments.xml', ''),
        ('rId2', R + '/settings', 'settings.xml', ''),
        ('rId3', 'http://schemas.microsoft.com/office/2011/relationships/people', 'people.xml', ''),
        ('rId4', R + '/image', 'media/image1.png', ''),
    ])
    WML = 'application/vnd.openxmlformats-officedocument.wordprocessingml.'
    parts, ct = common(OV % ('word/document.xml', WML + 'document.main+xml') +
                       OV % ('word/comments.xml', WML + 'comments+xml') +
                       OV % ('word/settings.xml', WML + 'settings+xml') +
                       OV % ('word/people.xml', WML + 'people+xml'))
    return [('[Content_Types].xml', CT_HEAD + ct + '</Types>'),
            ('_rels/.rels', root_rels('officeDocument', 'word/document.xml'))] + parts + [
        ('word/document.xml', doc), ('word/_rels/document.xml.rels', doc_rels),
        ('word/comments.xml', comments), ('word/people.xml', people),
        ('word/settings.xml', settings), ('word/_rels/settings.xml.rels', settings_rels),
        ('word/media/image1.png', png_with_text()),
    ]


X = 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'


def xlsx():
    workbook = DECL + (
        '<workbook xmlns="%s" xmlns:r="%s" xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006" '
        'xmlns:x15ac="http://schemas.microsoft.com/office/spreadsheetml/2010/11/ac" '
        'xmlns:xr="http://schemas.microsoft.com/office/spreadsheetml/2014/revision" mc:Ignorable="x15ac xr">'
        '<fileSharing userName="Sharer %s"/>'
        '<mc:AlternateContent><mc:Choice Requires="x15ac"><x15ac:absPath url="C:\\Users\\%s\\Documents\\"/></mc:Choice></mc:AlternateContent>'
        '<xr:revisionPtr revIDLastSave="0" documentId="13_ncr:1_{%s}"/>'
        '<sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>') % (X, R, S, S, S)
    sheet = DECL + ('<worksheet xmlns="%s"><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>Visible cell</t></is></c>'
                    '</row></sheetData><pageSetup paperSize="9" r:id="rId2" xmlns:r="%s"/></worksheet>') % (X, R)
    comments = DECL + ('<comments xmlns="%s"><authors><author>Author %s</author></authors><commentList>'
                       '<comment ref="A1" authorId="0"><text><t>Note</t></text></comment></commentList></comments>') % (X, S)
    persons = DECL + ('<personList xmlns="http://schemas.microsoft.com/office/spreadsheetml/2018/threadedcomments">'
                      '<person displayName="Person %s" id="{00000000-0000-0000-0000-000000000001}" userId="%s@example.org" '
                      'providerId="AD"/></personList>') % (S, S)
    threaded = DECL + ('<ThreadedComments xmlns="http://schemas.microsoft.com/office/spreadsheetml/2018/threadedcomments">'
                       '<threadedComment ref="A1" dT="%s" personId="{00000000-0000-0000-0000-000000000001}" '
                       'id="{00000000-0000-0000-0000-000000000002}"><text>Thread</text></threadedComment></ThreadedComments>') % DATE
    usernames = DECL + ('<users xmlns="%s" count="1"><userInfo guid="{00000000-0000-0000-0000-000000000003}" '
                        'name="Reviser %s" id="1" dateTime="%s"/></users>') % (X, S, DATE)
    wb_rels = rels([('rId1', R + '/worksheet', 'worksheets/sheet1.xml', '')])
    sheet_rels = rels([('rId1', R + '/comments', '../comments1.xml', ''),
                       ('rId2', R + '/printerSettings', '../printerSettings/printerSettings1.bin', '')])
    SML = 'application/vnd.openxmlformats-officedocument.spreadsheetml.'
    parts, ct = common(OV % ('xl/workbook.xml', SML + 'sheet.main+xml') +
                       OV % ('xl/worksheets/sheet1.xml', SML + 'worksheet+xml') +
                       OV % ('xl/comments1.xml', SML + 'comments+xml'))
    return [('[Content_Types].xml', CT_HEAD + ct + '</Types>'),
            ('_rels/.rels', root_rels('officeDocument', 'xl/workbook.xml'))] + parts + [
        ('xl/workbook.xml', workbook), ('xl/_rels/workbook.xml.rels', wb_rels),
        ('xl/worksheets/sheet1.xml', sheet), ('xl/worksheets/_rels/sheet1.xml.rels', sheet_rels),
        ('xl/comments1.xml', comments), ('xl/persons/person.xml', persons),
        ('xl/threadedComments/threadedComment1.xml', threaded),
        ('xl/revisions/userNames.xml', usernames),
        ('xl/printerSettings/printerSettings1.bin', printer_settings()),
    ]


P = 'http://schemas.openxmlformats.org/presentationml/2006/main'
A = 'http://schemas.openxmlformats.org/drawingml/2006/main'


def pptx():
    pres = DECL + ('<p:presentation xmlns:p="%s" xmlns:r="%s" xmlns:a="%s">'
                   '<p:sldMasterIdLst><p:sldMasterId id="2147483648" r:id="rId1"/></p:sldMasterIdLst>'
                   '<p:sldIdLst><p:sldId id="256" r:id="rId2"/></p:sldIdLst>'
                   '<p:sldSz cx="9144000" cy="6858000"/><p:notesSz cx="6858000" cy="9144000"/></p:presentation>') % (P, R, A)
    sp_tree = ('<p:cSld><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>'
               '<p:grpSpPr/>%s</p:spTree></p:cSld>')
    text_box = ('<p:sp><p:nvSpPr><p:cNvPr id="2" name="Text"/><p:cNvSpPr txBox="1"/><p:nvPr/></p:nvSpPr>'
                '<p:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="5000000" cy="1000000"/></a:xfrm>'
                '<a:prstGeom prst="rect"><a:avLst/></a:prstGeom></p:spPr>'
                '<p:txBody><a:bodyPr/><a:p><a:r><a:t>Visible slide text</a:t></a:r></a:p></p:txBody></p:sp>')
    slide = DECL + ('<p:sld xmlns:p="%s" xmlns:r="%s" xmlns:a="%s">' % (P, R, A)) + sp_tree % text_box + '</p:sld>'
    layout = DECL + ('<p:sldLayout xmlns:p="%s" xmlns:r="%s" xmlns:a="%s">' % (P, R, A)) + sp_tree % '' + '</p:sldLayout>'
    theme = DECL + ('<a:theme xmlns:a="%s" name="T"><a:themeElements>'
                    '<a:clrScheme name="C"><a:dk1><a:srgbClr val="000000"/></a:dk1><a:lt1><a:srgbClr val="FFFFFF"/></a:lt1>'
                    '<a:dk2><a:srgbClr val="000000"/></a:dk2><a:lt2><a:srgbClr val="FFFFFF"/></a:lt2>'
                    '<a:accent1><a:srgbClr val="4472C4"/></a:accent1><a:accent2><a:srgbClr val="ED7D31"/></a:accent2>'
                    '<a:accent3><a:srgbClr val="A5A5A5"/></a:accent3><a:accent4><a:srgbClr val="FFC000"/></a:accent4>'
                    '<a:accent5><a:srgbClr val="5B9BD5"/></a:accent5><a:accent6><a:srgbClr val="70AD47"/></a:accent6>'
                    '<a:hlink><a:srgbClr val="0563C1"/></a:hlink><a:folHlink><a:srgbClr val="954F72"/></a:folHlink></a:clrScheme>'
                    '<a:fontScheme name="F"><a:majorFont><a:latin typeface="DejaVu Sans"/><a:ea typeface=""/><a:cs typeface=""/></a:majorFont>'
                    '<a:minorFont><a:latin typeface="DejaVu Sans"/><a:ea typeface=""/><a:cs typeface=""/></a:minorFont></a:fontScheme>'
                    '<a:fmtScheme name="M"><a:fillStyleLst><a:solidFill><a:schemeClr val="phClr"/></a:solidFill>'
                    '<a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:fillStyleLst>'
                    '<a:lnStyleLst><a:ln/><a:ln/><a:ln/></a:lnStyleLst><a:effectStyleLst><a:effectStyle><a:effectLst/></a:effectStyle>'
                    '<a:effectStyle><a:effectLst/></a:effectStyle><a:effectStyle><a:effectLst/></a:effectStyle></a:effectStyleLst>'
                    '<a:bgFillStyleLst><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:solidFill><a:schemeClr val="phClr"/></a:solidFill>'
                    '<a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:bgFillStyleLst></a:fmtScheme>'
                    '</a:themeElements></a:theme>') % A
    master = DECL + ('<p:sldMaster xmlns:p="%s" xmlns:r="%s" xmlns:a="%s">' % (P, R, A)) + sp_tree % '' + (
        '<p:clrMap bg1="lt1" tx1="dk1" bg2="lt2" tx2="dk2" accent1="accent1" accent2="accent2" accent3="accent3" '
        'accent4="accent4" accent5="accent5" accent6="accent6" hlink="hlink" folHlink="folHlink"/>'
        '<p:sldLayoutIdLst><p:sldLayoutId id="2147483649" r:id="rId1"/></p:sldLayoutIdLst></p:sldMaster>')
    authors = DECL + ('<p:cmAuthorLst xmlns:p="%s"><p:cmAuthor id="0" name="Author %s" initials="%s" lastIdx="1" clrIdx="0"/>'
                      '</p:cmAuthorLst>') % (P, S, S)
    modern_authors = DECL + ('<p188:authorLst xmlns:p188="http://schemas.microsoft.com/office/powerpoint/2018/8/main">'
                             '<p188:author id="{00000000-0000-0000-0000-000000000004}" name="Modern %s" initials="%s" '
                             'userId="%s@example.org" providerId="AD"/></p188:authorLst>') % (S, S, S)
    comments = DECL + ('<p:cmLst xmlns:p="%s"><p:cm authorId="0" dt="%s" idx="1"><p:pos x="10" y="10"/>'
                       '<p:text>Slide comment</p:text></p:cm></p:cmLst>') % (P, DATE)
    PML = 'application/vnd.openxmlformats-officedocument.presentationml.'
    parts, ct = common(OV % ('ppt/presentation.xml', PML + 'presentation.main+xml') +
                       OV % ('ppt/slides/slide1.xml', PML + 'slide+xml') +
                       OV % ('ppt/slideLayouts/slideLayout1.xml', PML + 'slideLayout+xml') +
                       OV % ('ppt/slideMasters/slideMaster1.xml', PML + 'slideMaster+xml') +
                       OV % ('ppt/theme/theme1.xml', 'application/vnd.openxmlformats-officedocument.theme+xml') +
                       OV % ('ppt/commentAuthors.xml', PML + 'commentAuthors+xml') +
                       OV % ('ppt/comments/comment1.xml', PML + 'comments+xml'))
    return [('[Content_Types].xml', CT_HEAD + ct + '</Types>'),
            ('_rels/.rels', root_rels('officeDocument', 'ppt/presentation.xml'))] + parts + [
        ('ppt/presentation.xml', pres),
        ('ppt/_rels/presentation.xml.rels', rels([
            ('rId1', R + '/slideMaster', 'slideMasters/slideMaster1.xml', ''),
            ('rId2', R + '/slide', 'slides/slide1.xml', ''),
            ('rId3', R + '/theme', 'theme/theme1.xml', ''),
            ('rId4', R + '/commentAuthors', 'commentAuthors.xml', ''),
            ('rId5', 'http://schemas.microsoft.com/office/2018/10/relationships/authors', 'authors.xml', '')])),
        ('ppt/slides/slide1.xml', slide),
        ('ppt/slides/_rels/slide1.xml.rels', rels([
            ('rId1', R + '/slideLayout', '../slideLayouts/slideLayout1.xml', ''),
            ('rId2', R + '/comments', '../comments/comment1.xml', '')])),
        ('ppt/slideLayouts/slideLayout1.xml', layout),
        ('ppt/slideLayouts/_rels/slideLayout1.xml.rels', rels([('rId1', R + '/slideMaster', '../slideMasters/slideMaster1.xml', '')])),
        ('ppt/slideMasters/slideMaster1.xml', master),
        ('ppt/slideMasters/_rels/slideMaster1.xml.rels', rels([
            ('rId1', R + '/slideLayout', '../slideLayouts/slideLayout1.xml', ''),
            ('rId2', R + '/theme', '../theme/theme1.xml', '')])),
        ('ppt/theme/theme1.xml', theme),
        ('ppt/commentAuthors.xml', authors), ('ppt/authors.xml', modern_authors),
        ('ppt/comments/comment1.xml', comments),
    ]


if __name__ == '__main__':
    for name, build in (('sample.docx', docx), ('sample.xlsx', xlsx), ('sample.pptx', pptx)):
        write(os.path.join(HERE, name), build())
        print('wrote', name)
