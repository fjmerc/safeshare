// Tests for Office (docx/xlsx/pptx) metadata stripping in
// internal/static/web/assets/metadata-strip.js.
//
// The stripper runs under Node and in real Chromium and Firefox (Tor Browser
// is Firefox-based, and deflate-raw stream support is the part that differs
// between engines). Every output is then checked by fixtures/check_office.py,
// which uses Python's own zip and XML parsers rather than the stripper's: the
// sentinel planted in each metadata location (see make_office_fixtures.py)
// must be present in every input and absent from every output.
//
//   node tests/js/office-metadata.test.js
//
// Needs Node 22.2+, python3, and for the browser runs the globally installed
// playwright package with chromium and firefox (npm i -g playwright); set
// REQUIRE_BROWSERS=1 to fail instead of skipping when they're missing. OUT_DIR
// keeps the stripped files, e.g. to open them in LibreOffice. Exits non-zero on
// failure.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const repoRoot = path.resolve(__dirname, '..', '..');
const stripperPath = path.join(repoRoot, 'internal/static/web/assets/metadata-strip.js');
const fixtures = path.join(__dirname, 'fixtures');
const checker = path.join(fixtures, 'check_office.py');
const M = require(stripperPath);
const outDir = process.env.OUT_DIR || fs.mkdtempSync(path.join(os.tmpdir(), 'office-strip-'));
fs.mkdirSync(outDir, { recursive: true });

// Fixtures that must come out fully clean, and sample.docm, whose VBA project
// can't be cleaned and must be reported instead.
const CLEAN = ['sample.docx', 'sample.xlsx', 'sample.pptx', 'sample-dd.docx'];
const REQUIRE_BROWSERS = process.env.REQUIRE_BROWSERS === '1';
let failures = 0;
function check(name, ok, detail) {
    if (ok) {
        console.log('PASS ' + name);
    } else {
        failures++;
        console.log('FAIL ' + name + (detail ? ': ' + detail : ''));
    }
}

function inspect(files) {
    const out = execFileSync('python3', [checker, ...files]).toString().trim().split('\n');
    return out.map((l) => JSON.parse(l));
}

function u8(buf) { return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength); }

async function expectReject(name, promise, code) {
    try {
        await promise;
        check(name, false, 'resolved, expected ' + code);
    } catch (e) {
        check(name, e.code === code, 'got ' + e.code + ' (' + e.message + ')');
    }
}

// Build a minimal stored (uncompressed) zip with the given entries and flags.
function storedZip(entries, flags) {
    const parts = [];
    const central = [];
    let offset = 0;
    for (const [name, text] of entries) {
        const nameB = Buffer.from(name);
        const data = Buffer.from(text);
        const crc = zlibCrc(data);
        const local = Buffer.alloc(30);
        local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(20, 4); local.writeUInt16LE(flags || 0, 6);
        local.writeUInt32LE(crc, 14); local.writeUInt32LE(data.length, 18); local.writeUInt32LE(data.length, 22);
        local.writeUInt16LE(nameB.length, 26);
        const cd = Buffer.alloc(46);
        cd.writeUInt32LE(0x02014b50, 0); cd.writeUInt16LE(20, 4); cd.writeUInt16LE(20, 6); cd.writeUInt16LE(flags || 0, 8);
        cd.writeUInt32LE(crc, 16); cd.writeUInt32LE(data.length, 20); cd.writeUInt32LE(data.length, 24);
        cd.writeUInt16LE(nameB.length, 28); cd.writeUInt32LE(offset, 42);
        parts.push(local, nameB, data);
        central.push(cd, nameB);
        offset += 30 + nameB.length + data.length;
    }
    const cdBuf = Buffer.concat(central);
    const eocd = Buffer.alloc(22);
    eocd.writeUInt32LE(0x06054b50, 0); eocd.writeUInt16LE(entries.length, 8); eocd.writeUInt16LE(entries.length, 10);
    eocd.writeUInt32LE(cdBuf.length, 12); eocd.writeUInt32LE(offset, 16);
    return Buffer.concat([...parts, cdBuf, eocd]);
}

// All parts of a zip as text, decompressed with Node's own zlib (not the
// stripper's code), joined so tests can search the whole package.
function zipText(buf) {
    const zlib = require('zlib');
    const b = Buffer.from(buf);
    const eocd = b.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
    let pos = b.readUInt32LE(eocd + 16);
    const parts = [];
    for (let i = 0; i < b.readUInt16LE(eocd + 10); i++) {
        const method = b.readUInt16LE(pos + 10), comp = b.readUInt32LE(pos + 20);
        const nameLen = b.readUInt16LE(pos + 28), extra = b.readUInt16LE(pos + 30), comment = b.readUInt16LE(pos + 32);
        const local = b.readUInt32LE(pos + 42);
        const start = local + 30 + b.readUInt16LE(local + 26) + b.readUInt16LE(local + 28);
        const data = b.subarray(start, start + comp);
        parts.push(b.toString('utf8', pos + 46, pos + 46 + nameLen) + '\n' +
            (method === 8 ? zlib.inflateRawSync(data) : data).toString('latin1'));
        pos += 46 + nameLen + extra + comment;
    }
    return parts.join('\n');
}

function zlibCrc(buf) {
    return require('zlib').crc32(buf); // Node 22.2+
}

async function nodeRuns() {
    const files = [];
    for (const name of CLEAN) {
        const input = fs.readFileSync(path.join(fixtures, name));
        const r = await M.stripMetadata(u8(input));
        check('node ' + name + ': detected as office, nothing left uncleaned',
            r.type === 'office' && r.supported === true && r.incomplete.length === 0, JSON.stringify([r.type, r.incomplete]));
        const file = path.join(outDir, 'node.' + name);
        fs.writeFileSync(file, Buffer.from(r.data));
        files.push(file);
    }
    const docm = await M.stripMetadata(u8(fs.readFileSync(path.join(fixtures, 'sample.docm'))));
    check('docm: VBA project reported as not cleaned', JSON.stringify(docm.incomplete) === '["word/vbaProject.bin"]',
        JSON.stringify(docm.incomplete));
    return files;
}

async function browserRuns() {
    let playwright;
    try {
        const root = execFileSync('npm', ['root', '-g']).toString().trim();
        playwright = require(path.join(root, 'playwright'));
    } catch (e) {
        check('browser runs: playwright installed', !REQUIRE_BROWSERS, 'REQUIRE_BROWSERS=1');
        if (!REQUIRE_BROWSERS) console.log('SKIP browser runs: playwright not installed');
        return [];
    }
    const files = [];
    const script = fs.readFileSync(stripperPath, 'utf8');
    for (const engine of ['chromium', 'firefox']) {
        let browser;
        try {
            browser = await playwright[engine].launch(engine === 'chromium' ? { chromiumSandbox: false } : {});
        } catch (e) {
            check(engine + ': launches', !REQUIRE_BROWSERS, e.message.split('\n')[0]);
            if (!REQUIRE_BROWSERS) console.log('SKIP ' + engine + ': ' + e.message.split('\n')[0]);
            continue;
        }
        const page = await browser.newPage();
        await page.setContent('<html><body></body></html>');
        await page.addScriptTag({ content: script });
        check(engine + ': compression streams available', await page.evaluate(() => SafeShareMetadata.compressionSupported()));
        for (const name of CLEAN) {
            const input = Array.from(fs.readFileSync(path.join(fixtures, name)));
            const out = await page.evaluate(async (bytes) => {
                const r = await SafeShareMetadata.stripMetadata(new Uint8Array(bytes));
                return { type: r.type, incomplete: r.incomplete, data: Array.from(new Uint8Array(r.data)) };
            }, input);
            check(engine + ' ' + name + ': detected as office, nothing left uncleaned',
                out.type === 'office' && out.incomplete.length === 0);
            const file = path.join(outDir, engine + '.' + name);
            fs.writeFileSync(file, Buffer.from(out.data));
            files.push(file);
        }
        await browser.close();
    }
    return files;
}

function verifyOutputs(files) {
    const inputs = inspect(CLEAN.map((n) => path.join(fixtures, n)));
    for (const r of inputs) {
        // Gate: a clean output only means something if the input had it all.
        check('input ' + path.basename(r.file) + ' carries the sentinel and dates',
            r.entry_sentinel > 0 && r.raw_sentinel > r.entry_sentinel && r.entry_date > 0 &&
            r.zip_times > 0 && r.zip_extra > 0 && r.zip_comments > 0 && r.unix_creator > 0, JSON.stringify(r));
    }
    const byName = Object.fromEntries(inputs.map((r) => [path.basename(r.file), r.entries]));
    for (const r of inspect(files)) {
        const name = path.basename(r.file);
        check(name + ': no sentinel anywhere', r.raw_sentinel === 0 && r.entry_sentinel === 0,
            'raw ' + r.raw_sentinel + ', entries ' + r.entry_sentinel);
        check(name + ': fixture dates replaced', r.entry_date === 0, String(r.entry_date));
        check(name + ': zip times, extra fields, comments and creator OS cleared',
            r.zip_times === 0 && r.zip_extra === 0 && r.zip_comments === 0 && r.unix_creator === 0, JSON.stringify(r));
        check(name + ': rsid attributes removed', r.rsid_attrs === 0, String(r.rsid_attrs));
        check(name + ': every XML part still parses', r.xml_errors.length === 0, r.xml_errors.join('; '));
        check(name + ': CRCs valid', r.bad_crc === null, String(r.bad_crc));
        check(name + ': visible text kept', r.visible === true);
        check(name + ': same parts in the same order',
            JSON.stringify(r.entries) === JSON.stringify(byName[name.slice(name.indexOf('.') + 1)]));
    }
}

async function edgeCases() {
    const ct = ['[Content_Types].xml', '<Types/>'];

    const plainZip = storedZip([['readme.txt', 'hello']]);
    const r = await M.stripMetadata(u8(plainZip));
    check('non-Office zip passes through unsupported', r.supported === false && r.type === null &&
        Buffer.from(r.data).equals(plainZip));

    await expectReject('encrypted zip entry rejected', M.stripMetadata(u8(storedZip([ct], 0x01))), 'ENCRYPTED');

    const corrupt = storedZip([ct, ['word/document.xml', '<w:document w:rsidR="00AA"/>']]);
    corrupt[corrupt.indexOf('<w:document') + 5] ^= 0x01; // still valid UTF-8, but no longer matches its CRC
    await expectReject('corrupt Office part rejected', M.stripMetadata(u8(corrupt)), 'MALFORMED');

    const zip64 = storedZip([ct]);
    const eocdAt = zip64.length - 22;
    zip64.writeUInt16LE(0xFFFF, eocdAt + 10);
    await expectReject('zip64 marker rejected', M.stripMetadata(u8(zip64)), 'MALFORMED');

    // Over 100 MB: refused if it's an Office file, passed through otherwise.
    const pad = Buffer.alloc(100 * 1024 * 1024);
    await expectReject('Office file over 100 MB rejected',
        M.stripMetadata(u8(storedZip([ct, ['word/document.xml', '<w:document/>'], ['pad.bin', pad]]))), 'TOO_LARGE');
    const bigPlain = await M.stripMetadata(u8(storedZip([['pad.bin', pad]])));
    check('plain zip over 100 MB passes through unsupported', bigPlain.supported === false);

    // An unreadable zip64 archive passes through; an unreadable Office file doesn't.
    const zip64Plain = storedZip([['readme.txt', 'hello']]);
    zip64Plain.writeUInt16LE(0xFFFF, zip64Plain.length - 22 + 10);
    check('unreadable non-Office zip passes through',
        (await M.stripMetadata(u8(zip64Plain))).supported === false);

    const saved = globalThis.DecompressionStream;
    globalThis.DecompressionStream = undefined;
    try {
        check('compressionSupported() is false without DecompressionStream', M.compressionSupported() === false);
        await expectReject('Office file rejected when the browser lacks streams',
            M.stripMetadata(u8(fs.readFileSync(path.join(fixtures, 'sample.docx')))), 'UNSUPPORTED_BROWSER');
    } finally {
        globalThis.DecompressionStream = saved;
    }

    const png = fs.readFileSync(path.join(repoRoot, 'internal/static/web/assets/favicon-16x16.png'));
    const p = await M.stripMetadata(u8(png));
    check('PNG still stripped through the async API', p.type === 'png' && p.supported === true);

    // Fake end-of-directory signature inside the archive comment
    const withComment = storedZip([ct, ['word/document.xml', '<w:document/>']]);
    const comment = Buffer.from('note PK\x05\x06 not the real record');
    withComment.writeUInt16LE(comment.length, withComment.length - 2);
    const commented = await M.stripMetadata(u8(Buffer.concat([withComment, comment])));
    check('fake end-of-directory signature in the comment is skipped', commented.type === 'office');

    // An unreadable Office zip fails closed even when [Content_Types].xml isn't first
    const late = storedZip([['_rels/.rels', '<Relationships/>'], ct]);
    late.writeUInt16LE(0xFFFF, late.length - 22 + 10);
    await expectReject('unreadable Office zip rejected wherever [Content_Types].xml is',
        M.stripMetadata(u8(late)), 'MALFORMED');

    // Quotes inside comments and CDATA don't hide the tags after them
    const hidden = M.scrubOfficeXml('<w:document><!-- don\'t --><![CDATA[ " ]]><w:ins w:author="Bob"/><!-- it\'s --></w:document>');
    check('comments and CDATA with quotes are skipped, later tags scrubbed', !hidden.includes('Bob'), hidden);

    // What the scrubber can't handle fails closed instead of slipping through
    for (const [label, xml] of [
        ['author lookalike in body text', '<w:document><w:t>he wrote author="Bob"</w:t></w:document>'],
        ['unterminated tag', '<w:document><w:ins w:author="Bob"'],
        ['unclosed author element', '<comments><authors><author>Bob'],
        ['DOCTYPE', '<!DOCTYPE x><w:document/>'],
    ]) {
        await expectReject(label + ' fails closed',
            M.stripMetadata(u8(storedZip([ct, ['word/document.xml', xml]]))), 'MALFORMED');
    }

    // Pathological markup is rejected quickly rather than hanging the tab
    for (const [label, xml] of [['40k < with no >', '<'.repeat(40000)], ['unclosed quote', '<a b="' + '<x '.repeat(40000)],
        ['40k unclosed rsids', '<w:rsids>'.repeat(40000)]]) {
        const t0 = Date.now();
        let threw = false;
        try { M.scrubOfficeXml(xml); } catch (e) { threw = e.code === 'MALFORMED'; }
        check(label + ' rejected in linear time', threw && Date.now() - t0 < 500, (Date.now() - t0) + ' ms');
    }

    // Parts that can't be cleaned are reported; stale [trash] entries dropped
    const mixed = await M.stripMetadata(u8(storedZip([ct, ['ppt/presentation.xml', '<p:presentation/>'],
        ['ppt/media/media1.mp4', 'ftypisom GPS'], ['ppt/media/image2.svg', '<svg/>'], ['ppt/media/image3.gif', 'GIF89a'],
        ['ppt/media/image4.emf', 'EMF'], ['xl/activeX/activeX1.bin', 'x'], ['[trash]/0001.dat', 'old bytes']])));
    check('video, GIF and ActiveX reported; EMF kept; [trash] dropped',
        JSON.stringify(mixed.incomplete) === '["ppt/media/media1.mp4","ppt/media/image3.gif","xl/activeX/activeX1.bin"]' &&
        !zipText(mixed.data).includes('old bytes'), JSON.stringify(mixed.incomplete));

    // SVG: metadata, comments and editor data removed; embedded rasters reported
    const svgIn = '<?xml version="1.0"?><!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">' +
        '<svg xmlns:inkscape="i" xmlns:sodipodi="s" sodipodi:docname="C:\\Users\\Bob\\icon.svg" inkscape:export-filename="/home/bob/x.png">' +
        '<!-- by Bob --><metadata><rdf:RDF><cc:Work><dc:creator>Bob</dc:creator></cc:Work></rdf:RDF></metadata>' +
        '<sodipodi:namedview inkscape:current-layer="Bob"/><path d="M0 0"/></svg>';
    const svgs = await M.stripMetadata(u8(storedZip([ct, ['word/document.xml', '<w:document/>'], ['word/media/image1.svg', svgIn],
        ['word/media/image2.svg', '<svg><image href="data:image/jpeg;base64,AAAA"/></svg>'],
        ['word/media/image3.svg', '<svg xmlns:xlink="x"><rdf:RDF><dc:creator>Bob</dc:creator></rdf:RDF><i:pgf>Bob</i:pgf>' +
            '<image xlink:href="/home/bob/p.jpg"/><a href="#top"/><a href="https://example.org/"/></svg>'],
        ['word/media/image4.svg', '<svg><style>@import url(file:///home/bob/a.css);</style></svg>'],
        ['word/media/image5.svg', '<svg><image href="data:;base64,/9j/AAAA"/></svg>']])));
    const svgOut = zipText(svgs.data);
    check('SVG cleaned (metadata, comments, Inkscape data), data-URI SVG reported',
        !/Bob|bob/.test(svgOut.replace(/word\/media\/image[245]\.svg\n[^\n]*/g, '')) && svgOut.includes('<path d="M0 0"/>') &&
        svgOut.includes('href="#top"') && svgOut.includes('href="https://example.org/"') &&
        JSON.stringify(svgs.incomplete) === '["word/media/image2.svg","word/media/image4.svg","word/media/image5.svg"]',
        JSON.stringify(svgs.incomplete));

    // Word fields that link to files keep the path in the field code
    for (const [label, xml] of [
        ['LINK field', '<w:document><w:r><w:instrText xml:space="preserve"> LINK Excel.Sheet.12 "C:\\\\Users\\\\Bob\\\\Book1.xlsx" "Sheet1!R1C1" \\a </w:instrText></w:r></w:document>'],
        ['INCLUDEPICTURE in fldSimple', '<w:document><w:fldSimple w:instr=" INCLUDEPICTURE &quot;x.png&quot; \\d "/></w:document>'],
        ['HYPERLINK field to a network path', '<w:document><w:instrText> HYPERLINK "\\\\\\\\srv\\\\bob\\\\a.docx" </w:instrText></w:document>'],
    ]) {
        const r = await M.stripMetadata(u8(storedZip([ct, ['word/document.xml', xml]])));
        check(label + ' reported as not cleaned', r.incomplete.length === 1 && r.incomplete[0].startsWith('word/document.xml'),
            JSON.stringify(r.incomplete));
    }
    for (const [label, xml] of [
        ['deleted LINK field', '<w:document><w:del><w:r><w:delInstrText> LINK Excel.Sheet.12 "C:\\\\Users\\\\Bob\\\\B.xlsx"</w:delInstrText></w:r></w:del></w:document>'],
        ['old INCLUDE field with a Unix path', '<w:document><w:instrText> INCLUDE "/Users/bob/x.docx" </w:instrText></w:document>'],
        ['HYPERLINK to a Unix path', '<w:document><w:instrText> HYPERLINK "/Users/bob/x.docx" </w:instrText></w:document>'],
        ['lower-case link in fldSimple', '<w:document><w:fldSimple w:instr=" link Excel.Sheet.12 &quot;x.xlsx&quot;"/></w:document>'],
    ]) {
        const r = await M.stripMetadata(u8(storedZip([ct, ['word/document.xml', xml]])));
        check(label + ' reported as not cleaned', r.incomplete.length === 1, JSON.stringify(r.incomplete));
    }
    const webField = await M.stripMetadata(u8(storedZip([ct, ['word/document.xml',
        '<w:document><w:instrText> HYPERLINK "https://example.org/link/page" </w:instrText><w:instrText> PAGE </w:instrText></w:document>']])));
    check('web HYPERLINK and PAGE fields are fine', webField.incomplete.length === 0, JSON.stringify(webField.incomplete));

    const webext = await M.stripMetadata(u8(storedZip([ct, ['word/document.xml', '<w:document/>'],
        ['word/webextensions/webextension1.xml', '<we:webextension><we:property name="u" value="bob@corp.com"/></we:webextension>']])));
    check('add-in (web extension) state reported', JSON.stringify(webext.incomplete) === '["word/webextensions/webextension1.xml"]',
        JSON.stringify(webext.incomplete));

    const pretty = await M.stripMetadata(u8(storedZip([ct, ['ppt/presentation.xml', '<p:presentation/>'],
        ['ppt/authors.xml', '<p188:authorLst>\n  <p188:author id="{1}" name="Bob" initials="B" userId="b@x" providerId="AD"/>\n</p188:authorLst>']])));
    check('pretty-printed authors.xml is cleaned, not refused', !zipText(pretty.data).includes('Bob'));

    const table = M.scrubOfficeXml('<table id="1" name="Table1" displayName="Table1" ref="A1:B2"/><person displayName="Bob" id="{1}"/>');
    check('Excel table names kept, person display names cleared',
        table === '<table id="1" name="Table1" displayName="Table1" ref="A1:B2"/><person displayName="" id="{1}"/>', table);
    const ns0 = M.scrubOfficeXml('<ns0:settings><ns0:mailMerge><ns0:query ns0:val="C:\\Bob"/></ns0:mailMerge><ns0:docVars><ns0:docVar/></ns0:docVars></ns0:settings>');
    check('mail merge and docVars removed under any prefix', ns0 === '<ns0:settings></ns0:settings>', ns0);
    await expectReject('unquoted attribute value fails closed',
        M.stripMetadata(u8(storedZip([ct, ['word/document.xml', '<w:document><w:ins w:author=Bob/></w:document>']]))), 'MALFORMED');
    const video = M.scrubOfficeXml('<Relationship Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/video" ' +
        'Target="https://www.youtube.com/embed/x" TargetMode="External"/>');
    check('online video link kept', video.includes('Target="https://www.youtube.com/embed/x"'), video);
    const R = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships/';
    for (const [type, target] of [['image', 'https://cdn.example.org/a.png'],
        ['video', 'https://corp-my.sharepoint.com/personal/bob_corp_com/v.mp4']]) {
        const out = M.scrubOfficeXml('<Relationship Type="' + R + type + '" Target="' + target + '" TargetMode="External"/>');
        check('external ' + type + ' link ' + target + ' blanked', out.includes('Target=""'), out);
    }

    const visio = await M.stripMetadata(u8(storedZip([ct, ['visio/document.xml', '<Creator>Bob</Creator>']])));
    check('Visio and other non-Office packages are unsupported, not "cleaned"', visio.supported === false);
    const lower = await M.stripMetadata(u8(storedZip([['[content_types].xml', '<Types/>'], ['word/document.xml', '<w:document/>']])));
    check('lower-case [content_types].xml still detected', lower.type === 'office');

    const label = await M.stripMetadata(u8(storedZip([ct, ['word/document.xml', '<w:document/>'],
        ['docMetadata/LabelInfo.xml', '<clbl:labelList xmlns:clbl="x"><clbl:label id="{1}" siteId="{TENANT}"/></clbl:labelList>']])));
    check('sensitivity label (tenant siteId) emptied', !zipText(label.data).includes('TENANT') && label.incomplete.length === 0);

    const quoted = M.scrubOfficeXml("<w:ins w:author = 'Bob' w:date='2031-02-03T04:05:06Z' w:rsidR='00AA'/>");
    check('single-quoted and spaced attributes scrubbed',
        quoted === '<w:ins w:author="" w:date="1970-01-01T00:00:00Z"/>', quoted);

    const H = ' Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink"';
    const L = ' Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/externalLinkPath"';
    const rels = [
        ['<Relationship' + H + ' Target="\\\\srv\\x" TargetMode="External"/>', ''],
        ['<Relationship' + H + ' Target="/Users/bob/notes.docx" TargetMode="External"/>', ''],
        ['<Relationship' + H + ' Target="../bob/notes.docx" TargetMode="External"/>', ''],
        ['<Relationship' + L + ' Target="https://corp-my.sharepoint.com/personal/bob_corp_com/b.xlsx" TargetMode="External"/>', ''],
        ['<Relationship Target="C:/Users/x"/>', ''],
        ['<Relationship' + H + ' Target="https://example.org/" TargetMode="External"/>', 'https://example.org/'],
        ['<Relationship Target="../media/image1.png"/>', '../media/image1.png'],
    ];
    for (const [tag, want] of rels) {
        const got = /Target="([^"]*)"/.exec(M.scrubOfficeXml(tag))[1];
        const target = /Target="([^"]*)"/.exec(tag)[1];
        check('link target ' + target + ' -> "' + want + '"', got === want, got);
    }

    const more = M.scrubOfficeXml('<x:comments xmlns:x="m"><x:authors><x:author>Bob</x:author><author xml:space="preserve">Bob</author>' +
        '</x:authors></x:comments><pc:chgData name="Bob" userId="S::b@x::1"/><w:permStart w:ed="CORP\\bob"/>' +
        '<w15:docId w15:val="{1}"></w15:docId><p1510:client id="{CLIENT}" v="1"/><w_1:x w_1:author="Bob"/>' +
        '<ink timeString="2031-02-03T00:00:00Z"/><protectedRange securityDescriptor="O:S-1-5-21-1"/>');
    check('prefixed authors, chgData, permStart, docId, client id, NCName prefixes, ink and SIDs scrubbed',
        !/Bob|bob|CLIENT|S-1-5|2031|docId/.test(more), more);

    const scrubbed = M.scrubOfficeXml('<a w:author="x" w:authorId="7" name="Sheet1"><p:cmAuthor id="0" name="n"/></a>');
    check('scrub leaves authorId and unrelated name attributes alone',
        scrubbed === '<a w:author="" w:authorId="7" name="Sheet1"><p:cmAuthor id="0" name=""/></a>', scrubbed);
}

(async () => {
    await edgeCases();
    const files = (await nodeRuns()).concat(await browserRuns());
    verifyOutputs(files);
    console.log('\nStripped files in ' + outDir);
    if (failures) {
        console.log(failures + ' failure(s)');
        process.exit(1);
    }
    console.log('All passed');
})().catch((e) => {
    console.error(e);
    process.exit(1);
});
