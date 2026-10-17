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
        M.stripMetadata(u8(storedZip([ct, ['pad.bin', pad]]))), 'TOO_LARGE');
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

    // Leftovers the tag scrubber can't reach fail closed instead of slipping through
    for (const [label, xml] of [
        ['CDATA hiding a tag', '<w:document><![CDATA[ " ]]><w:ins w:author="Bob"/>" </w:document>'],
        ['author lookalike in body text', '<w:document><w:t>he wrote author="Bob"</w:t></w:document>'],
    ]) {
        await expectReject(label + ' fails closed',
            M.stripMetadata(u8(storedZip([ct, ['word/document.xml', xml]]))), 'MALFORMED');
    }

    const quoted = M.scrubOfficeXml("<w:ins w:author = 'Bob' w:date='2031-02-03T04:05:06Z' w:rsidR='00AA'/>");
    check('single-quoted and spaced attributes scrubbed',
        quoted === '<w:ins w:author="" w:date="1970-01-01T00:00:00Z"/>', quoted);
    const paths = M.scrubOfficeXml('<Relationship Target="\\\\srv\\x" TargetMode="External"/><Relationship Target="C:/Users/x"/>' +
        '<Relationship Target="https://example.org/" TargetMode="External"/>');
    check('network and drive paths blanked, web links kept',
        paths === '<Relationship Target="" TargetMode="External"/><Relationship Target=""/>' +
        '<Relationship Target="https://example.org/" TargetMode="External"/>', paths);

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
