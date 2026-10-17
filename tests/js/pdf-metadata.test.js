// Tests for PDF metadata stripping in internal/static/web/assets/metadata-strip.js.
//
// The stripper runs under Node and in real Chromium and Firefox. Every output
// is then checked by fixtures/check_pdf.py, which shares no code with the
// stripper: the sentinel planted in each metadata location (see
// make_pdf_fixtures.py) must be present in every input and absent from every
// output, and the output must keep its size (metadata is overwritten in place).
//
//   node tests/js/pdf-metadata.test.js
//
// Needs Node 22.2+, python3, and for the browser runs the globally installed
// playwright package with chromium and firefox; set REQUIRE_BROWSERS=1 to fail
// instead of skipping when they're missing. OUT_DIR keeps the stripped files
// (e.g. for `qpdf --check` or `pdfcpu validate -m strict`). Exits non-zero on
// failure.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const repoRoot = path.resolve(__dirname, '..', '..');
const stripperPath = path.join(repoRoot, 'internal/static/web/assets/metadata-strip.js');
const fixtures = path.join(__dirname, 'fixtures');
const checker = path.join(fixtures, 'check_pdf.py');
const M = require(stripperPath);
const outDir = process.env.OUT_DIR || fs.mkdtempSync(path.join(os.tmpdir(), 'pdf-strip-'));
fs.mkdirSync(outDir, { recursive: true });
const REQUIRE_BROWSERS = process.env.REQUIRE_BROWSERS === '1';

// Fixtures that must come out fully clean
const CLEAN = ['sample.pdf', 'sample-objstm.pdf', 'sample-linear.pdf'];

let failures = 0;
function check(name, ok, detail) {
    if (ok) {
        console.log('PASS ' + name);
    } else {
        failures++;
        console.log('FAIL ' + name + (detail ? ': ' + detail : ''));
    }
}

function u8(buf) { return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength); }

function inspect(files) {
    return execFileSync('python3', [checker, ...files]).toString().trim().split('\n').map((l) => JSON.parse(l));
}

async function expectReject(name, promise, code) {
    try {
        await promise;
        check(name, false, 'resolved, expected ' + code);
    } catch (e) {
        check(name, e.code === code, 'got ' + e.code + ' (' + e.message + ')');
    }
}

// A minimal PDF from object bodies, with a classic xref table.
function makePdf(objs, trailerExtra) {
    let out = '%PDF-1.7\n';
    const offsets = [];
    objs.forEach((body, i) => {
        offsets.push(out.length);
        out += (i + 1) + ' 0 obj\n' + body + '\nendobj\n';
    });
    const xref = out.length;
    out += 'xref\n0 ' + (objs.length + 1) + '\n0000000000 65535 f \n';
    offsets.forEach((o) => { out += String(o).padStart(10, '0') + ' 00000 n \n'; });
    out += 'trailer\n<< /Size ' + (objs.length + 1) + ' /Root 1 0 R ' + (trailerExtra || '') + ' >>\nstartxref\n' + xref + '\n%%EOF\n';
    return Buffer.from(out, 'latin1');
}

const CATALOG = '<< /Type /Catalog /Pages 2 0 R >>';
const PAGES = '<< /Type /Pages /Kids [] /Count 0 >>';

async function nodeRuns() {
    const files = [];
    for (const name of CLEAN) {
        const input = fs.readFileSync(path.join(fixtures, name));
        const r = await M.stripMetadata(u8(input));
        check('node ' + name + ': detected as pdf, nothing left uncleaned, same size',
            r.type === 'pdf' && r.supported && r.incomplete.length === 0 && r.data.byteLength === input.length,
            JSON.stringify([r.type, r.incomplete, r.data.byteLength, input.length]));
        const file = path.join(outDir, 'node.' + name);
        fs.writeFileSync(file, Buffer.from(r.data));
        files.push(file);
    }
    const attach = await M.stripMetadata(u8(fs.readFileSync(path.join(fixtures, 'sample-attach.pdf'))));
    check('attachment reported as not cleaned', JSON.stringify(attach.incomplete) === '["attached file (object 15)"]',
        JSON.stringify(attach.incomplete));
    await expectReject('encrypted PDF rejected', M.stripMetadata(u8(fs.readFileSync(path.join(fixtures, 'sample-encrypted.pdf')))),
        'ENCRYPTED');
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
        for (const name of CLEAN) {
            const input = Array.from(fs.readFileSync(path.join(fixtures, name)));
            const out = await page.evaluate(async (bytes) => {
                const r = await SafeShareMetadata.stripMetadata(new Uint8Array(bytes));
                return { type: r.type, incomplete: r.incomplete, data: Array.from(new Uint8Array(r.data)) };
            }, input);
            check(engine + ' ' + name + ': detected as pdf, nothing left uncleaned', out.type === 'pdf' && out.incomplete.length === 0);
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
        check('input ' + path.basename(r.file) + ' carries the sentinel, dates and XMP',
            r.sentinel > 0 && r.dates > 0 && r.xmp > 0, JSON.stringify(r));
    }
    const sizes = Object.fromEntries(inputs.map((r) => [path.basename(r.file), r.size]));
    for (const r of inspect(files)) {
        const name = path.basename(r.file);
        check(name + ': no sentinel anywhere (raw or inflated)', r.sentinel === 0, String(r.sentinel));
        check(name + ': fixture dates removed', r.dates === 0, String(r.dates));
        check(name + ': no XMP left', r.xmp === 0, String(r.xmp));
        check(name + ': visible text kept', r.visible === true);
        check(name + ': same size as the input', r.size === sizes[name.slice(name.indexOf('.') + 1)]);
    }
}

async function edgeCases() {
    // The cross-reference table isn't trusted: a broken one doesn't matter.
    const broken = makePdf([CATALOG, PAGES, '<< /Author (Bob) >>'], '/Info 3 0 R').toString('latin1')
        .replace(/startxref\n\d+/, 'startxref\n999999');
    const b = await M.stripMetadata(u8(Buffer.from(broken, 'latin1')));
    check('broken xref: Info still cleared', !Buffer.from(b.data).includes('Bob'));

    // Comment authors are cleared; a form field's /T (its name) is kept.
    const annots = await M.stripMetadata(u8(makePdf([CATALOG, PAGES,
        '<< /Type /Annot /Subtype /Text /T (Bob) /M (D:20310203) /Contents (note) >>',
        '<< /Type /Annot /Subtype /Widget /T (email_field) /FT /Tx >>'])));
    const at = Buffer.from(annots.data).toString('latin1');
    check('comment author cleared, form field name kept', !at.includes('Bob') && !at.includes('D:2031') &&
        at.includes('(email_field)') && at.includes('(note)'));

    // An attached PDF's own objects aren't mistaken for the outer file's.
    const inner = '1 0 obj\n<< /Author (Inner) >>\nendobj\n';
    const attached = await M.stripMetadata(u8(makePdf([CATALOG, PAGES,
        '<< /Type /EmbeddedFile /Length ' + inner.length + ' >>\nstream\n' + inner + '\nendstream'])));
    check('attached file untouched and reported', Buffer.from(attached.data).toString('latin1').includes(inner) &&
        attached.incomplete.length === 1, JSON.stringify(attached.incomplete));

    const jpx = await M.stripMetadata(u8(makePdf([CATALOG, PAGES,
        '<< /Type /XObject /Subtype /Image /Filter /JPXDecode /Length 4 >>\nstream\nJP2!\nendstream'])));
    check('JPEG 2000 image reported', JSON.stringify(jpx.incomplete) === '["JPEG 2000 image (object 3)"]', JSON.stringify(jpx.incomplete));

    await expectReject('/Encrypt in the trailer rejected',
        M.stripMetadata(u8(makePdf([CATALOG, PAGES, '<< /Filter /Standard /V 2 >>'], '/Encrypt 3 0 R'))), 'ENCRYPTED');

    const big = Buffer.alloc(100 * 1024 * 1024 + 1, 0x20);
    Buffer.from('%PDF-1.7\n').copy(big);
    await expectReject('PDF over 100 MB rejected', M.stripMetadata(u8(big)), 'TOO_LARGE');

    const deep = await M.stripMetadata(u8(makePdf([CATALOG, PAGES, '['.repeat(100) + ']'.repeat(100)]))).then(() => 'ok', (e) => e.code);
    check('deeply nested arrays rejected, not a stack overflow', deep === 'MALFORMED', deep);
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
