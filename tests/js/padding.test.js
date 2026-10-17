// Browser-side tests for the E2E payload framing and PADME padding in
// internal/static/web/assets/crypto.js. There is no JS test runner in this
// project, so this drives a real Chromium through the globally installed
// `playwright` package (Web Crypto needs a secure context, hence the routed
// http://localhost page).
//
//   node tests/js/padding.test.js
//
// Needs: npm i -g playwright (and its chromium). Exits non-zero on failure.

const path = require('path');
const { execFileSync } = require('child_process');

const repoRoot = path.resolve(__dirname, '..', '..');
const cryptoJs = path.join(repoRoot, 'internal/static/web/assets/crypto.js');
const playwrightPath = path.join(execFileSync('npm', ['root', '-g']).toString().trim(), 'playwright');
const { chromium } = require(playwrightPath);

// Fixtures produced by the pre-padding crypto.js (origin/develop at v1.15.0) with the
// key bytes 0,1,2,...,31 over the body "legacy file body\n". "sf01" is a hidden-filename
// upload (name "legacy-name.txt"), "v1" is a raw encrypted file with no header.
const FIXTURE_KEY = Array.from({ length: 32 }, (_, i) => i);
const FIXTURE_SF01 = 'lElvE45B547o60NNn9lSllo2OXgLHPo259agbLPHM5dGTFKE8huBdaycewoZ19nctJk0CGdJ5QoCluP6MflYLmBLvOc=';
const FIXTURE_V1 = 'TIQKTTuY/mV4+WlJEX8jUZnPCboeyM2Hd+UXriLYqU3aB6JwXS8VB6FQTSon';

let failures = 0;
function check(name, ok, detail) {
    if (ok) {
        console.log('PASS ' + name);
    } else {
        failures++;
        console.log('FAIL ' + name + (detail ? ' -- ' + detail : ''));
    }
}

// Reference PADME straight from the paper, with BigInt (independent of crypto.js).
function padmeRef(L) {
    L = BigInt(L);
    if (L < 2n) return L;
    const E = BigInt(L.toString(2).length - 1);
    const S = BigInt(E.toString(2).length);
    const lastBits = E - S;
    const mask = (1n << lastBits) - 1n;
    return (L + mask) & ~mask;
}

(async () => {
    const browser = await chromium.launch({ chromiumSandbox: false });
    const page = await browser.newPage();
    await page.route('http://localhost/**', r => r.fulfill({ contentType: 'text/html', body: '<html></html>' }));
    await page.goto('http://localhost/');
    await page.addScriptTag({ path: cryptoJs });
    page.on('pageerror', e => { failures++; console.log('PAGE ERROR ' + e.message); });

    // --- PADME buckets ---
    const vectors = [[0, 0], [1, 1], [2, 2], [3, 3], [9, 10], [100, 104], [1000, 1024], [1025, 1088],
        [1048577, 1081344], [4294967297, 4362076160]];
    for (const [n, want] of vectors) {
        const got = await page.evaluate(n => SafeShareCrypto.padmeLength(n), n);
        check(`padme(${n}) == ${want}`, got === want, 'got ' + got);
    }
    const sample = [];
    for (let e = 1; e < 40; e++) {
        const p = Math.pow(2, e);
        sample.push(p - 1, p, p + 1, Math.floor(p * 1.37));
    }
    for (let i = 0; i < 300; i++) sample.push(Math.floor(Math.random() * 3e9));
    const results = await page.evaluate(ns => ns.map(n => SafeShareCrypto.padmeLength(n)), sample);
    let mismatches = 0, tooBig = 0, tooSmall = 0;
    sample.forEach((n, i) => {
        if (BigInt(results[i]) !== padmeRef(n)) mismatches++;
        if (n >= 2 && results[i] > n * 1.125 + 1e-9) tooBig++;
        if (results[i] < n) tooSmall++;
    });
    check('padme matches BigInt reference on ' + sample.length + ' sizes (incl. > 2^32)', mismatches === 0, mismatches + ' mismatches');
    check('padme never shrinks and overhead <= 12.5%', tooBig === 0 && tooSmall === 0);

    // --- Round trips through wrap -> encrypt -> decrypt -> unwrap ---
    const roundTrip = (size, name, max) => page.evaluate(async ({ size, name, max }) => {
        const C = SafeShareCrypto;
        const data = new Uint8Array(size);
        for (let off = 0; off < size; off += 65536) {
            crypto.getRandomValues(data.subarray(off, Math.min(off + 65536, size)));
        }
        const key = await C.generateEncryptionKey();
        const wrapped = C.wrapPayloadPadded(name, data.buffer, max);
        const enc = await C.encryptFile(key, wrapped);
        const dec = await C.decryptFile(key, enc);
        const un = C.unwrapPayload(dec);
        const out = new Uint8Array(un.data);
        let same = out.length === data.length;
        for (let i = 0; same && i < out.length; i++) if (out[i] !== data[i]) same = false;
        return { same, filename: un.filename, version: un.version, stored: enc.byteLength, wrapped: wrapped.byteLength };
    }, { size, name, max });

    const edgeSizes = [0, 1, 2, 4096 - 16 - 8, 4096 - 16 - 8 + 1, 5000, 65536, 1000000];
    for (const size of edgeSizes) {
        const r = await roundTrip(size, 'note.txt', 0);
        const want = Math.max(Number(padmeRef(16 + 8 + size)), 4096);
        check(`round trip ${size} B (bucket ${want})`, r.same && r.filename === 'note.txt' && r.version === 2 && r.wrapped === want && r.stored === want + 28,
            JSON.stringify(r));
    }
    // exact PADME bucket edge above the floor: payload already equals a bucket, so no extra pad
    {
        const edge = Number(padmeRef(1000000));
        const size = edge - 16 - 0; // empty filename
        const r = await roundTrip(size, '', 0);
        check('round trip with payload exactly at a bucket edge, empty filename', r.same && r.filename === null && r.wrapped === edge, JSON.stringify(r));
    }
    {
        const r = await roundTrip(100 * 1024 * 1024, 'big.bin', 0);
        const want = Number(padmeRef(16 + 7 + 100 * 1024 * 1024));
        check('round trip ~100 MiB (bucket ' + want + ')', r.same && r.wrapped === want, JSON.stringify(r));
    }
    // Two different sizes in the same bucket store the same size
    {
        const a = await roundTrip(1000001, 'a', 0);
        const b = await roundTrip(1000300, 'bbbbbbbb', 0);
        check('different file sizes, same stored size', a.stored === b.stored, a.stored + ' vs ' + b.stored);
    }

    // --- Size limit interaction ---
    {
        const max = 1000000;
        // PADME would round this up past the limit; it is capped 4096 below it (room for the form)
        const r1 = await roundTrip(990000, '', max);
        check('limit: bucket capped below the limit', r1.same && r1.stored === max - 4096, JSON.stringify(r1));
        // Inside the last 4096 bytes: left unpadded, never refused, never above the limit
        const r2 = await roundTrip(max - 28 - 16 - 100, '', max);
        check('limit: file in the last KB is left unpadded, not refused', r2.same && r2.stored === max - 100, JSON.stringify(r2));
        const r3 = await roundTrip(max - 28 - 16, '', max); // exactly fits unpadded
        check('limit: file that exactly fits unpadded still fits', r3.same && r3.stored === max, JSON.stringify(r3));
        const err = await page.evaluate(max => {
            try { SafeShareCrypto.wrapPayloadPadded('', new ArrayBuffer(max - 28 - 16 + 1), max); return null; }
            catch (e) { return { code: e.code, msg: e.message }; }
        }, max);
        check('limit: file too large even unpadded is refused with PAYLOAD_TOO_LARGE', err && err.code === 'PAYLOAD_TOO_LARGE', JSON.stringify(err));
    }

    // --- Old formats still decrypt (fixtures from the pre-padding code) ---
    {
        const r = await page.evaluate(async ({ keyBytes, sf01, v1 }) => {
            const C = SafeShareCrypto;
            const key = await crypto.subtle.importKey('raw', new Uint8Array(keyBytes), { name: 'AES-GCM' }, false, ['decrypt']);
            const fromB64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0)).buffer;
            const dec = async s => C.unwrapPayload(await C.decryptFile(key, fromB64(s)));
            const a = await dec(sf01), b = await dec(v1);
            const td = new TextDecoder();
            return { a: [a.filename, td.decode(a.data), a.version], b: [b.filename, td.decode(b.data), b.version] };
        }, { keyBytes: FIXTURE_KEY, sf01: FIXTURE_SF01, v1: FIXTURE_V1 });
        check('old SF01 payload decrypts (name + body)', r.a[0] === 'legacy-name.txt' && r.a[1] === 'legacy file body\n' && r.a[2] === 1, JSON.stringify(r.a));
        check('old raw (v1) payload decrypts unchanged', r.b[0] === null && r.b[1] === 'legacy file body\n' && r.b[2] === 1, JSON.stringify(r.b));
    }
    // New code's unpadded SF01 writer is byte-compatible with the old one
    {
        const same = await page.evaluate(() => {
            const C = SafeShareCrypto;
            const w = new Uint8Array(C.wrapPayload('x.txt', new TextEncoder().encode('hi').buffer));
            return Array.from(w).join(',');
        });
        check('wrapPayload (SF01) unchanged', same === '83,70,48,49,5,0,0,0,120,46,116,120,116,104,105', same);
    }

    // --- Tampered / malformed SF02 headers are rejected ---
    const tamper = (mutate) => page.evaluate(m => {
        const C = SafeShareCrypto;
        const w = new Uint8Array(C.wrapPayloadPadded('n.txt', new TextEncoder().encode('hello world').buffer, 0));
        const v = new DataView(w.buffer);
        new Function('w', 'v', m)(w, v);
        try { C.unwrapPayload(w.buffer); return 'accepted'; } catch (e) { return 'rejected: ' + e.message; }
    }, mutate);
    const rejected = s => s.startsWith('rejected');
    check('data length > decrypted size rejected', rejected(await tamper('v.setUint32(8, 0xFFFFFFF0, true);')));
    check('data length just past the end rejected', rejected(await tamper('v.setUint32(8, w.length - 16 - 5 + 1, true);')));
    check('huge 64-bit data length rejected', rejected(await tamper('v.setUint32(12, 0x7FFFFFFF, true);')));
    check('name length > payload rejected', rejected(await tamper('v.setUint32(4, 1024, true); v.setUint32(8, w.length, true);')));
    check('name length over the cap rejected', rejected(await tamper('v.setUint32(4, 5000, true);')));
    check('non-zero padding rejected', rejected(await tamper('w[w.length - 1] = 1;')));
    check('truncated SF02 header rejected', await page.evaluate(() => {
        try { SafeShareCrypto.unwrapPayload(new Uint8Array([0x53, 0x46, 0x30, 0x32, 0, 0]).buffer); return false; } catch (e) { return true; }
    }));
    check('untampered SF02 accepted', !rejected(await tamper('')));
    check('shortening data length (extra bytes become padding) is rejected unless zero', rejected(await tamper('v.setUint32(8, 3, true);')));

    // --- Tamper with the ciphertext: GCM rejects before framing is even looked at ---
    {
        const r = await page.evaluate(async () => {
            const C = SafeShareCrypto;
            const key = await C.generateEncryptionKey();
            const enc = new Uint8Array(await C.encryptFile(key, C.wrapPayloadPadded('a', new ArrayBuffer(10), 0)));
            enc[200] ^= 1;
            try { await C.decryptFile(key, enc.buffer); return 'accepted'; } catch (e) { return 'rejected'; }
        });
        check('flipped ciphertext bit fails authentication', r === 'rejected');
    }

    await browser.close();
    console.log(failures === 0 ? '\nALL PASSED' : `\n${failures} FAILED`);
    process.exit(failures === 0 ? 0 : 1);
})().catch(e => { console.error(e); process.exit(2); });
