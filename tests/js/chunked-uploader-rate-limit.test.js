// When the server refuses chunks with a rate limit, every in-flight chunk
// fails at once. The uploader must report that to the page once (it used to
// show one error message per parallel chunk) and must not retry, since the
// limit lasts up to an hour.
//
//   node tests/js/chunked-uploader-rate-limit.test.js

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const src = path.resolve(__dirname, '..', '..', 'internal/static/web/assets/chunked-uploader.js');

async function run({ chunkStatus }) {
    const chunkRequests = [];
    const sandbox = {
        window: {},
        console: { log() {}, warn() {}, error() {} },
        AbortController,
        FormData,
        Blob,
        crypto: {}, // no subtle: the uploader skips client checksums
        setTimeout,
        clearTimeout,
        fetch: async (url) => {
            if (url === '/api/upload/init') {
                return { ok: true, status: 201, headers: { get: () => null },
                    json: async () => ({ upload_id: 'u1', chunk_size: 1024, total_chunks: 6 }) };
            }
            chunkRequests.push(url);
            // Let every worker get its request in before any answer arrives.
            await new Promise((r) => setTimeout(r, 20));
            if (chunkStatus === 429) {
                return { ok: false, status: 429, headers: { get: (h) => (h === 'Retry-After' ? '3600' : null) },
                    json: async () => ({ error: 'Rate limit exceeded. Please try again later.', code: 'RATE_LIMIT_EXCEEDED' }) };
            }
            return { ok: true, status: 200, headers: { get: () => null }, json: async () => ({}) };
        },
    };
    vm.createContext(sandbox);
    vm.runInContext(fs.readFileSync(src, 'utf8'), sandbox, { filename: src });
    sandbox.__file = new Blob([new Uint8Array(6 * 1024)]);
    sandbox.__file.name = 'six.bin';
    return vm.runInContext(`(async () => {
        const errors = [];
        const u = new ChunkedUploader(__file, { persistState: false, concurrency: 6, retryAttempts: 3 });
        u.on('error', (d) => errors.push(d));
        await u.init();
        let thrown = null;
        try { await u.uploadAllChunks(); } catch (e) { thrown = e; }
        const chunkErrors = errors.length;
        // A later failure outside the chunk run (here: assembly) must still
        // reach the page; the de-duplication covers one run's chunks only.
        u._reportError(new Error('Upload rejected: malware detected'), { stage: 'assembly', code: 'MALWARE_DETECTED' });
        return { errors, thrown, chunkErrors };
    })()`, sandbox).then((r) => Object.assign(r, { chunkRequests }));
}

(async () => {
    let failures = 0;
    const check = (name, ok, detail) => {
        console.log((ok ? 'PASS ' : 'FAIL ') + name + (ok || !detail ? '' : ' -- ' + detail));
        if (!ok) failures++;
    };

    const limited = await run({ chunkStatus: 429 });
    check('a rate-limited upload fails', !!limited.thrown);
    check('the failure is reported to the page once', limited.chunkErrors === 1, `${limited.chunkErrors} error events`);
    check('a later assembly failure is still reported', limited.errors.length === 2 &&
        limited.errors[1].code === 'MALWARE_DETECTED', JSON.stringify(limited.errors.map((e) => e.code)));
    check('the report carries the rate-limit code', limited.errors[0] && limited.errors[0].code === 'RATE_LIMIT_EXCEEDED',
        JSON.stringify(limited.errors[0]));
    check('the thrown error is marked reported, so the page does not show it again', limited.thrown && limited.thrown.reported === true);
    check('chunks are not retried after an hour-long Retry-After', limited.chunkRequests.length <= 6,
        `${limited.chunkRequests.length} chunk requests`);

    const ok = await run({ chunkStatus: 200 });
    check('a normal upload still succeeds without error events', !ok.thrown && ok.chunkErrors === 0,
        ok.thrown ? String(ok.thrown) : `${ok.errors.length} errors`);

    if (failures) {
        console.log(failures + ' FAILED');
        process.exit(1);
    }
    console.log('ALL PASSED');
})().catch((e) => { console.log('FAIL ' + (e && e.stack || e)); process.exit(1); });
