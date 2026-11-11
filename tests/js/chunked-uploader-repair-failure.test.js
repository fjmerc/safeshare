// If an assembly retry has to re-upload missing chunks and that fails (here:
// the rate limit), the failure is shown to the page, which resets. The upload
// must then stop: it used to carry on in the background and report a second
// failure, or even complete after the page had given up on it. And the
// parallel chunk failures must be reported once, not once per chunk.
//
//   node tests/js/chunked-uploader-repair-failure.test.js

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const src = path.resolve(__dirname, '..', '..', 'internal/static/web/assets/chunked-uploader.js');
const reply = (status, body, headers) => ({
    ok: status < 300, status, headers: { get: (h) => (headers && headers[h]) || null }, json: async () => body,
});

// The first assembly fails retryably; the retry finds every chunk missing and
// re-uploads them, which is refused. `afterwards` is what the server would
// have said next had the client kept polling.
async function run(afterwards) {
    let completeCalls = 0;
    let statusCalls = 0;
    let repairing = false;
    const sandbox = {
        window: {}, console: { log() {}, warn() {}, error() {} },
        AbortController, FormData, Blob, crypto: {}, setTimeout, clearTimeout,
        fetch: async (url) => {
            if (url === '/api/upload/init') return reply(201, { upload_id: 'u1', chunk_size: 1024, total_chunks: 6 });
            if (url.startsWith('/api/upload/chunk/')) {
                await new Promise((r) => setTimeout(r, 10));
                return repairing
                    ? reply(429, { error: 'Rate limit exceeded', code: 'RATE_LIMIT_EXCEEDED' }, { 'Retry-After': '3600' })
                    : reply(200, {});
            }
            if (url.startsWith('/api/upload/complete/')) {
                completeCalls++;
                if (completeCalls === 2) {
                    repairing = true;
                    return reply(400, { error: 'missing', code: 'MISSING_CHUNKS', missing_chunks: [0, 1, 2, 3, 4, 5], retry_recommended: true });
                }
                return reply(202, { status: 'processing' });
            }
            if (url.startsWith('/api/upload/status/')) {
                statusCalls++;
                if (statusCalls === 1) return reply(200, { status: 'failed', retryable: true, error_code: 'SCAN_UNAVAILABLE' });
                return afterwards === 'completed'
                    ? reply(200, { status: 'completed', claim_code: 'C', download_url: '/d' })
                    : reply(200, { status: 'failed', retryable: false, error_code: 'MALWARE_DETECTED', error_message: 'malware' });
            }
            throw new Error('unexpected request ' + url);
        },
    };
    vm.createContext(sandbox);
    vm.runInContext(fs.readFileSync(src, 'utf8'), sandbox, { filename: src });
    sandbox.__file = new Blob([new Uint8Array(6 * 1024)]);
    sandbox.__file.name = 'six.bin';
    return vm.runInContext(`(async () => {
        const events = [];
        const u = new ChunkedUploader(__file, { persistState: false, concurrency: 6, retryAttempts: 3 });
        u.sleep = () => Promise.resolve();
        u.on('error', (d) => events.push(d.stage + ':' + d.code));
        u.on('complete', () => events.push('complete'));
        await u.init();
        await u.uploadAllChunks();
        let thrown = null;
        try { await u.complete(); } catch (e) { thrown = e; }
        return { events, thrown };
    })()`, sandbox);
}

(async () => {
    let failures = 0;
    const check = (name, ok, detail) => {
        console.log((ok ? 'PASS ' : 'FAIL ') + name + (ok || !detail ? '' : ' -- ' + detail));
        if (!ok) failures++;
    };

    for (const afterwards of ['failed', 'completed']) {
        const r = await run(afterwards);
        const events = JSON.stringify(r.events);
        check(`(server would have ${afterwards}) the repair failure is reported once`,
            r.events.length === 1 && r.events[0] === 'chunk_upload:RATE_LIMIT_EXCEEDED', events);
        check(`(server would have ${afterwards}) the upload stops there`, !!r.thrown && r.thrown.reported === true,
            r.thrown ? 'not marked reported' : 'no error thrown');
    }

    if (failures) {
        console.log(failures + ' FAILED');
        process.exit(1);
    }
    console.log('ALL PASSED');
})().catch((e) => { console.log('FAIL ' + (e && e.stack || e)); process.exit(1); });
