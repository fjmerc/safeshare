// "Never expire" (0 hours) must reach the server as 0 for chunked uploads;
// it used to be turned into 24 because 0 is falsy.
//
//   node tests/js/chunked-uploader-expiry.test.js

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const src = path.resolve(__dirname, '..', '..', 'internal/static/web/assets/chunked-uploader.js');

async function initBodyFor(options) {
    let body = null;
    const sandbox = {
        window: {},
        console: { log() {}, warn() {}, error() {} },
        AbortController,
        setTimeout,
        clearTimeout,
        fetch: async (url, init) => {
            if (url === '/api/upload/init') body = JSON.parse(init.body);
            return { ok: true, status: 201, json: async () => ({ upload_id: 'u1', chunk_size: 1024, total_chunks: 1 }) };
        },
    };
    vm.createContext(sandbox);
    vm.runInContext(fs.readFileSync(src, 'utf8'), sandbox, { filename: src });
    sandbox.__opts = options;
    await vm.runInContext(`new ChunkedUploader({ name: 'a.bin', size: 10 }, Object.assign({ persistState: false }, __opts)).init()`, sandbox);
    return body;
}

(async () => {
    let failures = 0;
    const check = (name, ok, detail) => {
        console.log((ok ? 'PASS ' : 'FAIL ') + name + (ok || !detail ? '' : ' -- ' + detail));
        if (!ok) failures++;
    };

    const never = await initBodyFor({ expiresInHours: 0 });
    check('0 hours (never expire) is sent as 0', never && never.expires_in_hours === 0, JSON.stringify(never));
    const twelve = await initBodyFor({ expiresInHours: 12 });
    check('12 hours is sent as 12', twelve && twelve.expires_in_hours === 12, JSON.stringify(twelve));
    const unset = await initBodyFor({});
    check('no expiry given defaults to 24', unset && unset.expires_in_hours === 24, JSON.stringify(unset));

    if (failures) {
        console.log(failures + ' FAILED');
        process.exit(1);
    }
    console.log('ALL PASSED');
})().catch((e) => { console.log('FAIL ' + (e && e.stack || e)); process.exit(1); });
