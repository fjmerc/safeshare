// Browser test: choosing several files on the upload page gives one bundle
// link. Run with SAFESHARE_BROWSER_TESTS=1 (see bundle-harness.js).

const H = require('./bundle-harness');
H.requireBrowserTests('bundle-upload.test.js');

async function openUploadPage(browser, baseURL) {
    const context = await H.newBrowserContext(browser, baseURL);
    const page = await context.newPage();
    await page.goto(baseURL + '/');
    await page.waitForFunction(() => document.getElementById('fileInput'));
    return { context, page };
}

async function setE2E(page, on) {
    await page.evaluate((on) => {
        const t = document.getElementById('e2eEncryptionToggle');
        if (t && t.checked !== on) t.click();
    }, on);
}

async function uploadBundle(page, files) {
    await page.setInputFiles('#fileInput', files);
    await page.waitForSelector('#bundleFileList:not(.hidden)');
    await page.waitForFunction(() => !document.getElementById('uploadButton').disabled);
    await page.click('#uploadButton');
}

(async () => {
    const { chromium } = H.loadPlaywright();
    const server = await H.startServer();
    const browser = await chromium.launch({ chromiumSandbox: false });
    const pngs = H.makeFiles([['one.png', H.PNG_1PX], ['two.png', H.PNG_1PX], ['three.png', H.PNG_1PX]]);

    try {
        // Plain bundle: one link, one QR code, three files on the server.
        {
            const { context, page } = await openUploadPage(browser, server.baseURL);
            await setE2E(page, false);
            await page.setInputFiles('#fileInput', pngs);
            const listed = await page.$$eval('#bundleFileList li', (lis) => lis.length);
            H.check('three files are listed before upload', listed === 3, 'listed ' + listed);
            H.check('upload button names the bundle', /3 files/.test(await page.textContent('#uploadButton')));
            await page.click('#uploadButton');
            await page.waitForSelector('#resultsSection:not(.hidden)', { timeout: 30000 });
            const url = await page.inputValue('#downloadUrl');
            const m = /\/#\/bundle\/([A-Za-z0-9_-]+)$/.exec(url);
            H.check('result is one bundle link', !!m, url);
            H.check('one QR code', (await page.$$('#qrcode canvas, #qrcode img')).length >= 1 &&
                (await page.$$eval('#qrcode > *', (els) => els.filter((e) => e.tagName === 'CANVAS').length)) <= 1);
            const filesShown = await page.$$eval('#bundleFilesInfo li', (lis) => lis.map((li) => li.textContent));
            H.check('results list the files', filesShown.length === 3 && filesShown[0].includes('one.png'), JSON.stringify(filesShown));
            const info = await (await fetch(server.baseURL + '/api/bundle/' + m[1] + '/info')).json();
            H.check('server has three files', info.file_count === 3 && info.files[2].original_filename === 'three.png', JSON.stringify(info));
            await context.close();
        }

        // Encrypted bundle: the link carries the key, the server has a manifest.
        {
            const { context, page } = await openUploadPage(browser, server.baseURL);
            await setE2E(page, true);
            await page.evaluate(() => {
                const hide = document.getElementById('e2eHideFilenameToggle');
                if (hide && !hide.checked) hide.click();
            });
            await uploadBundle(page, pngs.slice(0, 2));
            await page.waitForSelector('#resultsSection:not(.hidden)', { timeout: 30000 });
            const url = await page.inputValue('#downloadUrl');
            const m = /\/#\/bundle\/([A-Za-z0-9_-]+)\/key\/[A-Za-z0-9_-]{43}$/.exec(url);
            H.check('encrypted bundle link carries the key', !!m, url);
            const info = m && await (await fetch(server.baseURL + '/api/bundle/' + m[1] + '/info')).json();
            H.check('encrypted bundle stored a manifest', !!(info && info.client_encrypted && info.encrypted_manifest), JSON.stringify(info));
            H.check('with Hide filename, the server never sees the names', !!info && info.files.every((f) => f.original_filename === 'encrypted.bin'), JSON.stringify(info && info.files));
            await context.close();
        }

        // A file that fails: no link, and the draft is deleted.
        {
            const { context, page } = await openUploadPage(browser, server.baseURL);
            await setE2E(page, false);
            let uploads = 0;
            await page.route('**/api/upload', (route) => {
                uploads++;
                if (uploads === 2) {
                    return route.fulfill({ status: 500, contentType: 'application/json', body: '{"error":"boom","code":"INTERNAL_ERROR"}' });
                }
                return route.continue();
            });
            const deleted = page.waitForResponse((r) => r.request().method() === 'DELETE' && /\/api\/bundles\/\d+$/.test(r.url()), { timeout: 30000 });
            await uploadBundle(page, pngs);
            const del = await deleted;
            H.check('failed bundle is deleted', del.status() === 204, 'status ' + del.status());
            await page.waitForTimeout(500);
            H.check('no link is shown after a failure', await page.isHidden('#resultsSection'));
            await context.close();
        }

        // Too many files for one bundle.
        {
            const { context, page } = await openUploadPage(browser, server.baseURL);
            const many = H.makeFiles(Array.from({ length: 11 }, (_, i) => ['f' + i + '.txt', 'x' + i]));
            await page.setInputFiles('#fileInput', many);
            await page.waitForTimeout(400);
            H.check('11 files: upload disabled', await page.isDisabled('#uploadButton'));
            H.check('11 files: limit explained', /10/.test(await page.textContent('#bundleLimitMessage')));
            await context.close();
        }

        // One file keeps the single-file flow.
        {
            const { context, page } = await openUploadPage(browser, server.baseURL);
            await setE2E(page, false);
            await page.setInputFiles('#fileInput', pngs.slice(0, 1));
            await page.waitForFunction(() => !document.getElementById('uploadButton').disabled);
            H.check('one file: no bundle list', await page.isHidden('#bundleFileList'));
            await page.click('#uploadButton');
            await page.waitForSelector('#resultsSection:not(.hidden)', { timeout: 30000 });
            const url = await page.inputValue('#downloadUrl');
            H.check('one file: a claim link, not a bundle', !url.includes('#/bundle/'), url);
            await context.close();
        }

        // Chunked members: a server that sends every file through chunked upload.
        {
            const chunky = await H.startServer({ CHUNKED_UPLOAD_THRESHOLD: '1024' });
            try {
                const big = H.makeFiles([['big-a.bin', Buffer.alloc(300 * 1024, 7)], ['big-b.bin', Buffer.alloc(200 * 1024, 9)]]);
                for (const e2e of [false, true]) {
                    const { context, page } = await openUploadPage(browser, chunky.baseURL);
                    await setE2E(page, e2e);
                    const inits = [];
                    page.on('request', (r) => { if (r.url().endsWith('/api/upload/init')) inits.push(r); });
                    await uploadBundle(page, big);
                    await page.waitForSelector('#resultsSection:not(.hidden)', { timeout: 60000 });
                    const url = await page.inputValue('#downloadUrl');
                    const m = /\/#\/bundle\/([A-Za-z0-9_-]+)/.exec(url);
                    const info = m && await (await fetch(chunky.baseURL + '/api/bundle/' + m[1] + '/info')).json();
                    H.check('chunked bundle (e2e=' + e2e + ') used chunked uploads', inits.length === 2, inits.length + ' inits');
                    H.check('chunked bundle (e2e=' + e2e + ') published both files', !!info && info.file_count === 2, JSON.stringify(info));
                    await context.close();
                }
            } finally {
                chunky.stop();
            }
        }
    } finally {
        await browser.close();
        server.stop();
    }
    H.finish();
})().catch((e) => { console.log('FAIL ' + (e && e.stack || e)); process.exit(1); });
